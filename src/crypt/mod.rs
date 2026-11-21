// SPDX-License-Identifier: GPL-3.0-or-later

//! Decryption of all RAR formats: the legacy ciphers of RAR 1.3, 1.5 and
//! 2.0, and AES-128 (RAR 3.x) and AES-256 (RAR 5.0) in CBC mode.

pub mod aes;
pub mod kdf;
pub mod legacy;

use crate::hash::sha256::hmac_sha256;
use crate::hash::{HashType, HashValue};
use aes::Aes;

pub const SIZE_SALT50: usize = 16;
pub const SIZE_SALT30: usize = 8;
pub const SIZE_INITV: usize = 16;
pub const SIZE_PSWCHECK: usize = 8;
pub const SIZE_PSWCHECK_CSUM: usize = 4;
pub const CRYPT_BLOCK_SIZE: usize = 16;
pub const CRYPT_BLOCK_MASK: usize = CRYPT_BLOCK_SIZE - 1;
/// Largest RAR 5.0 KDF iteration count exponent accepted.
pub const CRYPT5_KDF_LG2_COUNT_MAX: u32 = 24;
/// Highest RAR 5.0 encryption version supported.
pub const CRYPT_VERSION: u64 = 0;
/// RAR uses at most this many password characters, minus one.
pub const MAXPASSWORD_RAR: usize = 128;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum CryptMethod {
    #[default]
    None,
    Rar13,
    Rar15,
    Rar20,
    Rar30,
    Rar50,
    Unknown,
}

/// The password as RAR uses it: at most 127 characters.
fn limit(pwd: &str) -> String {
    pwd.chars().take(MAXPASSWORD_RAR - 1).collect()
}

/// 8-bit password for the legacy ciphers.
fn legacy_bytes(pwd: &str) -> Vec<u8> {
    let mut b = crate::unicode::wide_to_char(&limit(pwd));
    b.truncate(MAXPASSWORD_RAR - 1);
    b
}

/// Keys derived for RAR 5.0 encryption.
pub struct Rar5Keys {
    pub hash_key: [u8; 32],
    pub psw_check: [u8; SIZE_PSWCHECK],
}

#[derive(Clone)]
enum Cipher {
    None,
    Rar13(legacy::Rar13),
    Rar15(legacy::Rar15),
    Rar20(Box<legacy::Rar20>),
    Aes(Box<Aes>),
}

/// Recently derived keys: key derivation is slow on purpose, and solid or
/// multi-volume archives set the same keys again and again.
#[derive(Clone)]
struct Derived {
    pwd: String,
    salt: Vec<u8>,
    lg2: u32,
    keys: [[u8; 32]; 3],
}

const CACHE: usize = 4;

#[derive(Clone)]
pub struct CryptData {
    method: CryptMethod,
    cipher: Cipher,
    cache: Vec<Derived>,
}

impl Default for CryptData {
    fn default() -> Self {
        Self::new()
    }
}

impl CryptData {
    pub fn new() -> Self {
        CryptData { method: CryptMethod::None, cipher: Cipher::None, cache: Vec::new() }
    }

    pub fn method(&self) -> CryptMethod {
        self.method
    }

    fn derive(&mut self, pwd: &str, salt: &[u8], lg2: u32, f: impl FnOnce() -> [[u8; 32]; 3]) -> [[u8; 32]; 3] {
        if let Some(d) = self.cache.iter().find(|d| d.pwd == pwd && d.salt == salt && d.lg2 == lg2) {
            return d.keys;
        }
        let keys = f();
        if self.cache.len() >= CACHE {
            self.cache.remove(0);
        }
        self.cache.push(Derived { pwd: pwd.to_string(), salt: salt.to_vec(), lg2, keys });
        keys
    }

    /// Sets the decryption key. Returns None for an empty password, an
    /// unsupported method or invalid parameters; for RAR 5.0 returns the
    /// checksum key and the password check value.
    pub fn set_keys(
        &mut self,
        method: CryptMethod,
        password: &str,
        salt: Option<&[u8]>,
        init_v: Option<&[u8; 16]>,
        lg2_count: u32,
    ) -> Option<Rar5Keys> {
        if method == CryptMethod::None || password.is_empty() {
            return None;
        }
        self.method = method;
        let none = Rar5Keys { hash_key: [0; 32], psw_check: [0; SIZE_PSWCHECK] };
        match method {
            CryptMethod::Rar13 => self.cipher = Cipher::Rar13(legacy::Rar13::new(&legacy_bytes(password))),
            CryptMethod::Rar15 => self.cipher = Cipher::Rar15(legacy::Rar15::new(&legacy_bytes(password))),
            CryptMethod::Rar20 => self.cipher = Cipher::Rar20(Box::new(legacy::Rar20::new(&legacy_bytes(password)))),
            CryptMethod::Rar30 => {
                let pwd = limit(password);
                let salt: Option<[u8; 8]> = salt.and_then(|s| s.get(..8)?.try_into().ok());
                let salt_key = salt.map_or(Vec::new(), |s| s.to_vec());
                // Marks "no salt" apart from any 8-byte salt.
                let lg2 = salt.is_some() as u32;
                let keys = self.derive(&pwd, &salt_key, lg2, || {
                    let utf16: Vec<u8> = pwd.encode_utf16().flat_map(u16::to_le_bytes).collect();
                    let (key, iv) = kdf::rar3(&utf16, salt.as_ref());
                    let mut k = [[0u8; 32]; 3];
                    k[0][..16].copy_from_slice(&key);
                    k[1][..16].copy_from_slice(&iv);
                    k
                });
                let iv: [u8; 16] = keys[1][..16].try_into().unwrap();
                self.cipher = Cipher::Aes(Box::new(Aes::new(&keys[0][..16], Some(&iv))));
            }
            CryptMethod::Rar50 => {
                if lg2_count > CRYPT5_KDF_LG2_COUNT_MAX {
                    return None;
                }
                let salt: [u8; 16] = salt?.get(..16)?.try_into().ok()?;
                let pwd = limit(password);
                let [key, hash_key, check] =
                    self.derive(&pwd, &salt, lg2_count + 2, || {
                        let (a, b, c) = kdf::pbkdf2(pwd.as_bytes(), &salt, 1 << lg2_count);
                        [a, b, c]
                    });
                // The 32-byte check value is folded to 8 bytes by XOR.
                let mut psw_check = [0u8; SIZE_PSWCHECK];
                for (i, b) in check.iter().enumerate() {
                    psw_check[i % SIZE_PSWCHECK] ^= b;
                }
                if let Some(iv) = init_v {
                    self.cipher = Cipher::Aes(Box::new(Aes::new(&key, Some(iv))));
                }
                return Some(Rar5Keys { hash_key, psw_check });
            }
            _ => return None,
        }
        Some(none)
    }

    /// Uses the fixed RAR 1.3 key of archive comments.
    pub fn set_cmt13_encryption(&mut self) {
        self.method = CryptMethod::Rar13;
        self.cipher = Cipher::Rar13(legacy::Rar13::comment());
    }

    pub fn decrypt(&mut self, buf: &mut [u8]) {
        match &mut self.cipher {
            Cipher::None => {}
            Cipher::Rar13(c) => c.decrypt(buf),
            Cipher::Rar15(c) => c.apply(buf),
            Cipher::Rar20(c) => c.decrypt(buf),
            Cipher::Aes(a) => a.cbc_decrypt(buf),
        }
    }
}

pub use kdf::pbkdf2;

/// RAR 5.0 with checksum MACs: checksums are replaced by HMAC-SHA256 of
/// the checksum, keyed with the checksum key. CRC32 is folded to 32 bits.
pub fn convert_hash_to_mac(v: &mut HashValue, key: &[u8; 32]) {
    match v.kind {
        HashType::Crc32 => {
            let d = hmac_sha256(key, &v.crc32.to_le_bytes());
            v.crc32 = d.chunks_exact(4).fold(0, |c, w| c ^ u32::from_le_bytes(w.try_into().unwrap()));
        }
        HashType::Blake2 => v.digest = hmac_sha256(key, &v.digest),
        _ => {}
    }
}
