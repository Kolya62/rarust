// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! RAR encryption: legacy RAR 1.3/1.5/2.0 ciphers and AES based RAR 3.x/5.0.

pub mod aes;

use crate::hash::crc32::{crc32, crc_table};
use crate::hash::sha1::Sha1;
use crate::hash::sha256::{hmac_sha256, HmacSha256};
use crate::hash::{HashType, HashValue};
use aes::Aes;

pub const SIZE_SALT50: usize = 16;
pub const SIZE_SALT30: usize = 8;
pub const SIZE_INITV: usize = 16;
pub const SIZE_PSWCHECK: usize = 8;
pub const SIZE_PSWCHECK_CSUM: usize = 4;
pub const CRYPT_BLOCK_SIZE: usize = 16;
pub const CRYPT_BLOCK_MASK: usize = CRYPT_BLOCK_SIZE - 1;
pub const CRYPT5_KDF_LG2_COUNT_MAX: u32 = 24;
pub const CRYPT_VERSION: u64 = 0;
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

/// Password with RAR compatible truncation applied.
fn truncated(pwd: &str) -> Vec<char> {
    pwd.chars().take(MAXPASSWORD_RAR - 1).collect()
}

/// Password as 8-bit string for legacy ciphers.
fn password_bytes(pwd: &str) -> Vec<u8> {
    let s: String = truncated(pwd).into_iter().collect();
    let mut b = crate::unicode::wide_to_char(&s);
    b.truncate(MAXPASSWORD_RAR - 1);
    b
}

static INIT_SUBST_TABLE20: [u8; 256] = [
    215, 19, 149, 35, 73, 197, 192, 205, 249, 28, 16, 119, 48, 221, 2, 42, 232, 1, 177, 233, 14, 88, 219, 25,
    223, 195, 244, 90, 87, 239, 153, 137, 255, 199, 147, 70, 92, 66, 246, 13, 216, 40, 62, 29, 217, 230, 86, 6,
    71, 24, 171, 196, 101, 113, 218, 123, 93, 91, 163, 178, 202, 67, 44, 235, 107, 250, 75, 234, 49, 167, 125,
    211, 83, 114, 157, 144, 32, 193, 143, 36, 158, 124, 247, 187, 89, 214, 141, 47, 121, 228, 61, 130, 213, 194,
    174, 251, 97, 110, 54, 229, 115, 57, 152, 94, 105, 243, 212, 55, 209, 245, 63, 11, 164, 200, 31, 156, 81,
    176, 227, 21, 76, 99, 139, 188, 127, 17, 248, 51, 207, 120, 189, 210, 8, 226, 41, 72, 183, 203, 135, 165,
    166, 60, 98, 7, 122, 38, 155, 170, 69, 172, 252, 238, 39, 134, 59, 128, 236, 27, 240, 80, 131, 3, 85, 206,
    145, 79, 154, 142, 159, 220, 201, 133, 74, 64, 20, 129, 224, 185, 138, 103, 173, 182, 43, 34, 254, 82, 198,
    151, 231, 180, 58, 10, 118, 26, 102, 12, 50, 132, 22, 191, 136, 111, 162, 179, 45, 4, 148, 108, 161, 56,
    78, 126, 242, 222, 15, 175, 146, 23, 33, 241, 181, 190, 77, 225, 0, 46, 169, 186, 68, 95, 237, 65, 53, 208,
    253, 168, 9, 18, 100, 52, 116, 184, 160, 96, 109, 37, 30, 106, 140, 104, 150, 5, 204, 117, 112, 84,
];

#[derive(Clone)]
struct Kdf3Item {
    pwd: String,
    salt: Option<[u8; SIZE_SALT30]>,
    key: [u8; 16],
    init: [u8; 16],
}

#[derive(Clone)]
struct Kdf5Item {
    pwd: String,
    salt: [u8; SIZE_SALT50],
    lg2: u32,
    key: [u8; 32],
    psw_check: [u8; 32],
    hash_key: [u8; 32],
}

/// Keys derived for RAR 5.0 encryption.
pub struct Rar5Keys {
    pub hash_key: [u8; 32],
    pub psw_check: [u8; SIZE_PSWCHECK],
}

#[derive(Clone)]
pub struct CryptData {
    method: CryptMethod,
    aes: Option<Aes>,
    subst20: [u8; 256],
    key20: [u32; 4],
    key13: [u8; 3],
    key15: [u16; 4],
    kdf3: Vec<Kdf3Item>,
    kdf5: Vec<Kdf5Item>,
}

impl Default for CryptData {
    fn default() -> Self {
        Self::new()
    }
}

impl CryptData {
    pub fn new() -> Self {
        CryptData {
            method: CryptMethod::None,
            aes: None,
            subst20: [0; 256],
            key20: [0; 4],
            key13: [0; 3],
            key15: [0; 4],
            kdf3: Vec::new(),
            kdf5: Vec::new(),
        }
    }

    pub fn method(&self) -> CryptMethod {
        self.method
    }

    /// Set decryption keys. Returns None if the method is not supported or
    /// KDF parameters are invalid. For RAR 5.0 returns hash key and
    /// password check value.
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
        let dummy = Rar5Keys { hash_key: [0; 32], psw_check: [0; SIZE_PSWCHECK] };
        match method {
            CryptMethod::Rar13 => self.set_key13(&password_bytes(password)),
            CryptMethod::Rar15 => self.set_key15(&password_bytes(password)),
            CryptMethod::Rar20 => self.set_key20(&password_bytes(password)),
            CryptMethod::Rar30 => {
                let s = salt.map(|s| <[u8; 8]>::try_from(&s[..8]).unwrap());
                self.set_key30(password, s)
            }
            CryptMethod::Rar50 => {
                let s: [u8; 16] = salt?[..16].try_into().ok()?;
                return self.set_key50(password, &s, init_v, lg2_count);
            }
            _ => return None,
        }
        Some(dummy)
    }

    pub fn decrypt(&mut self, buf: &mut [u8]) {
        match self.method {
            CryptMethod::Rar13 => self.decrypt13(buf),
            CryptMethod::Rar15 => self.crypt15(buf),
            CryptMethod::Rar20 => {
                for c in buf.as_chunks_mut::<16>().0 {
                    self.decrypt_block20(c);
                }
            }
            CryptMethod::Rar30 | CryptMethod::Rar50 => {
                if let Some(a) = self.aes.as_mut() {
                    a.cbc_decrypt(buf)
                }
            }
            _ => {}
        }
    }

    fn set_key13(&mut self, pwd: &[u8]) {
        self.key13 = [0; 3];
        for &p in pwd {
            self.key13[0] = self.key13[0].wrapping_add(p);
            self.key13[1] ^= p;
            self.key13[2] = self.key13[2].wrapping_add(p).rotate_left(1);
        }
    }

    pub fn set_cmt13_encryption(&mut self) {
        self.method = CryptMethod::Rar13;
        self.key13 = [0, 7, 77];
    }

    fn decrypt13(&mut self, data: &mut [u8]) {
        for d in data {
            self.key13[1] = self.key13[1].wrapping_add(self.key13[2]);
            self.key13[0] = self.key13[0].wrapping_add(self.key13[1]);
            *d = d.wrapping_sub(self.key13[0]);
        }
    }

    fn set_key15(&mut self, pwd: &[u8]) {
        let t = crc_table();
        let c = crc32(0xffffffff, pwd);
        self.key15 = [c as u16, (c >> 16) as u16, 0, 0];
        for &p in pwd {
            let tp = t[p as usize];
            self.key15[2] ^= (p as u32 ^ tp) as u16;
            self.key15[3] = self.key15[3].wrapping_add((p as u32).wrapping_add(tp >> 16) as u16);
        }
    }

    fn crypt15(&mut self, data: &mut [u8]) {
        let t = crc_table();
        let k = &mut self.key15;
        for d in data {
            k[0] = k[0].wrapping_add(0x1234);
            let idx = ((k[0] & 0x1fe) >> 1) as usize;
            k[1] ^= t[idx] as u16;
            k[2] = k[2].wrapping_sub((t[idx] >> 16) as u16);
            k[0] ^= k[2];
            k[3] = k[3].rotate_right(1) ^ k[1];
            k[3] = k[3].rotate_right(1);
            k[0] ^= k[3];
            *d ^= (k[0] >> 8) as u8;
        }
    }

    fn subst_long(&self, t: u32) -> u32 {
        let s = &self.subst20;
        (s[(t & 255) as usize] as u32)
            | ((s[((t >> 8) & 255) as usize] as u32) << 8)
            | ((s[((t >> 16) & 255) as usize] as u32) << 16)
            | ((s[((t >> 24) & 255) as usize] as u32) << 24)
    }

    fn set_key20(&mut self, pwd: &[u8]) {
        let t = crc_table();
        self.key20 = [0xD3A3B879, 0x3F6D12F7, 0x7515A235, 0xA4E7F123];
        self.subst20 = INIT_SUBST_TABLE20;
        let len = pwd.len();
        // Password buffer has a terminating zero that the loop may read.
        let mut p = pwd.to_vec();
        p.resize((len | CRYPT_BLOCK_MASK) + 2, 0);
        for j in 0..256u32 {
            let mut i = 0;
            while i < len {
                let mut n1 = (t[((p[i] as u32).wrapping_sub(j) & 0xff) as usize] & 0xff) as usize;
                let n2 = (t[((p[i + 1] as u32).wrapping_add(j) & 0xff) as usize] & 0xff) as usize;
                let mut k = 1;
                while n1 != n2 {
                    self.subst20.swap(n1, (n1 + i + k) & 0xff);
                    n1 = (n1 + 1) & 0xff;
                    k += 1;
                }
                i += 2;
            }
        }
        let mut i = 0;
        while i < len {
            let mut blk = [0u8; 16];
            blk.copy_from_slice(&p[i..i + 16]);
            self.encrypt_block20(&mut blk);
            p[i..i + 16].copy_from_slice(&blk);
            i += 16;
        }
    }

    fn rounds20(&self, buf: &[u8], rev: bool) -> [u8; 16] {
        let k = self.key20;
        let g = |o: usize| u32::from_le_bytes(buf[o..o + 4].try_into().unwrap());
        let (mut a, mut b, mut c, mut d) = (g(0) ^ k[0], g(4) ^ k[1], g(8) ^ k[2], g(12) ^ k[3]);
        for n in 0..32 {
            let i = if rev { 31 - n } else { n };
            let t = c.wrapping_add(d.rotate_left(11)) ^ k[i & 3];
            let ta = a ^ self.subst_long(t);
            let t = (d ^ c.rotate_left(17)).wrapping_add(k[i & 3]);
            let tb = b ^ self.subst_long(t);
            a = c;
            b = d;
            c = ta;
            d = tb;
        }
        let mut out = [0u8; 16];
        out[0..4].copy_from_slice(&(c ^ k[0]).to_le_bytes());
        out[4..8].copy_from_slice(&(d ^ k[1]).to_le_bytes());
        out[8..12].copy_from_slice(&(a ^ k[2]).to_le_bytes());
        out[12..16].copy_from_slice(&(b ^ k[3]).to_le_bytes());
        out
    }

    fn upd_keys20(&mut self, buf: &[u8]) {
        let t = crc_table();
        let mut i = 0;
        while i < 16 {
            self.key20[0] ^= t[buf[i] as usize];
            self.key20[1] ^= t[buf[i + 1] as usize];
            self.key20[2] ^= t[buf[i + 2] as usize];
            self.key20[3] ^= t[buf[i + 3] as usize];
            i += 4;
        }
    }

    fn encrypt_block20(&mut self, buf: &mut [u8; 16]) {
        let out = self.rounds20(buf, false);
        buf.copy_from_slice(&out);
        self.upd_keys20(&out);
    }

    fn decrypt_block20(&mut self, buf: &mut [u8]) {
        let inb: [u8; 16] = buf[..16].try_into().unwrap();
        let out = self.rounds20(&inb, true);
        buf[..16].copy_from_slice(&out);
        self.upd_keys20(&inb);
    }

    fn set_key30(&mut self, pwd: &str, salt: Option<[u8; 8]>) {
        let pwd_s: String = truncated(pwd).into_iter().collect();
        if let Some(it) = self.kdf3.iter().find(|i| i.pwd == pwd_s && i.salt == salt) {
            self.aes = Some(Aes::new(&it.key, Some(&it.init)));
            return;
        }
        let mut raw: Vec<u8> = pwd_s.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        if let Some(s) = salt {
            raw.extend_from_slice(&s);
        }
        let mut c = Sha1::new();
        const ROUNDS: u32 = 0x40000;
        let mut init = [0u8; 16];
        for i in 0..ROUNDS {
            c.update_rar29(&mut raw);
            c.update(&[i as u8, (i >> 8) as u8, (i >> 16) as u8]);
            if i % (ROUNDS / 16) == 0 {
                let mut tc = c.clone();
                let d = tc.finalize_words();
                init[(i / (ROUNDS / 16)) as usize] = d[4] as u8;
            }
        }
        let d = c.finalize_words();
        let mut key = [0u8; 16];
        for i in 0..4 {
            for j in 0..4 {
                key[i * 4 + j] = (d[i] >> (j * 8)) as u8;
            }
        }
        if self.kdf3.len() >= 4 {
            self.kdf3.remove(0);
        }
        self.kdf3.push(Kdf3Item { pwd: pwd_s, salt, key, init });
        self.aes = Some(Aes::new(&key, Some(&init)));
    }

    fn set_key50(&mut self, pwd: &str, salt: &[u8; 16], init_v: Option<&[u8; 16]>, lg2: u32) -> Option<Rar5Keys> {
        if lg2 > CRYPT5_KDF_LG2_COUNT_MAX {
            return None;
        }
        let pwd_s: String = truncated(pwd).into_iter().collect();
        let item = match self.kdf5.iter().find(|i| i.pwd == pwd_s && i.lg2 == lg2 && &i.salt == salt) {
            Some(i) => i.clone(),
            None => {
                let (key, hash_key, psw_check) = pbkdf2(pwd_s.as_bytes(), salt, 1 << lg2);
                let it = Kdf5Item { pwd: pwd_s, salt: *salt, lg2, key, psw_check, hash_key };
                if self.kdf5.len() >= 4 {
                    self.kdf5.remove(0);
                }
                self.kdf5.push(it.clone());
                it
            }
        };
        let mut psw_check = [0u8; SIZE_PSWCHECK];
        for (i, b) in item.psw_check.iter().enumerate() {
            psw_check[i % SIZE_PSWCHECK] ^= b;
        }
        if let Some(iv) = init_v {
            self.aes = Some(Aes::new(&item.key, Some(iv)));
        }
        Some(Rar5Keys { hash_key: item.hash_key, psw_check })
    }
}

/// PBKDF2-HMAC-SHA256 returning key for `count` iterations and two
/// supplementary values for count+16 and count+32 iterations.
pub fn pbkdf2(pwd: &[u8], salt: &[u8], count: u32) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let hm = HmacSha256::new(pwd);
    let mut sd = salt[..salt.len().min(64)].to_vec();
    sd.extend_from_slice(&[0, 0, 0, 1]);
    let mut u = hm.mac(&sd);
    let mut f = u;
    let mut out = [[0u8; 32]; 3];
    let counts = [count - 1, 16, 16];
    for (i, &n) in counts.iter().enumerate() {
        for _ in 0..n {
            u = hm.mac(&u);
            for k in 0..32 {
                f[k] ^= u[k];
            }
        }
        out[i] = f;
    }
    (out[0], out[1], out[2])
}

pub fn convert_hash_to_mac(v: &mut HashValue, key: &[u8; 32]) {
    match v.kind {
        HashType::Crc32 => {
            let d = hmac_sha256(key, &v.crc32.to_le_bytes());
            let mut c = 0u32;
            for (i, b) in d.iter().enumerate() {
                c ^= (*b as u32) << ((i & 3) * 8);
            }
            v.crc32 = c;
        }
        HashType::Blake2 => {
            v.digest = hmac_sha256(key, &v.digest);
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pbkdf2_vectors() {
        let (k, _, _) = pbkdf2(b"password", b"salt", 1);
        assert_eq!(k[..4], [0x12, 0x0f, 0xb6, 0xcf]);
        let (k, _, _) = pbkdf2(b"password", b"salt", 4096);
        assert_eq!(k[..4], [0xc5, 0xe4, 0x78, 0xd5]);
    }
}
