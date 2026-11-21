// SPDX-License-Identifier: GPL-3.0-or-later

//! Key derivation of RAR 3.x and RAR 5.0.

use crate::hash::sha1::Sha1;
use crate::hash::sha256::HmacSha256;

/// RAR 3.x: 2^18 rounds of SHA-1 over the UTF-16LE password, the salt
/// and a 3-byte round counter. The AES-128 key is the final digest; one
/// byte of the IV is taken from an intermediate digest every 2^14 rounds.
pub fn rar3(pwd_utf16: &[u8], salt: Option<&[u8; 8]>) -> ([u8; 16], [u8; 16]) {
    let mut data = pwd_utf16.to_vec();
    if let Some(s) = salt {
        data.extend_from_slice(s);
    }
    const ROUNDS: u32 = 0x40000;
    let mut sha = Sha1::new();
    let mut iv = [0u8; 16];
    for i in 0..ROUNDS {
        sha.update_rar29(&mut data);
        sha.update(&i.to_le_bytes()[..3]);
        if i % (ROUNDS / 16) == 0 {
            iv[(i / (ROUNDS / 16)) as usize] = sha.clone().finalize_words()[4] as u8;
        }
    }
    let words = sha.finalize_words();
    let mut key = [0u8; 16];
    for (i, w) in words[..4].iter().enumerate() {
        key[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
    }
    (key, iv)
}

/// PBKDF2-HMAC-SHA256 (RFC 8018), first output block only. Returns the
/// values after `count`, `count + 16` and `count + 32` iterations: RAR 5.0
/// uses them as encryption key, checksum key and password check.
pub fn pbkdf2(pwd: &[u8], salt: &[u8], count: u32) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let mac = HmacSha256::new(pwd);
    let mut first = salt[..salt.len().min(64)].to_vec();
    first.extend_from_slice(&1u32.to_be_bytes());
    let mut u = mac.mac(&first);
    let mut acc = u;
    let mut run = |n: u32, acc: &mut [u8; 32]| {
        for _ in 0..n {
            u = mac.mac(&u);
            for (a, b) in acc.iter_mut().zip(u) {
                *a ^= b;
            }
        }
        *acc
    };
    let key = run(count - 1, &mut acc);
    let hash_key = run(16, &mut acc);
    let check = run(16, &mut acc);
    (key, hash_key, check)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(d: &[u8]) -> String {
        d.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn pbkdf2_rfc7914() {
        // RFC 7914 section 11, PBKDF2-HMAC-SHA256 test vectors.
        let (k, _, _) = pbkdf2(b"passwd", b"salt", 1);
        assert_eq!(hex(&k), "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc");
        let (k, _, _) = pbkdf2(b"Password", b"NaCl", 80000);
        assert_eq!(hex(&k), "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56");
    }
}
