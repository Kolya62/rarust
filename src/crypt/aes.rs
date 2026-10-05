// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! AES (Rijndael) with CBC mode, as used by RAR 3.x and 5.0.

const SBOX: [u8; 256] = {
    // Generate S-box at compile time.
    let mut sbox = [0u8; 256];
    let mut p: u8 = 1;
    let mut q: u8 = 1;
    loop {
        // p * 3
        p = p ^ (p << 1) ^ (if p & 0x80 != 0 { 0x1b } else { 0 });
        // q / 3
        q ^= q << 1;
        q ^= q << 2;
        q ^= q << 4;
        if q & 0x80 != 0 {
            q ^= 0x09;
        }
        let x = q ^ q.rotate_left(1) ^ q.rotate_left(2) ^ q.rotate_left(3) ^ q.rotate_left(4);
        sbox[p as usize] = x ^ 0x63;
        if p == 1 {
            break;
        }
    }
    sbox[0] = 0x63;
    sbox
};

const INV_SBOX: [u8; 256] = {
    let mut inv = [0u8; 256];
    let mut i = 0;
    while i < 256 {
        inv[SBOX[i] as usize] = i as u8;
        i += 1;
    }
    inv
};

const fn xtime(a: u8) -> u8 {
    (a << 1) ^ (if a & 0x80 != 0 { 0x1b } else { 0 })
}

const fn gmul(mut a: u8, mut b: u8) -> u8 {
    let mut r = 0;
    while b > 0 {
        if b & 1 != 0 {
            r ^= a;
        }
        a = xtime(a);
        b >>= 1;
    }
    r
}

// Encryption and decryption T-tables (column major, little endian words).
const fn make_te() -> [u32; 256] {
    let mut t = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let s = SBOX[i];
        t[i] = (gmul(s, 2) as u32) | ((s as u32) << 8) | ((s as u32) << 16) | ((gmul(s, 3) as u32) << 24);
        i += 1;
    }
    t
}
const fn make_td() -> [u32; 256] {
    let mut t = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let s = INV_SBOX[i];
        t[i] = (gmul(s, 14) as u32)
            | ((gmul(s, 9) as u32) << 8)
            | ((gmul(s, 13) as u32) << 16)
            | ((gmul(s, 11) as u32) << 24);
        i += 1;
    }
    t
}
static TE: [u32; 256] = make_te();
static TD: [u32; 256] = make_td();

#[derive(Clone)]
pub struct Aes {
    rounds: usize,
    enc_key: [u32; 60],
    dec_key: [u32; 60],
    iv: [u8; 16],
}

fn inv_mix_column(w: u32) -> u32 {
    let b = w.to_le_bytes();
    let mut r = [0u8; 4];
    for i in 0..4 {
        r[i] = gmul(b[i], 14) ^ gmul(b[(i + 1) % 4], 11) ^ gmul(b[(i + 2) % 4], 13) ^ gmul(b[(i + 3) % 4], 9);
    }
    u32::from_le_bytes(r)
}

fn sub_word(w: u32) -> u32 {
    let b = w.to_le_bytes();
    u32::from_le_bytes([SBOX[b[0] as usize], SBOX[b[1] as usize], SBOX[b[2] as usize], SBOX[b[3] as usize]])
}

impl Aes {
    /// `key` length must be 16, 24 or 32 bytes.
    pub fn new(key: &[u8], iv: Option<&[u8; 16]>) -> Self {
        let nk = key.len() / 4;
        let rounds = nk + 6;
        let total = 4 * (rounds + 1);
        let mut w = [0u32; 60];
        for i in 0..nk {
            w[i] = u32::from_le_bytes(key[i * 4..i * 4 + 4].try_into().unwrap());
        }
        let mut rcon: u8 = 1;
        for i in nk..total {
            let mut t = w[i - 1];
            if i % nk == 0 {
                t = sub_word(t.rotate_right(8)) ^ rcon as u32;
                rcon = xtime(rcon);
            } else if nk > 6 && i % nk == 4 {
                t = sub_word(t);
            }
            w[i] = w[i - nk] ^ t;
        }
        // Equivalent inverse cipher key schedule.
        let mut d = [0u32; 60];
        for r in 0..=rounds {
            for c in 0..4 {
                let v = w[(rounds - r) * 4 + c];
                d[r * 4 + c] = if r == 0 || r == rounds { v } else { inv_mix_column(v) };
            }
        }
        Aes { rounds, enc_key: w, dec_key: d, iv: iv.copied().unwrap_or([0; 16]) }
    }

    fn encrypt_block(&self, b: &mut [u8; 16]) {
        let k = &self.enc_key;
        let mut s = [0u32; 4];
        for c in 0..4 {
            s[c] = u32::from_le_bytes(b[c * 4..c * 4 + 4].try_into().unwrap()) ^ k[c];
        }
        for r in 1..self.rounds {
            let mut t = [0u32; 4];
            for c in 0..4 {
                t[c] = TE[(s[c] & 0xff) as usize]
                    ^ TE[((s[(c + 1) % 4] >> 8) & 0xff) as usize].rotate_left(8)
                    ^ TE[((s[(c + 2) % 4] >> 16) & 0xff) as usize].rotate_left(16)
                    ^ TE[(s[(c + 3) % 4] >> 24) as usize].rotate_left(24)
                    ^ k[r * 4 + c];
            }
            s = t;
        }
        for c in 0..4 {
            let v = (SBOX[(s[c] & 0xff) as usize] as u32)
                | ((SBOX[((s[(c + 1) % 4] >> 8) & 0xff) as usize] as u32) << 8)
                | ((SBOX[((s[(c + 2) % 4] >> 16) & 0xff) as usize] as u32) << 16)
                | ((SBOX[(s[(c + 3) % 4] >> 24) as usize] as u32) << 24);
            b[c * 4..c * 4 + 4].copy_from_slice(&(v ^ k[self.rounds * 4 + c]).to_le_bytes());
        }
    }

    fn decrypt_block(&self, b: &mut [u8; 16]) {
        let k = &self.dec_key;
        let mut s = [0u32; 4];
        for c in 0..4 {
            s[c] = u32::from_le_bytes(b[c * 4..c * 4 + 4].try_into().unwrap()) ^ k[c];
        }
        for r in 1..self.rounds {
            let mut t = [0u32; 4];
            for c in 0..4 {
                t[c] = TD[(s[c] & 0xff) as usize]
                    ^ TD[((s[(c + 3) % 4] >> 8) & 0xff) as usize].rotate_left(8)
                    ^ TD[((s[(c + 2) % 4] >> 16) & 0xff) as usize].rotate_left(16)
                    ^ TD[(s[(c + 1) % 4] >> 24) as usize].rotate_left(24)
                    ^ k[r * 4 + c];
            }
            s = t;
        }
        for c in 0..4 {
            let v = (INV_SBOX[(s[c] & 0xff) as usize] as u32)
                | ((INV_SBOX[((s[(c + 3) % 4] >> 8) & 0xff) as usize] as u32) << 8)
                | ((INV_SBOX[((s[(c + 2) % 4] >> 16) & 0xff) as usize] as u32) << 16)
                | ((INV_SBOX[(s[(c + 1) % 4] >> 24) as usize] as u32) << 24);
            b[c * 4..c * 4 + 4].copy_from_slice(&(v ^ k[self.rounds * 4 + c]).to_le_bytes());
        }
    }

    /// CBC encrypt whole 16 byte blocks in place.
    pub fn cbc_encrypt(&mut self, data: &mut [u8]) {
        for chunk in data.as_chunks_mut::<16>().0 {
            let mut b = [0u8; 16];
            for i in 0..16 {
                b[i] = chunk[i] ^ self.iv[i];
            }
            self.encrypt_block(&mut b);
            chunk.copy_from_slice(&b);
            self.iv = b;
        }
    }

    /// CBC decrypt whole 16 byte blocks in place.
    pub fn cbc_decrypt(&mut self, data: &mut [u8]) {
        for chunk in data.as_chunks_mut::<16>().0 {
            let ct: [u8; 16] = *chunk;
            let mut b = ct;
            self.decrypt_block(&mut b);
            for i in 0..16 {
                chunk[i] = b[i] ^ self.iv[i];
            }
            self.iv = ct;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const IV: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    const PT: [u8; 64] = [
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a, 0xae,
        0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51, 0x30, 0xc8,
        0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef, 0xf6, 0x9f, 0x24,
        0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
    ];
    fn check(key: &[u8], last: [u8; 16]) {
        let mut a = Aes::new(key, Some(&IV));
        let mut d = PT;
        a.cbc_encrypt(&mut d);
        assert_eq!(d[48..], last);
        let mut a = Aes::new(key, Some(&IV));
        a.cbc_decrypt(&mut d);
        assert_eq!(d, PT);
    }
    #[test]
    fn sbox() {
        assert_eq!(SBOX[0], 99);
        assert_eq!(SBOX[1], 124);
        assert_eq!(SBOX[255], 22);
    }
    #[test]
    fn cbc() {
        check(
            &[0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c],
            [0x3f, 0xf1, 0xca, 0xa1, 0x68, 0x1f, 0xac, 0x09, 0x12, 0x0e, 0xca, 0x30, 0x75, 0x86, 0xe1, 0xa7],
        );
        check(
            &[
                0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
                0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b,
            ],
            [0x08, 0xb0, 0xe2, 0x79, 0x88, 0x59, 0x88, 0x81, 0xd9, 0x20, 0xa9, 0xe6, 0x4f, 0x56, 0x15, 0xcd],
        );
        check(
            &[
                0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
            ],
            [0xb2, 0xeb, 0x05, 0xe2, 0xc3, 0x9b, 0xe9, 0xfc, 0xda, 0x6c, 0x19, 0x07, 0x8c, 0x6a, 0x9d, 0x1b],
        );
    }
}
