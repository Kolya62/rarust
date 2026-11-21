// SPDX-License-Identifier: GPL-3.0-or-later

//! Ciphers of RAR 1.3, 1.5 and 2.0. They are weak and only kept to read
//! old archives.

use crate::hash::crc32::{crc32, crc_table};

/// RAR 1.3: a byte stream cipher; three key bytes are derived from the
/// password and evolve with every byte.
#[derive(Clone, Default)]
pub struct Rar13 {
    k: [u8; 3],
}

impl Rar13 {
    pub fn new(pwd: &[u8]) -> Self {
        let mut k = [0u8; 3];
        for &b in pwd {
            k[0] = k[0].wrapping_add(b);
            k[1] ^= b;
            k[2] = k[2].wrapping_add(b).rotate_left(1);
        }
        Rar13 { k }
    }

    /// Fixed key used for archive comments of RAR 1.3.
    pub fn comment() -> Self {
        Rar13 { k: [0, 7, 77] }
    }

    pub fn decrypt(&mut self, data: &mut [u8]) {
        for d in data {
            self.k[1] = self.k[1].wrapping_add(self.k[2]);
            self.k[0] = self.k[0].wrapping_add(self.k[1]);
            *d = d.wrapping_sub(self.k[0]);
        }
    }
}

/// RAR 1.5: a 64-bit state stream cipher stirred with the CRC table.
#[derive(Clone, Default)]
pub struct Rar15 {
    k: [u16; 4],
}

impl Rar15 {
    pub fn new(pwd: &[u8]) -> Self {
        let table = crc_table();
        let crc = crc32(!0, pwd);
        let mut k = [crc as u16, (crc >> 16) as u16, 0, 0];
        for &b in pwd {
            let t = table[b as usize];
            k[2] ^= (b as u32 ^ t) as u16;
            k[3] = k[3].wrapping_add((b as u32).wrapping_add(t >> 16) as u16);
        }
        Rar15 { k }
    }

    /// Encryption and decryption are the same XOR with the key stream.
    pub fn apply(&mut self, data: &mut [u8]) {
        let table = crc_table();
        let k = &mut self.k;
        for d in data {
            k[0] = k[0].wrapping_add(0x1234);
            let t = table[((k[0] >> 1) & 0xff) as usize];
            k[1] ^= t as u16;
            k[2] = k[2].wrapping_sub((t >> 16) as u16);
            k[0] ^= k[2];
            k[3] = (k[3].rotate_right(1) ^ k[1]).rotate_right(1);
            k[0] ^= k[3];
            *d ^= (k[0] >> 8) as u8;
        }
    }
}

/// Initial substitution table of RAR 2.0, permuted by the password.
const SBOX20: [u8; 256] = [
    215, 19, 149, 35, 73, 197, 192, 205, 249, 28, 16, 119, 48, 221, 2, 42, 232, 1, 177, 233, 14, 88, 219, 25, 223,
    195, 244, 90, 87, 239, 153, 137, 255, 199, 147, 70, 92, 66, 246, 13, 216, 40, 62, 29, 217, 230, 86, 6, 71, 24,
    171, 196, 101, 113, 218, 123, 93, 91, 163, 178, 202, 67, 44, 235, 107, 250, 75, 234, 49, 167, 125, 211, 83, 114,
    157, 144, 32, 193, 143, 36, 158, 124, 247, 187, 89, 214, 141, 47, 121, 228, 61, 130, 213, 194, 174, 251, 97,
    110, 54, 229, 115, 57, 152, 94, 105, 243, 212, 55, 209, 245, 63, 11, 164, 200, 31, 156, 81, 176, 227, 21, 76,
    99, 139, 188, 127, 17, 248, 51, 207, 120, 189, 210, 8, 226, 41, 72, 183, 203, 135, 165, 166, 60, 98, 7, 122, 38,
    155, 170, 69, 172, 252, 238, 39, 134, 59, 128, 236, 27, 240, 80, 131, 3, 85, 206, 145, 79, 154, 142, 159, 220,
    201, 133, 74, 64, 20, 129, 224, 185, 138, 103, 173, 182, 43, 34, 254, 82, 198, 151, 231, 180, 58, 10, 118, 26,
    102, 12, 50, 132, 22, 191, 136, 111, 162, 179, 45, 4, 148, 108, 161, 56, 78, 126, 242, 222, 15, 175, 146, 23,
    33, 241, 181, 190, 77, 225, 0, 46, 169, 186, 68, 95, 237, 65, 53, 208, 253, 168, 9, 18, 100, 52, 116, 184, 160,
    96, 109, 37, 30, 106, 140, 104, 150, 5, 204, 117, 112, 84,
];

/// RAR 2.0: a 128-bit block cipher, a 32 round Feistel network with a
/// password dependent S-box. The key changes after every block.
#[derive(Clone)]
pub struct Rar20 {
    k: [u32; 4],
    sbox: [u8; 256],
}

impl Rar20 {
    pub fn new(pwd: &[u8]) -> Self {
        let table = crc_table();
        let mut c = Rar20 { k: [0xd3a3_b879, 0x3f6d_12f7, 0x7515_a235, 0xa4e7_f123], sbox: SBOX20 };
        // The password is processed in pairs of bytes and as zero padded
        // 16-byte blocks.
        let n = pwd.len();
        let mut p = pwd.to_vec();
        p.resize((n | 15) + 2, 0);
        for j in 0..256u32 {
            for i in (0..n).step_by(2) {
                let mut a = (table[((p[i] as u32).wrapping_sub(j) & 0xff) as usize] & 0xff) as usize;
                let b = (table[((p[i + 1] as u32).wrapping_add(j) & 0xff) as usize] & 0xff) as usize;
                let mut step = 1;
                while a != b {
                    c.sbox.swap(a, (a + i + step) & 0xff);
                    a = (a + 1) & 0xff;
                    step += 1;
                }
            }
        }
        for i in (0..n).step_by(16) {
            let block: [u8; 16] = p[i..i + 16].try_into().unwrap();
            let out = c.rounds(&block, false);
            c.mix_key(&out);
            p[i..i + 16].copy_from_slice(&out);
        }
        c
    }

    fn sub(&self, x: u32) -> u32 {
        u32::from_le_bytes(x.to_le_bytes().map(|b| self.sbox[b as usize]))
    }

    fn rounds(&self, block: &[u8; 16], decrypt: bool) -> [u8; 16] {
        let k = self.k;
        let w = |i: usize| u32::from_le_bytes(block[i * 4..i * 4 + 4].try_into().unwrap()) ^ k[i];
        let (mut a, mut b, mut c, mut d) = (w(0), w(1), w(2), w(3));
        for r in 0..32 {
            let rk = k[(if decrypt { 31 - r } else { r }) & 3];
            let na = a ^ self.sub(c.wrapping_add(d.rotate_left(11)) ^ rk);
            let nb = b ^ self.sub((d ^ c.rotate_left(17)).wrapping_add(rk));
            (a, b, c, d) = (c, d, na, nb);
        }
        let mut out = [0u8; 16];
        for (i, v) in [c ^ k[0], d ^ k[1], a ^ k[2], b ^ k[3]].iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
        }
        out
    }

    /// Mixes a ciphertext block into the key.
    fn mix_key(&mut self, ct: &[u8; 16]) {
        let table = crc_table();
        for (i, &b) in ct.iter().enumerate() {
            self.k[i & 3] ^= table[b as usize];
        }
    }

    /// Decrypts whole 16-byte blocks.
    pub fn decrypt(&mut self, data: &mut [u8]) {
        for block in data.chunks_exact_mut(16) {
            let ct: [u8; 16] = (&*block).try_into().unwrap();
            block.copy_from_slice(&self.rounds(&ct, true));
            self.mix_key(&ct);
        }
    }
}
