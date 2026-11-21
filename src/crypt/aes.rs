// SPDX-License-Identifier: GPL-3.0-or-later

//! AES (FIPS 197) in CBC mode, as used by RAR 3.x (AES-128) and RAR 5.0
//! (AES-256). Table based: each round is four lookups per output column.

/// Multiplication by x in GF(2^8) modulo x^8 + x^4 + x^3 + x + 1.
const fn xtime(a: u8) -> u8 {
    (a << 1) ^ if a & 0x80 != 0 { 0x1b } else { 0 }
}

const fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut r = 0;
    while b != 0 {
        if b & 1 != 0 {
            r ^= a;
        }
        a = xtime(a);
        b >>= 1;
    }
    r
}

/// S-box: multiplicative inverse followed by the affine transform.
const SBOX: [u8; 256] = {
    let mut s = [0u8; 256];
    let mut x = 0;
    while x < 256 {
        // Inverse as x^254.
        let mut inv = 1u8;
        let mut i = 0;
        while i < 254 {
            inv = gf_mul(inv, x as u8);
            i += 1;
        }
        if x == 0 {
            inv = 0;
        }
        s[x] = inv ^ inv.rotate_left(1) ^ inv.rotate_left(2) ^ inv.rotate_left(3) ^ inv.rotate_left(4) ^ 0x63;
        x += 1;
    }
    s
};

const INV_SBOX: [u8; 256] = {
    let mut s = [0u8; 256];
    let mut i = 0;
    while i < 256 {
        s[SBOX[i] as usize] = i as u8;
        i += 1;
    }
    s
};

const fn column(a: u8, b: u8, c: u8, d: u8) -> u32 {
    u32::from_be_bytes([a, b, c, d])
}

/// Encryption table: SubBytes and MixColumns for the byte in row 0.
/// Rows 1..3 use the same table rotated right by 8, 16 and 24 bits.
const TE: [u32; 256] = {
    let mut t = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let s = SBOX[i];
        t[i] = column(gf_mul(s, 2), s, s, gf_mul(s, 3));
        i += 1;
    }
    t
};

/// Decryption table: InvSubBytes and InvMixColumns for the byte in row 0.
const TD: [u32; 256] = {
    let mut t = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let s = INV_SBOX[i];
        t[i] = column(gf_mul(s, 14), gf_mul(s, 9), gf_mul(s, 13), gf_mul(s, 11));
        i += 1;
    }
    t
};

fn sub_word(w: u32) -> u32 {
    let b = w.to_be_bytes();
    column(SBOX[b[0] as usize], SBOX[b[1] as usize], SBOX[b[2] as usize], SBOX[b[3] as usize])
}

/// InvMixColumns of one column, used to build the equivalent inverse
/// cipher key schedule.
fn inv_mix(w: u32) -> u32 {
    let b = w.to_be_bytes();
    let s = |i: usize| b[i % 4];
    let mut r = [0u8; 4];
    for (i, x) in r.iter_mut().enumerate() {
        *x = gf_mul(s(i), 14) ^ gf_mul(s(i + 1), 11) ^ gf_mul(s(i + 2), 13) ^ gf_mul(s(i + 3), 9);
    }
    u32::from_be_bytes(r)
}

fn byte(w: u32, n: u32) -> usize {
    ((w >> (24 - 8 * n)) & 0xff) as usize
}

#[derive(Clone)]
pub struct Aes {
    rounds: usize,
    /// Round keys for encryption, 4 words per round.
    ek: [u32; 60],
    /// Round keys for the equivalent inverse cipher, in decryption order.
    dk: [u32; 60],
    iv: [u8; 16],
}

impl Aes {
    /// `key` must be 16, 24 or 32 bytes long.
    pub fn new(key: &[u8], iv: Option<&[u8; 16]>) -> Self {
        assert!(matches!(key.len(), 16 | 24 | 32), "bad AES key length");
        let nk = key.len() / 4;
        let rounds = nk + 6;
        let words = 4 * (rounds + 1);
        let mut ek = [0u32; 60];
        for (i, c) in key.chunks_exact(4).enumerate() {
            ek[i] = u32::from_be_bytes(c.try_into().unwrap());
        }
        let mut rcon = 1u8;
        for i in nk..words {
            let mut t = ek[i - 1];
            if i % nk == 0 {
                t = sub_word(t.rotate_left(8)) ^ (rcon as u32) << 24;
                rcon = xtime(rcon);
            } else if nk > 6 && i % nk == 4 {
                t = sub_word(t);
            }
            ek[i] = ek[i - nk] ^ t;
        }
        let mut dk = [0u32; 60];
        for r in 0..=rounds {
            for c in 0..4 {
                let w = ek[(rounds - r) * 4 + c];
                dk[r * 4 + c] = if r == 0 || r == rounds { w } else { inv_mix(w) };
            }
        }
        Aes { rounds, ek, dk, iv: iv.copied().unwrap_or([0; 16]) }
    }

    fn load(block: &[u8], k: &[u32]) -> [u32; 4] {
        let mut s = [0u32; 4];
        for c in 0..4 {
            s[c] = u32::from_be_bytes(block[c * 4..c * 4 + 4].try_into().unwrap()) ^ k[c];
        }
        s
    }

    fn store(s: [u32; 4], out: &mut [u8]) {
        for c in 0..4 {
            out[c * 4..c * 4 + 4].copy_from_slice(&s[c].to_be_bytes());
        }
    }

    fn encrypt_block(&self, block: &mut [u8]) {
        let k = &self.ek;
        let mut s = Self::load(block, k);
        for r in 1..self.rounds {
            let mut n = [0u32; 4];
            for c in 0..4 {
                n[c] = TE[byte(s[c], 0)]
                    ^ TE[byte(s[(c + 1) & 3], 1)].rotate_right(8)
                    ^ TE[byte(s[(c + 2) & 3], 2)].rotate_right(16)
                    ^ TE[byte(s[(c + 3) & 3], 3)].rotate_right(24)
                    ^ k[r * 4 + c];
            }
            s = n;
        }
        let mut n = [0u32; 4];
        for c in 0..4 {
            n[c] = column(
                SBOX[byte(s[c], 0)],
                SBOX[byte(s[(c + 1) & 3], 1)],
                SBOX[byte(s[(c + 2) & 3], 2)],
                SBOX[byte(s[(c + 3) & 3], 3)],
            ) ^ k[self.rounds * 4 + c];
        }
        Self::store(n, block);
    }

    fn decrypt_block(&self, block: &mut [u8]) {
        let k = &self.dk;
        let mut s = Self::load(block, k);
        for r in 1..self.rounds {
            let mut n = [0u32; 4];
            for c in 0..4 {
                n[c] = TD[byte(s[c], 0)]
                    ^ TD[byte(s[(c + 3) & 3], 1)].rotate_right(8)
                    ^ TD[byte(s[(c + 2) & 3], 2)].rotate_right(16)
                    ^ TD[byte(s[(c + 1) & 3], 3)].rotate_right(24)
                    ^ k[r * 4 + c];
            }
            s = n;
        }
        let mut n = [0u32; 4];
        for c in 0..4 {
            n[c] = column(
                INV_SBOX[byte(s[c], 0)],
                INV_SBOX[byte(s[(c + 3) & 3], 1)],
                INV_SBOX[byte(s[(c + 2) & 3], 2)],
                INV_SBOX[byte(s[(c + 1) & 3], 3)],
            ) ^ k[self.rounds * 4 + c];
        }
        Self::store(n, block);
    }

    /// CBC encryption of whole 16-byte blocks in place; a trailing partial
    /// block is left untouched.
    pub fn cbc_encrypt(&mut self, data: &mut [u8]) {
        for b in data.chunks_exact_mut(16) {
            for (x, v) in b.iter_mut().zip(self.iv) {
                *x ^= v;
            }
            self.encrypt_block(b);
            self.iv.copy_from_slice(b);
        }
    }

    fn cbc_decrypt_serial(&self, data: &mut [u8], mut prev: [u8; 16]) {
        for b in data.chunks_exact_mut(16) {
            let ct: [u8; 16] = (&*b).try_into().unwrap();
            self.decrypt_block(b);
            for (x, v) in b.iter_mut().zip(prev) {
                *x ^= v;
            }
            prev = ct;
        }
    }

    /// CBC decryption of whole 16-byte blocks in place. A plaintext block
    /// needs only its own and the previous ciphertext block, so big buffers
    /// are decrypted by several threads.
    pub fn cbc_decrypt(&mut self, data: &mut [u8]) {
        let len = data.len() & !15;
        if len == 0 {
            return;
        }
        let data = &mut data[..len];
        let next_iv: [u8; 16] = data[len - 16..].try_into().unwrap();
        const PART: usize = 256 * 1024;
        let threads = std::thread::available_parallelism().map_or(1, |n| n.get()).min(16);
        let parts = threads.min(len / PART);
        if parts < 2 {
            self.cbc_decrypt_serial(data, self.iv);
        } else {
            let part_len = (len / parts + 15) & !15;
            let mut ivs = vec![self.iv];
            ivs.extend((part_len..len).step_by(part_len).map(|p| <[u8; 16]>::try_from(&data[p - 16..p]).unwrap()));
            let this = &*self;
            std::thread::scope(|sc| {
                for (chunk, iv) in data.chunks_mut(part_len).zip(ivs) {
                    sc.spawn(move || this.cbc_decrypt_serial(chunk, iv));
                }
            });
        }
        self.iv = next_iv;
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
        assert_eq!(SBOX[0], 0x63);
        assert_eq!(SBOX[1], 0x7c);
        assert_eq!(SBOX[255], 0x16);
        for i in 0..256 {
            assert_eq!(INV_SBOX[SBOX[i] as usize] as usize, i);
        }
    }
    #[test]
    fn cbc_large_matches_blockwise() {
        let key = [5u8; 32];
        let iv = [9u8; 16];
        let plain: Vec<u8> = (0..(3 << 20) + 48).map(|i| (i * 7 + i / 251) as u8).collect();
        let mut enc = plain.clone();
        Aes::new(&key, Some(&iv)).cbc_encrypt(&mut enc);
        // Decrypt in uneven pieces, so both paths and IV chaining are used.
        let mut a = Aes::new(&key, Some(&iv));
        let mut dec = enc.clone();
        let (x, y) = dec.split_at_mut(1 << 20 | 32);
        a.cbc_decrypt(x);
        a.cbc_decrypt(y);
        assert!(dec == plain);
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
