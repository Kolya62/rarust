// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! SHA-256, HMAC-SHA256 and the PBKDF2 variant used by RAR 5.0.

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

#[derive(Clone)]
pub struct Sha256 {
    h: [u32; 8],
    count: u64,
    buf: [u8; 64],
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256 {
    pub fn new() -> Self {
        Sha256 { h: H0, count: 0, buf: [0; 64] }
    }

    fn transform(&mut self) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes(self.buf[i * 4..i * 4 + 4].try_into().unwrap());
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = s1.wrapping_add(w[i - 7]).wrapping_add(s0).wrapping_add(w[i - 16]);
        }
        let mut v = self.h;
        for i in 0..64 {
            let e = v[4];
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & v[5]) ^ (!e & v[6]);
            let t1 = v[7].wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
            let a = v[0];
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & v[1]) ^ (a & v[2]) ^ (v[1] & v[2]);
            let t2 = s0.wrapping_add(maj);
            v[7] = v[6];
            v[6] = v[5];
            v[5] = v[4];
            v[4] = v[3].wrapping_add(t1);
            v[3] = v[2];
            v[2] = v[1];
            v[1] = v[0];
            v[0] = t1.wrapping_add(t2);
        }
        for i in 0..8 {
            self.h[i] = self.h[i].wrapping_add(v[i]);
        }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        let mut pos = (self.count & 0x3f) as usize;
        self.count += data.len() as u64;
        while !data.is_empty() {
            let n = (64 - pos).min(data.len());
            self.buf[pos..pos + n].copy_from_slice(&data[..n]);
            data = &data[n..];
            pos += n;
            if pos == 64 {
                pos = 0;
                self.transform();
            }
        }
    }

    pub fn finalize(mut self) -> [u8; 32] {
        let bit_len = self.count.wrapping_mul(8);
        let mut pos = (self.count & 0x3f) as usize;
        self.buf[pos] = 0x80;
        pos += 1;
        if pos != 56 {
            if pos > 56 {
                while pos < 64 {
                    self.buf[pos] = 0;
                    pos += 1;
                }
                pos = 0;
            }
            if pos == 0 {
                self.transform();
            }
            for x in &mut self.buf[pos..56] {
                *x = 0;
            }
        }
        self.buf[56..].copy_from_slice(&bit_len.to_be_bytes());
        self.transform();
        let mut out = [0u8; 32];
        for i in 0..8 {
            out[i * 4..i * 4 + 4].copy_from_slice(&self.h[i].to_be_bytes());
        }
        out
    }

    pub fn digest(data: &[u8]) -> [u8; 32] {
        let mut s = Sha256::new();
        s.update(data);
        s.finalize()
    }
}

/// HMAC-SHA256 with precomputable inner/outer key states.
#[derive(Clone)]
pub struct HmacSha256 {
    inner: Sha256,
    outer: Sha256,
}

impl HmacSha256 {
    pub fn new(key: &[u8]) -> Self {
        let mut k = [0u8; 64];
        if key.len() > 64 {
            k[..32].copy_from_slice(&Sha256::digest(key));
        } else {
            k[..key.len()].copy_from_slice(key);
        }
        let mut ipad = [0u8; 64];
        let mut opad = [0u8; 64];
        for i in 0..64 {
            ipad[i] = k[i] ^ 0x36;
            opad[i] = k[i] ^ 0x5c;
        }
        let mut inner = Sha256::new();
        inner.update(&ipad);
        let mut outer = Sha256::new();
        outer.update(&opad);
        HmacSha256 { inner, outer }
    }

    pub fn mac(&self, data: &[u8]) -> [u8; 32] {
        let mut i = self.inner.clone();
        i.update(data);
        let ih = i.finalize();
        let mut o = self.outer.clone();
        o.update(&ih);
        o.finalize()
    }
}

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    HmacSha256::new(key).mac(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn abc() {
        let d = Sha256::digest(b"abc");
        assert_eq!(d[..4], [0xba, 0x78, 0x16, 0xbf]);
        let d = Sha256::digest(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        assert_eq!(d[..4], [0x24, 0x8d, 0x6a, 0x61]);
    }
    #[test]
    fn hmac() {
        // RFC 4231 test case 2.
        let m = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(m[..4], [0x5b, 0xdc, 0xc1, 0x46]);
    }
}
