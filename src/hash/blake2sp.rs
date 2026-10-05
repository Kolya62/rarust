// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! BLAKE2sp hash as used by RAR 5.0.

const BLOCK: usize = 64;
const OUT: usize = 32;
const PAR: usize = 8;

const IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

const SIGMA: [[u8; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

#[derive(Clone)]
struct Blake2s {
    buf: [u8; 2 * BLOCK],
    h: [u32; 8],
    t: [u32; 2],
    f: [u32; 2],
    buflen: usize,
    last_node: bool,
}

impl Blake2s {
    fn new(node_offset: u32, node_depth: u32) -> Self {
        let mut h = IV;
        h[0] ^= 0x02080020;
        h[2] ^= node_offset;
        h[3] ^= (node_depth << 16) | 0x20000000;
        Blake2s { buf: [0; 2 * BLOCK], h, t: [0; 2], f: [0; 2], buflen: 0, last_node: false }
    }

    fn inc(&mut self, inc: u32) {
        self.t[0] = self.t[0].wrapping_add(inc);
        if self.t[0] < inc {
            self.t[1] = self.t[1].wrapping_add(1);
        }
    }

    fn compress(&mut self, block_from_buf_start: bool) {
        let _ = block_from_buf_start;
        let mut m = [0u32; 16];
        for (i, w) in m.iter_mut().enumerate() {
            *w = u32::from_le_bytes(self.buf[i * 4..i * 4 + 4].try_into().unwrap());
        }
        let mut v = [0u32; 16];
        v[..8].copy_from_slice(&self.h);
        v[8..12].copy_from_slice(&IV[..4]);
        v[12] = self.t[0] ^ IV[4];
        v[13] = self.t[1] ^ IV[5];
        v[14] = self.f[0] ^ IV[6];
        v[15] = self.f[1] ^ IV[7];
        #[inline(always)]
        fn g(v: &mut [u32; 16], m: &[u32; 16], s: &[u8; 16], i: usize, a: usize, b: usize, c: usize, d: usize) {
            v[a] = v[a].wrapping_add(v[b]).wrapping_add(m[s[2 * i] as usize]);
            v[d] = (v[d] ^ v[a]).rotate_right(16);
            v[c] = v[c].wrapping_add(v[d]);
            v[b] = (v[b] ^ v[c]).rotate_right(12);
            v[a] = v[a].wrapping_add(v[b]).wrapping_add(m[s[2 * i + 1] as usize]);
            v[d] = (v[d] ^ v[a]).rotate_right(8);
            v[c] = v[c].wrapping_add(v[d]);
            v[b] = (v[b] ^ v[c]).rotate_right(7);
        }
        for s in SIGMA.iter() {
            g(&mut v, &m, s, 0, 0, 4, 8, 12);
            g(&mut v, &m, s, 1, 1, 5, 9, 13);
            g(&mut v, &m, s, 2, 2, 6, 10, 14);
            g(&mut v, &m, s, 3, 3, 7, 11, 15);
            g(&mut v, &m, s, 4, 0, 5, 10, 15);
            g(&mut v, &m, s, 5, 1, 6, 11, 12);
            g(&mut v, &m, s, 6, 2, 7, 8, 13);
            g(&mut v, &m, s, 7, 3, 4, 9, 14);
        }
        for i in 0..8 {
            self.h[i] ^= v[i] ^ v[i + 8];
        }
    }

    fn update(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            let left = self.buflen;
            let fill = 2 * BLOCK - left;
            if data.len() > fill {
                self.buf[left..].copy_from_slice(&data[..fill]);
                self.buflen += fill;
                self.inc(BLOCK as u32);
                self.compress(true);
                self.buf.copy_within(BLOCK.., 0);
                self.buflen -= BLOCK;
                data = &data[fill..];
            } else {
                self.buf[left..left + data.len()].copy_from_slice(data);
                self.buflen += data.len();
                data = &[];
            }
        }
    }

    fn finalize(&mut self) -> [u8; OUT] {
        if self.buflen > BLOCK {
            self.inc(BLOCK as u32);
            self.compress(true);
            self.buflen -= BLOCK;
            self.buf.copy_within(BLOCK..BLOCK + self.buflen, 0);
        }
        self.inc(self.buflen as u32);
        if self.last_node {
            self.f[1] = !0;
        }
        self.f[0] = !0;
        for b in &mut self.buf[self.buflen..] {
            *b = 0;
        }
        self.compress(true);
        let mut out = [0u8; OUT];
        for i in 0..8 {
            out[i * 4..i * 4 + 4].copy_from_slice(&self.h[i].to_le_bytes());
        }
        out
    }
}

#[derive(Clone)]
pub struct Blake2sp {
    s: Vec<Blake2s>,
    r: Blake2s,
    buf: [u8; PAR * BLOCK],
    buflen: usize,
}

impl Default for Blake2sp {
    fn default() -> Self {
        Self::new()
    }
}

impl Blake2sp {
    pub fn new() -> Self {
        let mut r = Blake2s::new(0, 1);
        r.last_node = true;
        let mut s: Vec<Blake2s> = (0..PAR as u32).map(|i| Blake2s::new(i, 0)).collect();
        s[PAR - 1].last_node = true;
        Blake2sp { s, r, buf: [0; PAR * BLOCK], buflen: 0 }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        let mut left = self.buflen;
        let fill = self.buf.len() - left;
        if left > 0 && data.len() >= fill {
            self.buf[left..].copy_from_slice(&data[..fill]);
            for i in 0..PAR {
                let blk: [u8; BLOCK] = self.buf[i * BLOCK..(i + 1) * BLOCK].try_into().unwrap();
                self.s[i].update(&blk);
            }
            data = &data[fill..];
            left = 0;
        }
        let stripe = PAR * BLOCK;
        let full = data.len() - data.len() % stripe;
        for (i, st) in self.s.iter_mut().enumerate() {
            let mut off = i * BLOCK;
            while off + BLOCK <= full {
                st.update(&data[off..off + BLOCK]);
                off += stripe;
            }
        }
        let rest = &data[full..];
        self.buf[left..left + rest.len()].copy_from_slice(rest);
        self.buflen = left + rest.len();
    }

    pub fn finalize(&self) -> [u8; OUT] {
        let mut st = self.clone();
        let mut hashes = [[0u8; OUT]; PAR];
        for i in 0..PAR {
            if st.buflen > i * BLOCK {
                let left = (st.buflen - i * BLOCK).min(BLOCK);
                let blk = st.buf[i * BLOCK..i * BLOCK + left].to_vec();
                st.s[i].update(&blk);
            }
            hashes[i] = st.s[i].finalize();
        }
        for h in &hashes {
            st.r.update(h);
        }
        st.r.finalize()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn empty() {
        let h = Blake2sp::new().finalize();
        assert_eq!(
            h,
            [
                0xdd, 0x0e, 0x89, 0x17, 0x76, 0x93, 0x3f, 0x43, 0xc7, 0xd0, 0x32, 0xb0, 0x8a, 0x91, 0x7e, 0x25,
                0x74, 0x1f, 0x8a, 0xa9, 0xa1, 0x2c, 0x12, 0xe1, 0xca, 0xc8, 0x80, 0x15, 0x00, 0xf2, 0xca, 0x4f
            ]
        );
    }
    #[test]
    fn chunked_equals_whole() {
        let data: Vec<u8> = (0..5000u32).map(|i| (i * 7 + 3) as u8).collect();
        let mut a = Blake2sp::new();
        a.update(&data);
        let mut b = Blake2sp::new();
        for c in data.chunks(37) {
            b.update(c);
        }
        assert_eq!(a.finalize(), b.finalize());
    }
}
