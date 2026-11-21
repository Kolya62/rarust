// SPDX-License-Identifier: GPL-3.0-or-later

//! BLAKE2sp (RFC 7693 BLAKE2s run as 8 parallel leaves plus a root node).

const BLOCK: usize = 64;
const OUT: usize = 32;
const LEAVES: usize = 8;
const STRIPE: usize = LEAVES * BLOCK;

const IV: [u32; 8] = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];

const SIGMA: [[usize; 16]; 10] = [
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

/// One BLAKE2s node. The most recent block is kept unprocessed until more
/// data arrives, because the final block must be compressed with the
/// finalization flag set.
#[derive(Clone)]
struct Node {
    h: [u32; 8],
    t: u64,
    last_node: bool,
    buf: [u8; BLOCK],
    len: usize,
}

impl Node {
    fn new(offset: u32, depth: u8, last_node: bool) -> Node {
        let p = [
            OUT as u32 | (LEAVES as u32) << 16 | 2 << 24, // digest length, key length 0, fanout, depth
            0,                                            // leaf length
            offset,                                       // node offset (low 32 bits)
            (depth as u32) << 16 | (OUT as u32) << 24,    // node depth, inner length
            0,
            0,
            0,
            0,
        ];
        let mut h = IV;
        for (x, y) in h.iter_mut().zip(p) {
            *x ^= y;
        }
        Node { h, t: 0, last_node, buf: [0; BLOCK], len: 0 }
    }

    fn compress(&mut self, block: &[u8; BLOCK], last: bool) {
        let mut m = [0u32; 16];
        for (i, x) in m.iter_mut().enumerate() {
            *x = u32::from_le_bytes(block[i * 4..i * 4 + 4].try_into().unwrap());
        }
        let mut v = [0u32; 16];
        v[..8].copy_from_slice(&self.h);
        v[8..].copy_from_slice(&IV);
        v[12] ^= self.t as u32;
        v[13] ^= (self.t >> 32) as u32;
        if last {
            v[14] = !v[14];
            if self.last_node {
                v[15] = !v[15];
            }
        }
        #[inline(always)]
        fn g(v: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, x: u32, y: u32) {
            v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
            v[d] = (v[d] ^ v[a]).rotate_right(16);
            v[c] = v[c].wrapping_add(v[d]);
            v[b] = (v[b] ^ v[c]).rotate_right(12);
            v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
            v[d] = (v[d] ^ v[a]).rotate_right(8);
            v[c] = v[c].wrapping_add(v[d]);
            v[b] = (v[b] ^ v[c]).rotate_right(7);
        }
        for s in &SIGMA {
            g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
            g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
            g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
            g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
            g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
            g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
            g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
            g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
        }
        for i in 0..8 {
            self.h[i] ^= v[i] ^ v[i + 8];
        }
    }

    fn update(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            if self.len == BLOCK {
                self.t += BLOCK as u64;
                let b = self.buf;
                self.compress(&b, false);
                self.len = 0;
            }
            let n = (BLOCK - self.len).min(data.len());
            self.buf[self.len..self.len + n].copy_from_slice(&data[..n]);
            self.len += n;
            data = &data[n..];
        }
    }

    fn finalize(mut self) -> [u8; OUT] {
        self.t += self.len as u64;
        self.buf[self.len..].fill(0);
        let b = self.buf;
        self.compress(&b, true);
        let mut out = [0u8; OUT];
        for (i, x) in self.h.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&x.to_le_bytes());
        }
        out
    }
}

/// BLAKE2sp hasher. Input is split into 64-byte blocks distributed round
/// robin over 8 leaves; the root hashes the concatenated leaf digests.
#[derive(Clone)]
pub struct Blake2sp {
    leaves: Vec<Node>,
    stripe: [u8; STRIPE],
    stripe_len: usize,
}

impl Default for Blake2sp {
    fn default() -> Self {
        Self::new()
    }
}

impl Blake2sp {
    pub fn new() -> Self {
        let leaves = (0..LEAVES).map(|i| Node::new(i as u32, 0, i == LEAVES - 1)).collect();
        Blake2sp { leaves, stripe: [0; STRIPE], stripe_len: 0 }
    }

    fn feed_stripes(leaves: &mut [Node], data: &[u8]) {
        debug_assert_eq!(data.len() % STRIPE, 0);
        // Leaves are independent, so large inputs use one thread per leaf.
        const THREADED_FROM: usize = 1 << 20;
        let work = |i: usize, leaf: &mut Node| {
            for s in data.chunks_exact(STRIPE) {
                leaf.update(&s[i * BLOCK..(i + 1) * BLOCK]);
            }
        };
        if data.len() >= THREADED_FROM && std::thread::available_parallelism().is_ok_and(|n| n.get() > 1) {
            std::thread::scope(|sc| {
                for (i, leaf) in leaves.iter_mut().enumerate() {
                    sc.spawn(move || work(i, leaf));
                }
            });
        } else {
            for (i, leaf) in leaves.iter_mut().enumerate() {
                work(i, leaf);
            }
        }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        if self.stripe_len > 0 {
            let n = (STRIPE - self.stripe_len).min(data.len());
            self.stripe[self.stripe_len..self.stripe_len + n].copy_from_slice(&data[..n]);
            self.stripe_len += n;
            data = &data[n..];
            if self.stripe_len < STRIPE {
                return;
            }
            let s = self.stripe;
            Self::feed_stripes(&mut self.leaves, &s);
            self.stripe_len = 0;
        }
        let whole = data.len() - data.len() % STRIPE;
        Self::feed_stripes(&mut self.leaves, &data[..whole]);
        let rest = &data[whole..];
        self.stripe[..rest.len()].copy_from_slice(rest);
        self.stripe_len = rest.len();
    }

    pub fn finalize(&self) -> [u8; OUT] {
        let mut root = Node::new(0, 1, true);
        for (i, leaf) in self.leaves.iter().enumerate() {
            let mut leaf = leaf.clone();
            let start = (i * BLOCK).min(self.stripe_len);
            let end = ((i + 1) * BLOCK).min(self.stripe_len);
            leaf.update(&self.stripe[start..end]);
            root.update(&leaf.finalize());
        }
        root.finalize()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(d: &[u8]) -> String {
        d.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn blake2s_rfc7693() {
        // Plain BLAKE2s-256 ("abc") from RFC 7693 Appendix B.
        let mut n = Node::new(0, 0, false);
        n.h = IV;
        n.h[0] ^= 0x0101_0020;
        n.update(b"abc");
        assert_eq!(hex(&n.finalize()), "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982");
    }

    #[test]
    fn empty() {
        assert_eq!(hex(&Blake2sp::new().finalize()), "dd0e891776933f43c7d032b08a917e25741f8aa9a12c12e1cac8801500f2ca4f");
    }

    #[test]
    fn split_points_agree() {
        let data: Vec<u8> = (0..(3u32 << 20) + 77).map(|i| (i * 13 + i / 97) as u8).collect();
        let mut whole = Blake2sp::new();
        whole.update(&data);
        let expect = whole.finalize();
        for step in [1usize, 37, 64, 512, 1000] {
            let mut h = Blake2sp::new();
            for c in data[..20_000].chunks(step) {
                h.update(c);
            }
            h.update(&data[20_000..]);
            assert_eq!(h.finalize(), expect, "step {step}");
        }
    }
}
