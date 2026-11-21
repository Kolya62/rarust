// SPDX-License-Identifier: GPL-3.0-or-later

//! SHA-1 (FIPS 180-4) with the RAR 3.x key derivation variant.

const INIT: [u32; 5] = [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476, 0xc3d2_e1f0];

#[derive(Clone)]
pub struct Sha1 {
    h: [u32; 5],
    pending: [u8; 64],
    pending_len: usize,
    total: u64,
}

impl Default for Sha1 {
    fn default() -> Self {
        Self::new()
    }
}

/// Runs the compression function on one block given as 16 big-endian words.
/// On return `w` holds the last 16 words of the message schedule.
fn compress(h: &mut [u32; 5], w: &mut [u32; 16]) {
    let [mut a, mut b, mut c, mut d, mut e] = *h;
    for t in 0..80 {
        let wt = if t < 16 {
            w[t]
        } else {
            let x = (w[(t + 13) & 15] ^ w[(t + 8) & 15] ^ w[(t + 2) & 15] ^ w[t & 15]).rotate_left(1);
            w[t & 15] = x;
            x
        };
        let (f, k) = match t / 20 {
            0 => ((b & c) | (!b & d), 0x5a82_7999),
            1 => (b ^ c ^ d, 0x6ed9_eba1),
            2 => ((b & c) | (b & d) | (c & d), 0x8f1b_bcdc),
            _ => (b ^ c ^ d, 0xca62_c1d6u32),
        };
        let tmp = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(wt);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = tmp;
    }
    for (s, v) in h.iter_mut().zip([a, b, c, d, e]) {
        *s = s.wrapping_add(v);
    }
}

fn load_words(block: &[u8]) -> [u32; 16] {
    let mut w = [0u32; 16];
    for (i, x) in w.iter_mut().enumerate() {
        *x = u32::from_be_bytes(block[i * 4..i * 4 + 4].try_into().unwrap());
    }
    w
}

impl Sha1 {
    pub fn new() -> Self {
        Sha1 { h: INIT, pending: [0; 64], pending_len: 0, total: 0 }
    }

    /// Feeds data. With `write_back`, every block taken directly from `data`
    /// (not the one completing previously buffered bytes) is replaced by its
    /// final message schedule words in little-endian order, as RAR 3.x key
    /// derivation expects.
    fn feed(&mut self, data: &mut [u8], write_back: bool) {
        self.total += data.len() as u64;
        let mut pos = 0;
        if self.pending_len > 0 {
            let take = (64 - self.pending_len).min(data.len());
            self.pending[self.pending_len..self.pending_len + take].copy_from_slice(&data[..take]);
            self.pending_len += take;
            pos = take;
            if self.pending_len < 64 {
                return;
            }
            let mut w = load_words(&self.pending);
            compress(&mut self.h, &mut w);
            self.pending_len = 0;
        } else if write_back && data.len() >= 64 {
            // The first full block is still hashed from a copy.
            self.pending.copy_from_slice(&data[..64]);
            let mut w = load_words(&self.pending);
            compress(&mut self.h, &mut w);
            pos = 64;
        }
        while data.len() - pos >= 64 {
            let block = &mut data[pos..pos + 64];
            let mut w = load_words(block);
            compress(&mut self.h, &mut w);
            if write_back {
                for (i, x) in w.iter().enumerate() {
                    block[i * 4..i * 4 + 4].copy_from_slice(&x.to_le_bytes());
                }
            }
            pos += 64;
        }
        let rest = data.len() - pos;
        self.pending[..rest].copy_from_slice(&data[pos..]);
        self.pending_len = rest;
    }

    pub fn update(&mut self, data: &[u8]) {
        let mut pos = 0;
        let mut buf = [0u8; 4096];
        while pos < data.len() {
            let n = (data.len() - pos).min(buf.len());
            buf[..n].copy_from_slice(&data[pos..pos + n]);
            self.feed(&mut buf[..n], false);
            pos += n;
        }
    }

    /// RAR 3.x variant: hashes `data` and modifies it in place.
    pub fn update_rar29(&mut self, data: &mut [u8]) {
        self.feed(data, true);
    }

    pub fn finalize_words(&mut self) -> [u32; 5] {
        let bits = self.total.wrapping_mul(8);
        let mut tail = [0u8; 72];
        tail[0] = 0x80;
        let pad = if self.pending_len < 56 { 56 - self.pending_len } else { 120 - self.pending_len };
        tail[pad..pad + 8].copy_from_slice(&bits.to_be_bytes());
        let mut tail = tail[..pad + 8].to_vec();
        self.feed(&mut tail, false);
        debug_assert_eq!(self.pending_len, 0);
        self.h
    }

    pub fn finalize(&mut self) -> [u8; 20] {
        let w = self.finalize_words();
        let mut out = [0u8; 20];
        for (i, x) in w.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&x.to_be_bytes());
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(d: &[u8]) -> String {
        d.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn vectors() {
        let mut s = Sha1::new();
        s.update(b"abc");
        assert_eq!(hex(&s.finalize()), "a9993e364706816aba3e25717850c26c9cd0d89d");
        let mut s = Sha1::new();
        s.update(b"");
        assert_eq!(hex(&s.finalize()), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        let mut s = Sha1::new();
        s.update(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        assert_eq!(hex(&s.finalize()), "84983e441c3bd26ebaae4aa1f95129e5e54670f1");
        let mut s = Sha1::new();
        let d = vec![b'a'; 1000];
        for _ in 0..1000 {
            s.update(&d);
        }
        assert_eq!(hex(&s.finalize()), "34aa973cd4c4daa4f61eeb2bdbad27316534016f");
    }
}
