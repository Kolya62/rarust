// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! SHA-1, including the RAR 2.9 quirk which writes the expanded message
//! schedule back into the input buffer.

#[derive(Clone)]
pub struct Sha1 {
    state: [u32; 5],
    count: u64,
    buffer: [u8; 64],
}

/// Process one block. `w` receives the final 16-word circular message
/// schedule, which RAR 2.9 key derivation depends on.
fn transform(state: &mut [u32; 5], block: &[u8], w: &mut [u32; 16]) {
    for i in 0..16 {
        w[i] = u32::from_be_bytes(block[i * 4..i * 4 + 4].try_into().unwrap());
    }
    let (mut a, mut b, mut c, mut d, mut e) = (state[0], state[1], state[2], state[3], state[4]);
    for i in 0..80 {
        let wi = if i < 16 {
            w[i]
        } else {
            let v = (w[(i + 13) & 15] ^ w[(i + 8) & 15] ^ w[(i + 2) & 15] ^ w[i & 15]).rotate_left(1);
            w[i & 15] = v;
            v
        };
        let (f, k) = match i {
            0..=19 => (((c ^ d) & b) ^ d, 0x5A827999),
            20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
            40..=59 => (((b | c) & d) | (b & c), 0x8F1BBCDC),
            _ => (b ^ c ^ d, 0xCA62C1D6),
        };
        let t = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(wi);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = t;
    }
    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
}

impl Default for Sha1 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha1 {
    pub fn new() -> Self {
        Sha1 {
            state: [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0],
            count: 0,
            buffer: [0; 64],
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        let mut w = [0u32; 16];
        let j = (self.count & 63) as usize;
        self.count += data.len() as u64;
        let mut i = 0;
        let mut j2 = j;
        if j + data.len() > 63 {
            i = 64 - j;
            self.buffer[j..].copy_from_slice(&data[..i]);
            let b = self.buffer;
            transform(&mut self.state, &b, &mut w);
            while i + 63 < data.len() {
                transform(&mut self.state, &data[i..i + 64], &mut w);
                i += 64;
            }
            j2 = 0;
        }
        self.buffer[j2..j2 + data.len() - i].copy_from_slice(&data[i..]);
    }

    /// RAR 2.9 variant: full blocks taken directly from `data` are
    /// overwritten with the expanded message schedule after processing.
    pub fn update_rar29(&mut self, data: &mut [u8]) {
        let mut w = [0u32; 16];
        let j = (self.count & 63) as usize;
        self.count += data.len() as u64;
        let mut i = 0;
        let mut j2 = j;
        if j + data.len() > 63 {
            i = 64 - j;
            self.buffer[j..].copy_from_slice(&data[..i]);
            let b = self.buffer;
            transform(&mut self.state, &b, &mut w);
            while i + 63 < data.len() {
                transform(&mut self.state, &data[i..i + 64], &mut w);
                for k in 0..16 {
                    data[i + k * 4..i + k * 4 + 4].copy_from_slice(&w[k].to_le_bytes());
                }
                i += 64;
            }
            j2 = 0;
        }
        let n = data.len() - i;
        self.buffer[j2..j2 + n].copy_from_slice(&data[i..]);
    }

    pub fn finalize_words(&mut self) -> [u32; 5] {
        let mut w = [0u32; 16];
        let bit_len = self.count.wrapping_mul(8);
        let mut pos = (self.count & 0x3f) as usize;
        self.buffer[pos] = 0x80;
        pos += 1;
        if pos != 56 {
            if pos > 56 {
                while pos < 64 {
                    self.buffer[pos] = 0;
                    pos += 1;
                }
                pos = 0;
            }
            if pos == 0 {
                let b = self.buffer;
                transform(&mut self.state, &b, &mut w);
            }
            for x in &mut self.buffer[pos..56] {
                *x = 0;
            }
        }
        self.buffer[56..64].copy_from_slice(&bit_len.to_be_bytes());
        let b = self.buffer;
        transform(&mut self.state, &b, &mut w);
        let r = self.state;
        *self = Sha1::new();
        r
    }

    pub fn finalize(&mut self) -> [u8; 20] {
        let w = self.finalize_words();
        let mut out = [0u8; 20];
        for i in 0..5 {
            out[i * 4..i * 4 + 4].copy_from_slice(&w[i].to_be_bytes());
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn abc() {
        let mut s = Sha1::new();
        s.update(b"abc");
        assert_eq!(s.finalize()[..4], [0xa9, 0x99, 0x3e, 0x36]);
        let mut s = Sha1::new();
        let d = vec![b'a'; 1000];
        for _ in 0..1000 {
            s.update(&d);
        }
        assert_eq!(s.finalize()[..4], [0x34, 0xaa, 0x97, 0x3c]);
    }
}
