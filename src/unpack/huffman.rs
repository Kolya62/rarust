// SPDX-License-Identifier: GPL-3.0-or-later

//! Canonical Huffman decoding shared by all RAR formats: codes are
//! assigned in order of (length, symbol), read MSB first, at most 15 bits.

pub const MAX_CODE_LEN: u32 = 15;
const QUICK_BITS: u32 = 10;

/// Bit stream the decoder reads from.
pub trait BitSource {
    /// Next 32 bits, MSB first; bits past the end read as zero.
    fn peek32(&mut self) -> u32;
    fn skip(&mut self, n: u32);
}

#[derive(Clone)]
pub struct Huffman {
    /// `limit[l]`: end of the codes of length `l` as a left aligned 15-bit
    /// number.
    limit: [u32; MAX_CODE_LEN as usize + 1],
    /// `first[l]`: first code of length `l`.
    first: [u32; MAX_CODE_LEN as usize + 1],
    /// `index[l]`: position of the first symbol of length `l` in `symbols`.
    index: [u32; MAX_CODE_LEN as usize + 1],
    symbols: Vec<u16>,
    /// Indexed by the next `QUICK_BITS` bits: symbol << 4 | length, or 0
    /// when the code is longer.
    quick: Vec<u16>,
}

impl Default for Huffman {
    fn default() -> Self {
        Huffman {
            limit: [0; MAX_CODE_LEN as usize + 1],
            first: [0; MAX_CODE_LEN as usize + 1],
            index: [0; MAX_CODE_LEN as usize + 1],
            symbols: Vec::new(),
            quick: vec![0; 1 << QUICK_BITS],
        }
    }
}

impl Huffman {
    pub fn new(lengths: &[u8]) -> Self {
        let mut h = Huffman::default();
        h.build(lengths);
        h
    }

    /// Builds the code from bit lengths (0 = symbol unused, values above 15
    /// are taken modulo 16).
    pub fn build(&mut self, lengths: &[u8]) {
        let mut count = [0u32; MAX_CODE_LEN as usize + 1];
        for &l in lengths {
            count[(l & 15) as usize] += 1;
        }
        count[0] = 0;
        let mut code = 0u32;
        let mut index = 0u32;
        for l in 1..=MAX_CODE_LEN as usize {
            self.first[l] = code;
            self.index[l] = index;
            code += count[l];
            index += count[l];
            // Oversubscribed (corrupt) codes saturate.
            self.limit[l] = (code << (MAX_CODE_LEN as usize - l)).min(1 << MAX_CODE_LEN);
            code <<= 1;
        }
        self.symbols.clear();
        self.symbols.resize(index as usize, 0);
        let mut next = self.index;
        for (sym, &l) in lengths.iter().enumerate() {
            let l = (l & 15) as usize;
            if l != 0 {
                self.symbols[next[l] as usize] = sym as u16;
                next[l] += 1;
            }
        }
        for v in 0..1usize << QUICK_BITS {
            let bits = (v as u32) << (MAX_CODE_LEN - QUICK_BITS);
            let (sym, len) = self.lookup(bits);
            self.quick[v] = if len <= QUICK_BITS { sym << 4 | len as u16 } else { 0 };
        }
    }

    /// Symbol and code length for 15 left aligned bits. A bit pattern that
    /// is not a code (incomplete or corrupt tables) decodes as symbol 0
    /// with length 15.
    #[inline(always)]
    fn lookup(&self, bits: u32) -> (u16, u32) {
        for l in 1..=MAX_CODE_LEN as usize {
            if bits < self.limit[l] {
                let code = bits >> (MAX_CODE_LEN as usize - l);
                let pos = self.index[l] as usize + code.wrapping_sub(self.first[l]) as usize;
                return (self.symbols.get(pos).copied().unwrap_or(0), l as u32);
            }
        }
        (0, MAX_CODE_LEN)
    }

    #[inline(always)]
    pub fn decode(&self, inp: &mut impl BitSource) -> u16 {
        let bits = inp.peek32() >> (32 - MAX_CODE_LEN);
        let q = self.quick[(bits >> (MAX_CODE_LEN - QUICK_BITS)) as usize];
        if q != 0 {
            inp.skip((q & 15) as u32);
            return q >> 4;
        }
        let (sym, len) = self.lookup(bits);
        inp.skip(len);
        sym
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct V(u64, u32);
    impl BitSource for V {
        fn peek32(&mut self) -> u32 {
            (self.0 << self.1 >> 32) as u32
        }
        fn skip(&mut self, n: u32) {
            self.1 += n;
        }
    }

    #[test]
    fn canonical() {
        // Lengths 2,1,3,3 give codes 10, 0, 110, 111.
        let h = Huffman::new(&[2, 1, 3, 3]);
        let mut v = V(0b1001_1011_1u64 << 55, 0);
        assert_eq!([h.decode(&mut v), h.decode(&mut v), h.decode(&mut v), h.decode(&mut v)], [0, 1, 2, 3]);
    }

    #[test]
    fn long_codes() {
        let mut lens = vec![15u8; 4];
        lens.push(1);
        let h = Huffman::new(&lens);
        // Symbol 4 has code 0; symbols 0..3 have 15-bit codes 1000..0 + i.
        let mut v = V((0b100_0000_0000_0010u64 << 49) | (0 << 48), 0);
        assert_eq!(h.decode(&mut v), 2);
        assert_eq!(h.decode(&mut v), 4);
    }
}
