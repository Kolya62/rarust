// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Bit input buffer used by decompression routines.

pub const MAX_SIZE: usize = 0x8000;
const PAD: usize = 64;

pub struct BitInput {
    pub in_addr: usize,
    pub in_bit: u32,
    pub in_buf: Vec<u8>,
    pub external_buffer: bool,
}

impl Default for BitInput {
    fn default() -> Self {
        Self::new()
    }
}

impl BitInput {
    pub fn new() -> Self {
        BitInput { in_addr: 0, in_bit: 0, in_buf: vec![0; MAX_SIZE + PAD], external_buffer: false }
    }

    /// Create with buffer of specified size (plus padding).
    pub fn with_size(size: usize) -> Self {
        BitInput { in_addr: 0, in_bit: 0, in_buf: vec![0; size + PAD], external_buffer: false }
    }

    pub fn init_bit_input(&mut self) {
        self.in_addr = 0;
        self.in_bit = 0;
    }

    #[inline(always)]
    pub fn addbits(&mut self, bits: u32) {
        let b = bits + self.in_bit;
        self.in_addr += (b >> 3) as usize;
        self.in_bit = b & 7;
    }

    #[inline(always)]
    pub fn faddbits(&mut self, bits: u32) {
        self.addbits(bits)
    }

    #[inline(always)]
    fn byte(&self, i: usize) -> u32 {
        match self.in_buf.get(i) {
            Some(&b) => b as u32,
            None => 0,
        }
    }

    #[inline(always)]
    fn be4(&self, a: usize) -> u32 {
        if let Some(s) = self.in_buf.get(a..a + 4) {
            u32::from_be_bytes([s[0], s[1], s[2], s[3]])
        } else {
            (self.byte(a) << 24) | (self.byte(a + 1) << 16) | (self.byte(a + 2) << 8) | self.byte(a + 3)
        }
    }

    /// Return 16 bits from current position.
    #[inline(always)]
    pub fn getbits(&self) -> u32 {
        (self.be4(self.in_addr) >> (16 - self.in_bit)) & 0xffff
    }

    #[inline(always)]
    pub fn fgetbits(&self) -> u32 {
        self.getbits()
    }

    /// Return 32 bits from current position.
    #[inline(always)]
    pub fn getbits32(&self) -> u32 {
        let mut bf = self.be4(self.in_addr) << self.in_bit;
        bf |= self.byte(self.in_addr + 4) >> (8 - self.in_bit);
        bf
    }

    /// Return 64 bits from current position.
    #[inline(always)]
    pub fn getbits64(&self) -> u64 {
        let hi = self.be4(self.in_addr) as u64;
        let lo = self.be4(self.in_addr + 4) as u64;
        let mut bf = ((hi << 32) | lo) << self.in_bit;
        bf |= (self.byte(self.in_addr + 8) >> (8 - self.in_bit)) as u64;
        bf
    }

    /// Check if buffer has enough space for inc_ptr bytes. Returns true if
    /// buffer will overflow.
    pub fn overflow(&self, inc_ptr: usize) -> bool {
        self.in_addr + inc_ptr >= MAX_SIZE
    }
}
