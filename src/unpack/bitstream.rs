// SPDX-License-Identifier: GPL-3.0-or-later

//! MSB-first bit reader over packed data that arrives in pieces, used by
//! the RAR 1.5-3.x decoders.

use super::huffman::BitSource;
use super::UnpackIo;

const CHUNK: usize = 0x10000;
/// Bytes kept available ahead of the read position when possible.
const LOOKAHEAD: usize = 64;

pub struct StreamBits {
    buf: Vec<u8>,
    /// Valid bytes in `buf`; the rest of `buf` is zero.
    len: usize,
    /// Bit position in `buf`.
    pos: u64,
    eof: bool,
}

impl Default for StreamBits {
    fn default() -> Self {
        StreamBits { buf: vec![0; CHUNK + LOOKAHEAD + 8], len: 0, pos: 0, eof: false }
    }
}

impl StreamBits {
    /// Starts reading a new packed stream.
    pub fn reset(&mut self) {
        self.buf.fill(0);
        self.len = 0;
        self.pos = 0;
        self.eof = false;
    }

    /// Makes at least `LOOKAHEAD` bytes available unless the input ended.
    /// Returns false on a read error.
    pub fn fill(&mut self, io: &mut dyn UnpackIo) -> bool {
        let byte = (self.pos >> 3) as usize;
        if self.eof || self.len.saturating_sub(byte) >= LOOKAHEAD {
            return true;
        }
        // Move the unread bytes to the front.
        let keep = byte.min(self.len);
        self.buf.copy_within(keep..self.len, 0);
        self.len -= keep;
        self.pos -= (keep as u64) * 8;
        self.buf[self.len..].fill(0);
        while self.len < CHUNK {
            let n = io.unp_read(&mut self.buf[self.len..CHUNK + LOOKAHEAD]);
            if n < 0 {
                self.eof = true;
                return false;
            }
            if n == 0 {
                self.eof = true;
                break;
            }
            self.len += n as usize;
        }
        true
    }

    /// True when more bits were consumed than the input had.
    pub fn overrun(&self) -> bool {
        self.pos > self.len as u64 * 8
    }

    /// Unread whole bytes, counting only data already buffered after
    /// `fill`.
    pub fn bytes_left(&self) -> usize {
        self.len.saturating_sub(((self.pos + 7) >> 3) as usize)
    }

    pub fn take(&mut self, n: u32) -> u32 {
        if n == 0 {
            return 0;
        }
        let v = self.peek32() >> (32 - n);
        self.pos += n as u64;
        v
    }

    /// Skips to the next byte boundary.
    pub fn align(&mut self) {
        self.pos = (self.pos + 7) & !7;
    }

    pub fn byte_pos(&self) -> usize {
        (self.pos >> 3) as usize
    }

    /// The buffered bytes starting at the current byte position.
    pub fn buffered(&self) -> &[u8] {
        &self.buf[self.byte_pos().min(self.len)..self.len]
    }

    pub fn skip_bytes(&mut self, n: usize) {
        self.pos += n as u64 * 8;
    }
}

impl BitSource for StreamBits {
    #[inline(always)]
    fn peek32(&mut self) -> u32 {
        let byte = (self.pos >> 3) as usize;
        let mut w = [0u8; 8];
        if let Some(s) = self.buf.get(byte..byte + 8) {
            w.copy_from_slice(s);
        }
        (u64::from_be_bytes(w) << (self.pos & 7) >> 32) as u32
    }

    #[inline(always)]
    fn skip(&mut self, n: u32) {
        self.pos += n as u64;
    }
}
