// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Reading of raw header data.

use crate::crypt::{CryptData, CRYPT_BLOCK_MASK};
use crate::hash::crc32::crc32;

#[derive(Default)]
pub struct RawRead {
    data: Vec<u8>,
    data_size: usize,
    read_pos: usize,
}

impl RawRead {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn reset(&mut self) {
        self.data.clear();
        self.read_pos = 0;
        self.data_size = 0;
    }

    /// Read `size` bytes using the provided reader, optionally decrypting.
    pub fn read_from(&mut self, size: usize, crypt: Option<&mut CryptData>, rd: &mut dyn FnMut(&mut [u8]) -> i32) -> usize {
        let mut read_size = 0;
        if let Some(crypt) = crypt {
            let full = self.data.len();
            let left = full - self.data_size;
            if size > left {
                let to_read = size - left;
                let aligned = to_read + ((!to_read).wrapping_add(1) & CRYPT_BLOCK_MASK);
                self.data.resize(full + aligned, 0);
                let r = rd(&mut self.data[full..full + aligned]);
                read_size = r.max(0) as usize;
                crypt.decrypt(&mut self.data[full..full + aligned]);
                self.data_size += if read_size == 0 { 0 } else { size };
            } else {
                read_size = size;
                self.data_size += size;
            }
        } else if size != 0 {
            self.data.resize(self.data_size + size, 0);
            let ds = self.data_size;
            let r = rd(&mut self.data[ds..ds + size]);
            read_size = r.max(0) as usize;
            self.data_size += read_size;
        }
        read_size
    }

    /// Append data from memory.
    pub fn read_mem(&mut self, src: &[u8]) {
        if !src.is_empty() {
            self.data.truncate(self.data_size);
            self.data.extend_from_slice(src);
            self.data_size += src.len();
        }
    }

    pub fn get1(&mut self) -> u8 {
        if self.read_pos < self.data_size {
            let b = self.data[self.read_pos];
            self.read_pos += 1;
            b
        } else {
            0
        }
    }

    pub fn get2(&mut self) -> u16 {
        if self.read_pos + 1 < self.data_size {
            let r = u16::from_le_bytes([self.data[self.read_pos], self.data[self.read_pos + 1]]);
            self.read_pos += 2;
            r
        } else {
            0
        }
    }

    pub fn get4(&mut self) -> u32 {
        if self.read_pos + 3 < self.data_size {
            let r = u32::from_le_bytes(self.data[self.read_pos..self.read_pos + 4].try_into().unwrap());
            self.read_pos += 4;
            r
        } else {
            0
        }
    }

    pub fn get8(&mut self) -> u64 {
        let lo = self.get4() as u64;
        let hi = self.get4() as u64;
        (hi << 32) | lo
    }

    pub fn getv(&mut self) -> u64 {
        let mut result: u64 = 0;
        let mut shift = 0;
        while self.read_pos < self.data_size && shift < 64 {
            let b = self.data[self.read_pos];
            self.read_pos += 1;
            result = result.wrapping_add(((b & 0x7f) as u64) << shift);
            if b & 0x80 == 0 {
                return result;
            }
            shift += 7;
        }
        0
    }

    /// Number of bytes in variable length integer at `pos`.
    pub fn get_vsize(&self, pos: usize) -> usize {
        for cur in pos..self.data_size {
            if self.data[cur] & 0x80 == 0 {
                return cur - pos + 1;
            }
        }
        0
    }

    /// Copy `field.len()` bytes, zero filling the rest. Returns copied size.
    pub fn getb(&mut self, field: &mut [u8]) -> usize {
        let copy = (self.data_size - self.read_pos).min(field.len());
        field[..copy].copy_from_slice(&self.data[self.read_pos..self.read_pos + copy]);
        for b in &mut field[copy..] {
            *b = 0;
        }
        self.read_pos += copy;
        copy
    }

    pub fn getb_vec(&mut self, size: usize) -> Vec<u8> {
        let mut v = vec![0u8; size];
        self.getb(&mut v);
        v
    }

    pub fn get_crc15(&self, processed_only: bool) -> u32 {
        if self.data_size <= 2 {
            return 0;
        }
        let end = if processed_only { self.read_pos } else { self.data_size };
        let crc = crc32(0xffffffff, &self.data[2..end.max(2)]);
        !crc & 0xffff
    }

    pub fn get_crc50(&self) -> u32 {
        if self.data_size <= 4 {
            return 0xffffffff;
        }
        crc32(0xffffffff, &self.data[4..self.data_size]) ^ 0xffffffff
    }

    pub fn size(&self) -> usize {
        self.data_size
    }
    pub fn data_left(&self) -> usize {
        self.data_size - self.read_pos.min(self.data_size)
    }
    pub fn get_pos(&self) -> usize {
        self.read_pos
    }
    pub fn set_pos(&mut self, p: usize) {
        self.read_pos = p;
    }
    pub fn skip(&mut self, n: usize) {
        self.read_pos += n;
    }
    pub fn data(&self) -> &[u8] {
        &self.data[..self.data_size]
    }
}

/// Read vint from byte array. Returns None on overflow.
pub fn raw_get_v(data: &[u8], pos: &mut usize) -> Option<u64> {
    let mut result: u64 = 0;
    let mut shift = 0u32;
    while *pos < data.len() {
        let b = data[*pos];
        *pos += 1;
        if shift < 64 {
            result = result.wrapping_add(((b & 0x7f) as u64) << shift);
        }
        if b & 0x80 == 0 {
            return Some(result);
        }
        shift += 7;
    }
    None
}
