// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! RAR 5.0 and 7.0 decompression.

use super::*;
use crate::getbits::MAX_SIZE;

impl Unpack {
    pub(super) fn unpack5(&mut self, solid: bool, io: &mut dyn UnpackIo) {
        self.file_extracted = true;
        if !self.suspended {
            self.unp_init_data(solid);
            if !self.unp_read_buf(io) {
                return;
            }
            let mut bh = self.block_header;
            if !self.read_block_header(&mut bh, io) {
                self.block_header = bh;
                return;
            }
            self.block_header = bh;
            if !self.read_tables(io) || !self.tables_read5 {
                return;
            }
        }
        loop {
            self.unp_ptr = self.wrap_up(self.unp_ptr);
            self.first_win_done |= self.prev_ptr > self.unp_ptr;
            self.prev_ptr = self.unp_ptr;
            if self.inp.in_addr as i64 >= self.read_border {
                let mut file_done = false;
                loop {
                    let bh = self.block_header;
                    let a = self.inp.in_addr as i64;
                    let end = bh.block_start + bh.block_size - 1;
                    if !(a > end || a == end && self.inp.in_bit >= bh.block_bit_size) {
                        break;
                    }
                    if bh.last_block_in_file {
                        file_done = true;
                        break;
                    }
                    let mut bh = self.block_header;
                    let ok = self.read_block_header(&mut bh, io);
                    self.block_header = bh;
                    if !ok || !self.read_tables(io) {
                        return;
                    }
                }
                if file_done || !self.unp_read_buf(io) {
                    break;
                }
            }
            if self.wrap_down(self.write_border.wrapping_sub(self.unp_ptr)) <= MAX_INC_LZ_MATCH as usize
                && self.write_border != self.unp_ptr
            {
                self.unp_write_buf(io);
                if self.written_file_size > self.dest_unp_size {
                    return;
                }
                if self.suspended {
                    self.file_extracted = false;
                    return;
                }
            }
            let main_slot = Self::decode_number(&mut self.inp, &self.block_tables.ld);
            if main_slot < 256 {
                self.window[self.unp_ptr] = main_slot as u8;
                self.unp_ptr += 1;
                continue;
            }
            if main_slot >= 262 {
                let mut length = Self::slot_to_length(&mut self.inp, main_slot - 262);
                let mut distance: usize = 1;
                let dist_slot = Self::decode_number(&mut self.inp, &self.block_tables.dd);
                let dbits;
                if dist_slot < 4 {
                    dbits = 0;
                    distance += dist_slot as usize;
                } else {
                    dbits = dist_slot / 2 - 1;
                    distance = distance.wrapping_add(((2 | (dist_slot & 1)) as usize).wrapping_shl(dbits));
                }
                if dbits > 0 {
                    if dbits >= 4 {
                        if dbits > 4 {
                            if dbits > 36 {
                                distance = distance.wrapping_add(((self.inp.getbits64() as usize) >> (68 - dbits)) << 4);
                            } else {
                                distance = distance.wrapping_add(((self.inp.getbits32() as usize) >> (36 - dbits)) << 4);
                            }
                            self.inp.addbits(dbits - 4);
                        }
                        let low_dist = Self::decode_number(&mut self.inp, &self.block_tables.ldd);
                        distance = distance.wrapping_add(low_dist as usize);
                    } else {
                        distance += (self.inp.getbits() >> (16 - dbits)) as usize;
                        self.inp.addbits(dbits);
                    }
                }
                if distance > 0x100 {
                    length += 1;
                    if distance > 0x2000 {
                        length += 1;
                        if distance > 0x40000 {
                            length += 1;
                        }
                    }
                }
                self.insert_old_dist(distance);
                self.last_length = length;
                self.copy_string(length, distance);
                continue;
            }
            if main_slot == 256 {
                let mut f = UnpackFilter::default();
                if !self.read_filter(&mut f, io) || !self.add_filter(f, io) {
                    break;
                }
                continue;
            }
            if main_slot == 257 {
                if self.last_length != 0 {
                    let (l, d) = (self.last_length, self.old_dist[0]);
                    self.copy_string(l, d);
                }
                continue;
            }
            if main_slot < 262 {
                let dist_num = (main_slot - 258) as usize;
                let distance = self.old_dist[dist_num];
                for i in (1..=dist_num).rev() {
                    self.old_dist[i] = self.old_dist[i - 1];
                }
                self.old_dist[0] = distance;
                let length_slot = Self::decode_number(&mut self.inp, &self.block_tables.rd);
                let length = Self::slot_to_length(&mut self.inp, length_slot);
                self.last_length = length;
                self.copy_string(length, distance);
                continue;
            }
        }
        self.unp_write_buf(io);
    }

    fn read_filter_data(inp: &mut BitInput) -> u32 {
        let byte_count = (inp.fgetbits() >> 14) + 1;
        inp.addbits(2);
        let mut data: u32 = 0;
        for i in 0..byte_count {
            data = data.wrapping_add((inp.fgetbits() >> 8) << (i * 8));
            inp.addbits(8);
        }
        data
    }

    fn read_filter(&mut self, f: &mut UnpackFilter, io: &mut dyn UnpackIo) -> bool {
        if !self.inp.external_buffer && self.inp.in_addr as i64 > self.read_top - 16 && !self.unp_read_buf(io) {
            return false;
        }
        f.block_start = Self::read_filter_data(&mut self.inp) as usize;
        f.block_length = Self::read_filter_data(&mut self.inp);
        if f.block_length > MAX_FILTER_BLOCK_SIZE {
            f.block_length = 0;
        }
        f.filter_type = (self.inp.fgetbits() >> 13) as u8;
        self.inp.faddbits(3);
        if f.filter_type == FILTER_DELTA {
            f.channels = ((self.inp.fgetbits() >> 11) + 1) as u8;
            self.inp.faddbits(5);
        }
        true
    }

    pub(super) fn add_filter_mt(&mut self, f: UnpackFilter, io: &mut dyn UnpackIo) -> bool {
        self.add_filter(f, io)
    }

    fn add_filter(&mut self, mut f: UnpackFilter, io: &mut dyn UnpackIo) -> bool {
        if self.filters.len() >= MAX_UNPACK_FILTERS {
            self.unp_write_buf(io);
            if self.filters.len() >= MAX_UNPACK_FILTERS {
                self.filters.clear();
            }
        }
        f.next_window = self.wr_ptr != self.unp_ptr && self.wrap_down(self.wr_ptr.wrapping_sub(self.unp_ptr)) <= f.block_start;
        f.block_start = (f.block_start.wrapping_add(self.unp_ptr)) % self.max_win_size;
        self.filters.push(f);
        true
    }

    pub(super) fn unp_write_buf(&mut self, io: &mut dyn UnpackIo) {
        let mut written_border = self.wr_ptr;
        let full_write_size = self.wrap_down(self.unp_ptr.wrapping_sub(written_border));
        let mut write_size_left = full_write_size;
        let mut not_all = false;
        let mut i = 0;
        while i < self.filters.len() {
            let flt = self.filters[i];
            if flt.filter_type == FILTER_NONE {
                i += 1;
                continue;
            }
            if flt.next_window {
                if self.wrap_down(flt.block_start.wrapping_sub(self.wr_ptr)) <= full_write_size {
                    self.filters[i].next_window = false;
                }
                i += 1;
                continue;
            }
            let block_start = flt.block_start;
            let block_length = flt.block_length as usize;
            if self.wrap_down(block_start.wrapping_sub(written_border)) < write_size_left {
                if written_border != block_start {
                    self.unp_write_area(written_border, block_start, io);
                    written_border = block_start;
                    write_size_left = self.wrap_down(self.unp_ptr.wrapping_sub(written_border));
                }
                if block_length <= write_size_left {
                    if block_length > 0 {
                        let block_end = self.wrap_up(block_start + block_length);
                        let mut mem = std::mem::take(&mut self.filter_src_memory);
                        mem.resize(block_length, 0);
                        if block_start < block_end || block_end == 0 {
                            mem.copy_from_slice(&self.window[block_start..block_start + block_length]);
                        } else {
                            let first = self.max_win_size - block_start;
                            mem[..first].copy_from_slice(&self.window[block_start..self.max_win_size]);
                            mem[first..].copy_from_slice(&self.window[..block_end]);
                        }
                        let out = self.apply_filter(&mut mem, &flt);
                        self.filters[i].filter_type = FILTER_NONE;
                        match out {
                            Some(true) => io.unp_write(&mem),
                            Some(false) => {
                                let d = std::mem::take(&mut self.filter_dst_memory);
                                io.unp_write(&d);
                                self.filter_dst_memory = d;
                            }
                            None => {}
                        }
                        self.filter_src_memory = mem;
                        self.unp_some_read = true;
                        self.written_file_size += block_length as i64;
                        written_border = block_end;
                        write_size_left = self.wrap_down(self.unp_ptr.wrapping_sub(written_border));
                    }
                } else {
                    self.wr_ptr = written_border;
                    for j in i..self.filters.len() {
                        if self.filters[j].filter_type != FILTER_NONE {
                            self.filters[j].next_window = false;
                        }
                    }
                    not_all = true;
                    break;
                }
            }
            i += 1;
        }
        self.filters.retain(|f| f.filter_type != FILTER_NONE);
        if !not_all {
            let up = self.unp_ptr;
            self.unp_write_area(written_border, up, io);
            self.wr_ptr = self.unp_ptr;
        }
        self.write_border = self.wrap_up(self.unp_ptr + self.max_win_size.min(UNPACK_MAX_WRITE));
        if self.write_border == self.unp_ptr
            || self.wr_ptr != self.unp_ptr
                && self.wrap_down(self.wr_ptr.wrapping_sub(self.unp_ptr)) < self.wrap_down(self.write_border.wrapping_sub(self.unp_ptr))
        {
            self.write_border = self.wr_ptr;
        }
    }

    /// Apply filter. Returns Some(true) if result is in `data`, Some(false)
    /// if result is in filter_dst_memory and None for unknown filter.
    fn apply_filter(&mut self, data: &mut [u8], flt: &UnpackFilter) -> Option<bool> {
        let data_size = data.len() as u32;
        match flt.filter_type {
            FILTER_E8 | FILTER_E8E9 => {
                let file_offset = self.written_file_size as u32;
                const FILE_SIZE: u32 = 0x1000000;
                let cmp2 = if flt.filter_type == FILTER_E8E9 { 0xe9 } else { 0xe8 };
                let mut cur_pos: u32 = 0;
                while cur_pos + 4 < data_size {
                    let cur_byte = data[cur_pos as usize];
                    cur_pos += 1;
                    if cur_byte == 0xe8 || cur_byte == cmp2 {
                        let offset = cur_pos.wrapping_add(file_offset) % FILE_SIZE;
                        let p = cur_pos as usize;
                        let addr = u32::from_le_bytes(data[p..p + 4].try_into().unwrap());
                        if addr & 0x80000000 != 0 {
                            if addr.wrapping_add(offset) & 0x80000000 == 0 {
                                data[p..p + 4].copy_from_slice(&addr.wrapping_add(FILE_SIZE).to_le_bytes());
                            }
                        } else if addr.wrapping_sub(FILE_SIZE) & 0x80000000 != 0 {
                            data[p..p + 4].copy_from_slice(&addr.wrapping_sub(offset).to_le_bytes());
                        }
                        cur_pos += 4;
                    }
                }
                Some(true)
            }
            FILTER_ARM => {
                let file_offset = self.written_file_size as u32;
                let mut cur_pos: u32 = 0;
                while cur_pos + 3 < data_size {
                    let p = cur_pos as usize;
                    if data[p + 3] == 0xeb {
                        let mut offset = data[p] as u32 + (data[p + 1] as u32) * 0x100 + (data[p + 2] as u32) * 0x10000;
                        offset = offset.wrapping_sub(file_offset.wrapping_add(cur_pos) / 4);
                        data[p] = offset as u8;
                        data[p + 1] = (offset >> 8) as u8;
                        data[p + 2] = (offset >> 16) as u8;
                    }
                    cur_pos += 4;
                }
                Some(true)
            }
            FILTER_DELTA => {
                let channels = flt.channels as usize;
                let size = data.len();
                self.filter_dst_memory.resize(size, 0);
                let dst = &mut self.filter_dst_memory;
                let mut src_pos = 0;
                for ch in 0..channels {
                    let mut prev: u8 = 0;
                    let mut d = ch;
                    while d < size {
                        prev = prev.wrapping_sub(data[src_pos]);
                        dst[d] = prev;
                        src_pos += 1;
                        d += channels;
                    }
                }
                Some(false)
            }
            _ => None,
        }
    }

    fn read_block_header(&mut self, header: &mut UnpackBlockHeader, io: &mut dyn UnpackIo) -> bool {
        header.header_size = 0;
        if !self.inp.external_buffer && self.inp.in_addr as i64 > self.read_top - 7 {
            self.block_header = *header;
            let ok = self.unp_read_buf(io);
            *header = self.block_header;
            if !ok {
                return false;
            }
        }
        self.inp.faddbits((8 - self.inp.in_bit) & 7);
        let block_flags = (self.inp.fgetbits() >> 8) as u8;
        self.inp.faddbits(8);
        let byte_count = ((block_flags >> 3) & 3) as u32 + 1;
        if byte_count == 4 {
            return false;
        }
        header.header_size = 2 + byte_count;
        header.block_bit_size = (block_flags & 7) as u32 + 1;
        let saved_checksum = (self.inp.fgetbits() >> 8) as u8;
        self.inp.faddbits(8);
        let mut block_size: u32 = 0;
        for i in 0..byte_count {
            block_size = block_size.wrapping_add((self.inp.fgetbits() >> 8) << (i * 8));
            self.inp.addbits(8);
        }
        header.block_size = block_size as i32 as i64;
        let checksum = (0x5a ^ block_flags as u32 ^ block_size ^ (block_size >> 8) ^ (block_size >> 16)) as u8;
        if checksum != saved_checksum {
            return false;
        }
        header.block_start = self.inp.in_addr as i64;
        self.read_border = self.read_border.min(header.block_start + header.block_size - 1);
        header.last_block_in_file = block_flags & 0x40 != 0;
        header.table_present = block_flags & 0x80 != 0;
        true
    }

    fn read_tables(&mut self, io: &mut dyn UnpackIo) -> bool {
        if !self.block_header.table_present {
            return true;
        }
        if !self.inp.external_buffer && self.inp.in_addr as i64 > self.read_top - 25 && !self.unp_read_buf(io) {
            return false;
        }
        let mut bit_length = [0u8; BC];
        let mut i = 0;
        while i < BC {
            let length = (self.inp.fgetbits() >> 12) as u8;
            self.inp.faddbits(4);
            if length == 15 {
                let mut zero_count = (self.inp.fgetbits() >> 12) as u8 as u32;
                self.inp.faddbits(4);
                if zero_count == 0 {
                    bit_length[i] = 15;
                } else {
                    zero_count += 2;
                    while zero_count > 0 && i < BC {
                        bit_length[i] = 0;
                        i += 1;
                        zero_count -= 1;
                    }
                    i -= 1;
                }
            } else {
                bit_length[i] = length;
            }
            i += 1;
        }
        Self::make_decode_tables(&bit_length, &mut self.block_tables.bd, BC);
        let mut table = [0u8; HUFF_TABLE_SIZEX];
        let table_size = if self.extra_dist { HUFF_TABLE_SIZEX } else { HUFF_TABLE_SIZEB };
        let mut i = 0;
        while i < table_size {
            if !self.inp.external_buffer && self.inp.in_addr as i64 > self.read_top - 5 && !self.unp_read_buf(io) {
                return false;
            }
            let number = Self::decode_number(&mut self.inp, &self.block_tables.bd);
            if number < 16 {
                table[i] = number as u8;
                i += 1;
            } else if number < 18 {
                let mut n;
                if number == 16 {
                    n = (self.inp.fgetbits() >> 13) + 3;
                    self.inp.faddbits(3);
                } else {
                    n = (self.inp.fgetbits() >> 9) + 11;
                    self.inp.faddbits(7);
                }
                if i == 0 {
                    return false;
                }
                while n > 0 && i < table_size {
                    table[i] = table[i - 1];
                    i += 1;
                    n -= 1;
                }
            } else {
                let mut n;
                if number == 18 {
                    n = (self.inp.fgetbits() >> 13) + 3;
                    self.inp.faddbits(3);
                } else {
                    n = (self.inp.fgetbits() >> 9) + 11;
                    self.inp.faddbits(7);
                }
                while n > 0 && i < table_size {
                    table[i] = 0;
                    i += 1;
                    n -= 1;
                }
            }
        }
        self.tables_read5 = true;
        if !self.inp.external_buffer && self.inp.in_addr as i64 > self.read_top {
            return false;
        }
        let dcodes = if self.extra_dist { DCX } else { DCB };
        let bt = &mut *self.block_tables;
        Self::make_decode_tables(&table[0..], &mut bt.ld, NC);
        Self::make_decode_tables(&table[NC..], &mut bt.dd, dcodes);
        Self::make_decode_tables(&table[NC + dcodes..], &mut bt.ldd, LDC);
        Self::make_decode_tables(&table[NC + dcodes + LDC..], &mut bt.rd, RC);
        let _ = MAX_SIZE;
        true
    }
}
