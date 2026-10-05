// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! RAR 3.x decompression.

use super::rarvm::{RarVM, VM_MEMSIZE};
use super::*;

const LDECODE: [u8; 28] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 14, 16, 20, 24, 28, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224];
const LBITS: [u8; 28] = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5];
const DBIT_LENGTH_COUNTS: [u32; 19] = [4, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 14, 0, 12];
const SDDECODE: [u8; 8] = [0, 4, 8, 16, 32, 64, 128, 192];
const SDBITS: [u8; 8] = [2, 2, 3, 4, 5, 6, 6, 6];

struct DTables {
    ddecode: [u32; DC30],
    dbits: [u8; DC30],
}

fn dtables() -> &'static DTables {
    static T: std::sync::OnceLock<DTables> = std::sync::OnceLock::new();
    T.get_or_init(|| {
        let mut t = DTables { ddecode: [0; DC30], dbits: [0; DC30] };
        let (mut dist, mut slot) = (0u32, 0usize);
        for (bit_length, &cnt) in DBIT_LENGTH_COUNTS.iter().enumerate() {
            for _ in 0..cnt {
                t.ddecode[slot] = dist;
                t.dbits[slot] = bit_length as u8;
                slot += 1;
                dist += 1 << bit_length;
            }
        }
        t
    })
}

impl Unpack {
    fn ppm_decode_char(&mut self, io: &mut dyn UnpackIo) -> i32 {
        let mut ppm = self.ppm.take().unwrap();
        let ch = ppm.decode_char(&mut || self.get_char(io));
        self.ppm = Some(ppm);
        ch
    }

    fn safe_ppm_decode_char(&mut self, io: &mut dyn UnpackIo) -> i32 {
        let ch = self.ppm_decode_char(io);
        if ch == -1 {
            self.ppm.as_mut().unwrap().clean_up();
            self.unp_block_ppm = false;
        }
        ch
    }

    pub(super) fn unpack29(&mut self, solid: bool, io: &mut dyn UnpackIo) {
        let dt = dtables();
        self.file_extracted = true;
        if !self.suspended {
            self.unp_init_data(solid);
            if !self.unp_read_buf30(io) {
                return;
            }
            if (!solid || !self.tables_read3) && !self.read_tables30(io) {
                return;
            }
        }
        loop {
            self.unp_ptr &= self.max_win_mask;
            self.first_win_done |= self.prev_ptr > self.unp_ptr;
            self.prev_ptr = self.unp_ptr;
            if self.inp.in_addr as i64 > self.read_border && !self.unp_read_buf30(io) {
                break;
            }
            if (self.wr_ptr.wrapping_sub(self.unp_ptr) & self.max_win_mask) <= MAX3_INC_LZ_MATCH as usize && self.wr_ptr != self.unp_ptr {
                self.unp_write_buf30(io);
                if self.written_file_size > self.dest_unp_size {
                    return;
                }
                if self.suspended {
                    self.file_extracted = false;
                    return;
                }
            }
            if self.unp_block_ppm {
                let ch = self.ppm_decode_char(io);
                if ch == -1 {
                    self.ppm.as_mut().unwrap().clean_up();
                    self.unp_block_ppm = false;
                    break;
                }
                if ch == self.ppm_esc_char {
                    let next_ch = self.safe_ppm_decode_char(io);
                    if next_ch == 0 {
                        if !self.read_tables30(io) {
                            break;
                        }
                        continue;
                    }
                    if next_ch == -1 || next_ch == 2 {
                        break;
                    }
                    if next_ch == 3 {
                        if !self.read_vm_code_ppm(io) {
                            break;
                        }
                        continue;
                    }
                    if next_ch == 4 {
                        let mut distance: u32 = 0;
                        let mut length: u32 = 0;
                        let mut failed = false;
                        for i in 0..4 {
                            let c = self.safe_ppm_decode_char(io);
                            if c == -1 {
                                failed = true;
                                break;
                            }
                            if i == 3 {
                                length = c as u8 as u32;
                            } else {
                                distance = (distance << 8) + c as u8 as u32;
                            }
                        }
                        if failed {
                            break;
                        }
                        self.copy_string(length + 32, distance as usize + 2);
                        continue;
                    }
                    if next_ch == 5 {
                        let length = self.safe_ppm_decode_char(io);
                        if length == -1 {
                            break;
                        }
                        self.copy_string(length as u32 + 4, 1);
                        continue;
                    }
                }
                self.window[self.unp_ptr] = ch as u8;
                self.unp_ptr += 1;
                continue;
            }
            let number = Self::decode_number(&mut self.inp, &self.block_tables.ld);
            if number < 256 {
                self.window[self.unp_ptr] = number as u8;
                self.unp_ptr += 1;
                continue;
            }
            if number >= 271 {
                let n = (number - 271) as usize;
                if n >= LDECODE.len() {
                    continue;
                }
                let mut length = LDECODE[n] as u32 + 3;
                let bits = LBITS[n] as u32;
                if bits > 0 {
                    length += self.inp.getbits() >> (16 - bits);
                    self.inp.addbits(bits);
                }
                let dist_number = (Self::decode_number(&mut self.inp, &self.block_tables.dd) as usize).min(DC30 - 1);
                let mut distance = dt.ddecode[dist_number] + 1;
                let bits = dt.dbits[dist_number] as u32;
                if bits > 0 {
                    if dist_number > 9 {
                        if bits > 4 {
                            distance = distance.wrapping_add((self.inp.getbits() >> (20 - bits)) << 4);
                            self.inp.addbits(bits - 4);
                        }
                        if self.low_dist_rep_count > 0 {
                            self.low_dist_rep_count -= 1;
                            distance = distance.wrapping_add(self.prev_low_dist as u32);
                        } else {
                            let low_dist = Self::decode_number(&mut self.inp, &self.block_tables.ldd);
                            if low_dist == 16 {
                                self.low_dist_rep_count = LOW_DIST_REP_COUNT as i32 - 1;
                                distance = distance.wrapping_add(self.prev_low_dist as u32);
                            } else {
                                distance = distance.wrapping_add(low_dist);
                                self.prev_low_dist = low_dist as i32;
                            }
                        }
                    } else {
                        distance += self.inp.getbits() >> (16 - bits);
                        self.inp.addbits(bits);
                    }
                }
                if distance >= 0x2000 {
                    length += 1;
                    if distance >= 0x40000 {
                        length += 1;
                    }
                }
                self.insert_old_dist(distance as usize);
                self.last_length = length;
                self.copy_string(length, distance as usize);
                continue;
            }
            if number == 256 {
                if !self.read_end_of_block(io) {
                    break;
                }
                continue;
            }
            if number == 257 {
                if !self.read_vm_code(io) {
                    break;
                }
                continue;
            }
            if number == 258 {
                if self.last_length != 0 {
                    let (l, d) = (self.last_length, self.old_dist[0]);
                    self.copy_string(l, d);
                }
                continue;
            }
            if number < 263 {
                let dist_num = (number - 259) as usize;
                let distance = self.old_dist[dist_num] as u32;
                for i in (1..=dist_num).rev() {
                    self.old_dist[i] = self.old_dist[i - 1];
                }
                self.old_dist[0] = distance as usize;
                let length_number = (Self::decode_number(&mut self.inp, &self.block_tables.rd) as usize).min(LDECODE.len() - 1);
                let mut length = LDECODE[length_number] as u32 + 2;
                let bits = LBITS[length_number] as u32;
                if bits > 0 {
                    length += self.inp.getbits() >> (16 - bits);
                    self.inp.addbits(bits);
                }
                self.last_length = length;
                self.copy_string(length, distance as usize);
                continue;
            }
            if number < 272 {
                let n = (number - 263) as usize;
                let mut distance = SDDECODE[n] as u32 + 1;
                let bits = SDBITS[n] as u32;
                if bits > 0 {
                    distance += self.inp.getbits() >> (16 - bits);
                    self.inp.addbits(bits);
                }
                self.insert_old_dist(distance as usize);
                self.last_length = 2;
                self.copy_string(2, distance as usize);
                continue;
            }
        }
        self.unp_write_buf30(io);
    }

    fn read_end_of_block(&mut self, io: &mut dyn UnpackIo) -> bool {
        let bit_field = self.inp.getbits();
        let new_table;
        let mut new_file = false;
        if bit_field & 0x8000 != 0 {
            new_table = true;
            self.inp.addbits(1);
        } else {
            new_file = true;
            new_table = bit_field & 0x4000 != 0;
            self.inp.addbits(2);
        }
        self.tables_read3 = !new_table;
        if new_file {
            return false;
        }
        self.read_tables30(io)
    }

    fn read_vm_code(&mut self, io: &mut dyn UnpackIo) -> bool {
        let first_byte = self.inp.getbits() >> 8;
        self.inp.addbits(8);
        let mut length = (first_byte & 7) + 1;
        if length == 7 {
            length = (self.inp.getbits() >> 8) + 7;
            self.inp.addbits(8);
        } else if length == 8 {
            length = self.inp.getbits();
            self.inp.addbits(16);
        }
        if length == 0 {
            return false;
        }
        let mut code = vec![0u8; length as usize];
        for i in 0..length as usize {
            if self.inp.in_addr as i64 >= self.read_top - 1 && !self.unp_read_buf30(io) && i < length as usize - 1 {
                return false;
            }
            code[i] = (self.inp.getbits() >> 8) as u8;
            self.inp.addbits(8);
        }
        self.add_vm_code(first_byte, &code)
    }

    fn read_vm_code_ppm(&mut self, io: &mut dyn UnpackIo) -> bool {
        let first_byte = self.safe_ppm_decode_char(io);
        if first_byte == -1 {
            return false;
        }
        let first_byte = first_byte as u32;
        let mut length = (first_byte & 7) + 1;
        if length == 7 {
            let b1 = self.safe_ppm_decode_char(io);
            if b1 == -1 {
                return false;
            }
            length = b1 as u32 + 7;
        } else if length == 8 {
            let b1 = self.safe_ppm_decode_char(io);
            if b1 == -1 {
                return false;
            }
            let b2 = self.safe_ppm_decode_char(io);
            if b2 == -1 {
                return false;
            }
            length = b1 as u32 * 256 + b2 as u32;
        }
        if length == 0 {
            return false;
        }
        let mut code = vec![0u8; length as usize];
        for c in code.iter_mut() {
            let ch = self.safe_ppm_decode_char(io);
            if ch == -1 {
                return false;
            }
            *c = ch as u8;
        }
        self.add_vm_code(first_byte, &code)
    }

    fn add_vm_code(&mut self, first_byte: u32, code: &[u8]) -> bool {
        self.vm_code_inp.init_bit_input();
        let n = code.len().min(crate::getbits::MAX_SIZE);
        self.vm_code_inp.in_buf[..n].copy_from_slice(&code[..n]);
        for b in &mut self.vm_code_inp.in_buf[n..] {
            *b = 0;
        }
        self.vm.init();
        let mut filt_pos;
        if first_byte & 0x80 != 0 {
            filt_pos = RarVM::read_data(&mut self.vm_code_inp);
            if filt_pos == 0 {
                self.init_filters30(false);
            } else {
                filt_pos -= 1;
            }
        } else {
            filt_pos = self.last_filter;
        }
        let fp = filt_pos as usize;
        if fp > self.filters30.len() || fp > self.old_filter_lengths.len() {
            return false;
        }
        self.last_filter = filt_pos;
        let new_filter = fp == self.filters30.len();
        let mut stack_filter = Box::new(UnpackFilter30::default());
        if new_filter {
            if fp > MAX3_UNPACK_FILTERS {
                return false;
            }
            stack_filter.parent_filter = self.filters30.len() as u32;
            self.filters30.push(UnpackFilter30::default());
            self.old_filter_lengths.push(0);
        } else {
            stack_filter.parent_filter = filt_pos;
        }
        // Move non-empty entries to the beginning, keeping empty slots in the end.
        let len = self.prg_stack.len();
        let mut compact: Vec<Option<Box<UnpackFilter30>>> = self.prg_stack.drain(..).filter(|x| x.is_some()).collect();
        let mut empty_count = len - compact.len();
        if empty_count == 0 {
            if len > MAX3_UNPACK_FILTERS {
                self.prg_stack = compact;
                return false;
            }
            empty_count = 1;
        }
        let stack_pos = compact.len();
        compact.resize_with(stack_pos + empty_count, || None);
        self.prg_stack = compact;
        let mut block_start = RarVM::read_data(&mut self.vm_code_inp);
        if first_byte & 0x40 != 0 {
            block_start = block_start.wrapping_add(258);
        }
        stack_filter.block_start = (block_start as usize).wrapping_add(self.unp_ptr) as u32 & self.max_win_mask as u32;
        if first_byte & 0x20 != 0 {
            stack_filter.block_length = RarVM::read_data(&mut self.vm_code_inp);
            self.old_filter_lengths[fp] = stack_filter.block_length;
        } else {
            stack_filter.block_length = self.old_filter_lengths.get(fp).copied().unwrap_or(0);
        }
        stack_filter.next_window =
            self.wr_ptr != self.unp_ptr && (self.wr_ptr.wrapping_sub(self.unp_ptr) & self.max_win_mask) <= block_start as usize;
        stack_filter.prg.init_r = [0; 7];
        stack_filter.prg.init_r[4] = stack_filter.block_length;
        if first_byte & 0x10 != 0 {
            let init_mask = self.vm_code_inp.fgetbits() >> 9;
            self.vm_code_inp.faddbits(7);
            for i in 0..7 {
                if init_mask & (1 << i) != 0 {
                    stack_filter.prg.init_r[i] = RarVM::read_data(&mut self.vm_code_inp);
                }
            }
        }
        if new_filter {
            let vm_code_size = RarVM::read_data(&mut self.vm_code_inp);
            if vm_code_size >= 0x10000 || vm_code_size == 0 || self.vm_code_inp.in_addr + vm_code_size as usize > code.len() {
                self.prg_stack[stack_pos] = Some(stack_filter);
                return false;
            }
            let mut vm_code = vec![0u8; vm_code_size as usize];
            for c in vm_code.iter_mut() {
                if self.vm_code_inp.overflow(3) {
                    self.prg_stack[stack_pos] = Some(stack_filter);
                    return false;
                }
                *c = (self.vm_code_inp.fgetbits() >> 8) as u8;
                self.vm_code_inp.faddbits(8);
            }
            let mut prg = std::mem::take(&mut self.filters30[fp].prg);
            self.vm.prepare(&vm_code, &mut prg);
            self.filters30[fp].prg = prg;
        }
        stack_filter.prg.filter_type = self.filters30[fp].prg.filter_type;
        self.prg_stack[stack_pos] = Some(stack_filter);
        true
    }

    fn unp_read_buf30(&mut self, io: &mut dyn UnpackIo) -> bool {
        let mut data_size = self.read_top - self.inp.in_addr as i64;
        if data_size < 0 {
            return false;
        }
        if self.inp.in_addr > crate::getbits::MAX_SIZE / 2 {
            if data_size > 0 {
                let a = self.inp.in_addr;
                self.inp.in_buf.copy_within(a..a + data_size as usize, 0);
            }
            self.inp.in_addr = 0;
            self.read_top = data_size;
        } else {
            data_size = self.read_top;
        }
        let ds = data_size as usize;
        let read_code = io.unp_read(&mut self.inp.in_buf[ds..crate::getbits::MAX_SIZE]);
        if read_code > 0 {
            self.read_top += read_code as i64;
        }
        self.read_border = self.read_top - 30;
        read_code != -1
    }

    fn unp_write_buf30(&mut self, io: &mut dyn UnpackIo) {
        let mask = self.max_win_mask;
        let mut written_border = self.wr_ptr;
        let mut write_size = self.unp_ptr.wrapping_sub(written_border) & mask;
        let mut i = 0;
        while i < self.prg_stack.len() {
            let flt = match &self.prg_stack[i] {
                None => {
                    i += 1;
                    continue;
                }
                Some(f) => f,
            };
            if flt.next_window {
                self.prg_stack[i].as_mut().unwrap().next_window = false;
                i += 1;
                continue;
            }
            let block_start = flt.block_start as usize;
            let block_length = flt.block_length as usize;
            if (block_start.wrapping_sub(written_border) & mask) < write_size {
                if written_border != block_start {
                    self.unp_write_area(written_border, block_start, io);
                    written_border = block_start;
                    write_size = self.unp_ptr.wrapping_sub(written_border) & mask;
                }
                if block_length <= write_size {
                    let block_end = (block_start + block_length) & mask;
                    if block_start < block_end || block_end == 0 {
                        let n = block_length.min(self.window.len() - block_start);
                        self.vm.set_memory(0, &self.window[block_start..block_start + n]);
                    } else {
                        let first = self.max_win_size - block_start;
                        self.vm.set_memory(0, &self.window[block_start..self.max_win_size]);
                        self.vm.set_memory(first, &self.window[..block_end]);
                    }
                    let mut flt = self.prg_stack[i].take().unwrap();
                    self.execute_code(&mut flt.prg);
                    let mut filtered = flt.prg.filtered_data;
                    let mut filtered_size = flt.prg.filtered_data_size;
                    while i + 1 < self.prg_stack.len() {
                        let next = match &self.prg_stack[i + 1] {
                            None => break,
                            Some(n) => n,
                        };
                        if next.block_start as usize != block_start || next.block_length != filtered_size || next.next_window {
                            break;
                        }
                        if let Some(off) = filtered {
                            self.vm.set_memory_from_self(0, off, filtered_size as usize);
                        }
                        let mut nf = self.prg_stack[i + 1].take().unwrap();
                        self.execute_code(&mut nf.prg);
                        filtered = nf.prg.filtered_data;
                        filtered_size = nf.prg.filtered_data_size;
                        i += 1;
                    }
                    if let Some(off) = filtered {
                        let end = (off + filtered_size as usize).min(VM_MEMSIZE + 4);
                        io.unp_write(&self.vm.mem[off..end]);
                    }
                    self.unp_some_read = true;
                    self.written_file_size += filtered_size as i64;
                    written_border = block_end;
                    write_size = self.unp_ptr.wrapping_sub(written_border) & mask;
                } else {
                    for j in i..self.prg_stack.len() {
                        if let Some(f) = self.prg_stack[j].as_mut() {
                            f.next_window = false;
                        }
                    }
                    self.wr_ptr = written_border;
                    return;
                }
            }
            i += 1;
        }
        let up = self.unp_ptr;
        self.unp_write_area(written_border, up, io);
        self.wr_ptr = self.unp_ptr;
    }

    fn execute_code(&mut self, prg: &mut super::rarvm::VmPreparedProgram) {
        prg.init_r[6] = self.written_file_size as u32;
        self.vm.execute(prg);
    }

    fn read_tables30(&mut self, io: &mut dyn UnpackIo) -> bool {
        let mut bit_length = [0u8; BC];
        let mut table = [0u8; HUFF_TABLE_SIZE30];
        if self.inp.in_addr as i64 > self.read_top - 25 && !self.unp_read_buf30(io) {
            return false;
        }
        self.inp.faddbits((8 - self.inp.in_bit) & 7);
        let bit_field = self.inp.fgetbits();
        if bit_field & 0x8000 != 0 {
            self.unp_block_ppm = true;
            let mut esc = self.ppm_esc_char;
            let mut ppm = self.ppm.take().unwrap();
            let r = ppm.decode_init(&mut esc, &mut || self.get_char(io));
            self.ppm = Some(ppm);
            self.ppm_esc_char = esc;
            return r;
        }
        self.unp_block_ppm = false;
        self.prev_low_dist = 0;
        self.low_dist_rep_count = 0;
        if bit_field & 0x4000 == 0 {
            self.unp_old_table = [0; HUFF_TABLE_SIZE30];
        }
        self.inp.faddbits(2);
        let mut i = 0;
        while i < BC {
            let length = (self.inp.fgetbits() >> 12) as u8;
            self.inp.faddbits(4);
            if length == 15 {
                let mut zero_count = self.inp.fgetbits() >> 12;
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
        Self::make_decode_tables(&bit_length, &mut self.block_tables.bd, BC30);
        let mut i = 0;
        while i < HUFF_TABLE_SIZE30 {
            if self.inp.in_addr as i64 > self.read_top - 5 && !self.unp_read_buf30(io) {
                return false;
            }
            let number = Self::decode_number(&mut self.inp, &self.block_tables.bd);
            if number < 16 {
                table[i] = ((number as u8).wrapping_add(self.unp_old_table[i])) & 0xf;
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
                while n > 0 && i < HUFF_TABLE_SIZE30 {
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
                while n > 0 && i < HUFF_TABLE_SIZE30 {
                    table[i] = 0;
                    i += 1;
                    n -= 1;
                }
            }
        }
        self.tables_read3 = true;
        if self.inp.in_addr as i64 > self.read_top {
            return false;
        }
        let bt = &mut *self.block_tables;
        Self::make_decode_tables(&table[0..], &mut bt.ld, NC30);
        Self::make_decode_tables(&table[NC30..], &mut bt.dd, DC30);
        Self::make_decode_tables(&table[NC30 + DC30..], &mut bt.ldd, LDC30);
        Self::make_decode_tables(&table[NC30 + DC30 + LDC30..], &mut bt.rd, RC30);
        self.unp_old_table = table;
        true
    }

    pub(super) fn unp_init_data30(&mut self, solid: bool) {
        if !solid {
            self.tables_read3 = false;
            self.unp_old_table = [0; HUFF_TABLE_SIZE30];
            self.ppm_esc_char = 2;
            self.unp_block_ppm = false;
        }
        self.init_filters30(solid);
    }

    pub(super) fn init_filters30(&mut self, solid: bool) {
        if !solid {
            self.old_filter_lengths.clear();
            self.last_filter = 0;
            self.filters30.clear();
        }
        self.prg_stack.clear();
    }
}
