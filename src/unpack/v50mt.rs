// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Multithreaded RAR 5.0 decompression. Blocks are decoded to an
//! intermediate representation in parallel and then applied to the
//! dictionary sequentially.

use super::*;

const UNP_READ_SIZE_MT: usize = 0x400000;
const UNP_BLOCKS_PER_THREAD: usize = 2;
const TOO_SMALL_TO_PROCESS: i64 = 1024;
const LARGE_BLOCK_SIZE: i64 = 0x20000;

const UNPDT_LITERAL: u8 = 0;
const UNPDT_MATCH: u8 = 1;
const UNPDT_FULLREP: u8 = 2;
const UNPDT_REP: u8 = 3;
const UNPDT_FILTER: u8 = 4;

#[derive(Clone, Copy, Default)]
struct DecodedItem {
    kind: u8,
    length: u16,
    distance: usize,
    literal: [u8; 8],
}

#[derive(Default)]
pub(super) struct ThreadData {
    inp: BitInput,
    /// Position of inp.in_buf[0] in the shared read buffer.
    base: i64,
    header_read: bool,
    block_header: UnpackBlockHeader,
    table_read: bool,
    block_tables: Box<UnpackBlockTables>,
    data_size: i64,
    damaged_data: bool,
    large_block: bool,
    no_data_left: bool,
    incomplete: bool,
    decoded: Vec<DecodedItem>,
}

/// Read block header from external buffer (no refilling).
fn read_block_header_ext(inp: &mut BitInput, header: &mut UnpackBlockHeader) -> bool {
    header.header_size = 0;
    inp.faddbits((8 - inp.in_bit) & 7);
    let block_flags = (inp.fgetbits() >> 8) as u8;
    inp.faddbits(8);
    let byte_count = ((block_flags >> 3) & 3) as u32 + 1;
    if byte_count == 4 {
        return false;
    }
    header.header_size = 2 + byte_count;
    header.block_bit_size = (block_flags & 7) as u32 + 1;
    let saved = (inp.fgetbits() >> 8) as u8;
    inp.faddbits(8);
    let mut block_size: u32 = 0;
    for i in 0..byte_count {
        block_size = block_size.wrapping_add((inp.fgetbits() >> 8) << (i * 8));
        inp.addbits(8);
    }
    header.block_size = block_size as i32 as i64;
    let checksum = (0x5a ^ block_flags as u32 ^ block_size ^ (block_size >> 8) ^ (block_size >> 16)) as u8;
    if checksum != saved {
        return false;
    }
    header.block_start = inp.in_addr as i64;
    header.last_block_in_file = block_flags & 0x40 != 0;
    header.table_present = block_flags & 0x80 != 0;
    true
}

/// Read Huffman tables from external buffer.
fn read_tables_ext(inp: &mut BitInput, header: &UnpackBlockHeader, tables: &mut UnpackBlockTables, extra_dist: bool) -> bool {
    if !header.table_present {
        return true;
    }
    let mut bit_length = [0u8; BC];
    let mut i = 0;
    while i < BC {
        let length = (inp.fgetbits() >> 12) as u8;
        inp.faddbits(4);
        if length == 15 {
            let mut zero_count = inp.fgetbits() >> 12;
            inp.faddbits(4);
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
    Unpack::make_decode_tables(&bit_length, &mut tables.bd, BC);
    let mut table = [0u8; HUFF_TABLE_SIZEX];
    let table_size = if extra_dist { HUFF_TABLE_SIZEX } else { HUFF_TABLE_SIZEB };
    let mut i = 0;
    while i < table_size {
        let number = Unpack::decode_number(inp, &tables.bd);
        if number < 16 {
            table[i] = number as u8;
            i += 1;
        } else if number < 18 {
            let mut n;
            if number == 16 {
                n = (inp.fgetbits() >> 13) + 3;
                inp.faddbits(3);
            } else {
                n = (inp.fgetbits() >> 9) + 11;
                inp.faddbits(7);
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
                n = (inp.fgetbits() >> 13) + 3;
                inp.faddbits(3);
            } else {
                n = (inp.fgetbits() >> 9) + 11;
                inp.faddbits(7);
            }
            while n > 0 && i < table_size {
                table[i] = 0;
                i += 1;
                n -= 1;
            }
        }
    }
    let dcodes = if extra_dist { DCX } else { DCB };
    Unpack::make_decode_tables(&table[0..], &mut tables.ld, NC);
    Unpack::make_decode_tables(&table[NC..], &mut tables.dd, dcodes);
    Unpack::make_decode_tables(&table[NC + dcodes..], &mut tables.ldd, LDC);
    Unpack::make_decode_tables(&table[NC + dcodes + LDC..], &mut tables.rd, RC);
    true
}

fn read_filter_ext(inp: &mut BitInput) -> UnpackFilter {
    let read_data = |inp: &mut BitInput| -> u32 {
        let byte_count = (inp.fgetbits() >> 14) + 1;
        inp.addbits(2);
        let mut data: u32 = 0;
        for i in 0..byte_count {
            data = data.wrapping_add((inp.fgetbits() >> 8) << (i * 8));
            inp.addbits(8);
        }
        data
    };
    let mut f = UnpackFilter { block_start: read_data(inp) as usize, block_length: read_data(inp), ..Default::default() };
    if f.block_length > MAX_FILTER_BLOCK_SIZE {
        f.block_length = 0;
    }
    f.filter_type = (inp.fgetbits() >> 13) as u8;
    inp.faddbits(3);
    if f.filter_type == FILTER_DELTA {
        f.channels = ((inp.fgetbits() >> 11) + 1) as u8;
        inp.faddbits(5);
    }
    f
}

fn read_distance(inp: &mut BitInput, tables: &UnpackBlockTables, large: bool) -> usize {
    let mut distance: usize = 1;
    let dist_slot = Unpack::decode_number(inp, &tables.dd);
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
                    distance = distance.wrapping_add(((inp.getbits64() as usize) >> (68 - dbits)) << 4);
                } else {
                    distance = distance.wrapping_add(((inp.getbits32() as usize) >> (36 - dbits)) << 4);
                }
                inp.addbits(dbits - 4);
            }
            let low = Unpack::decode_number(inp, &tables.ldd);
            distance = distance.wrapping_add(low as usize);
        } else {
            if large {
                distance += (inp.getbits32() >> (32 - dbits)) as usize;
            } else {
                distance += (inp.getbits() >> (16 - dbits)) as usize;
            }
            inp.addbits(dbits);
        }
    }
    distance
}

fn unpack_decode(d: &mut ThreadData, extra_dist: bool) {
    if !d.table_read {
        d.table_read = true;
        if !read_tables_ext(&mut d.inp, &d.block_header, &mut d.block_tables, extra_dist) {
            d.damaged_data = true;
            return;
        }
    }
    if d.inp.in_addr as i64 > d.block_header.header_size as i64 + d.block_header.block_size {
        d.damaged_data = true;
        return;
    }
    d.decoded.clear();
    let block_border = d.block_header.block_start + d.block_header.block_size - 1;
    let data_border = d.data_size - 16;
    let read_border = block_border.min(data_border);
    loop {
        let a = d.inp.in_addr as i64;
        if a >= read_border {
            if a > block_border || a == block_border && d.inp.in_bit >= d.block_header.block_bit_size {
                break;
            }
            if a >= data_border && !d.no_data_left || a >= d.data_size {
                d.incomplete = true;
                break;
            }
        }
        let main_slot = Unpack::decode_number(&mut d.inp, &d.block_tables.ld);
        if main_slot < 256 {
            if let Some(prev) = d.decoded.last_mut() {
                if prev.kind == UNPDT_LITERAL && prev.length < 7 {
                    prev.length += 1;
                    prev.literal[prev.length as usize] = main_slot as u8;
                    continue;
                }
            }
            let mut it = DecodedItem { kind: UNPDT_LITERAL, ..Default::default() };
            it.literal[0] = main_slot as u8;
            d.decoded.push(it);
            continue;
        }
        if main_slot >= 262 {
            let mut length = Unpack::slot_to_length(&mut d.inp, main_slot - 262);
            let distance = read_distance(&mut d.inp, &d.block_tables, false);
            if distance > 0x100 {
                length += 1;
                if distance > 0x2000 {
                    length += 1;
                    if distance > 0x40000 {
                        length += 1;
                    }
                }
            }
            d.decoded.push(DecodedItem { kind: UNPDT_MATCH, length: length as u16, distance, ..Default::default() });
            continue;
        }
        if main_slot == 256 {
            let f = read_filter_ext(&mut d.inp);
            d.decoded.push(DecodedItem { kind: UNPDT_FILTER, length: f.filter_type as u16, distance: f.block_start, ..Default::default() });
            d.decoded.push(DecodedItem { kind: UNPDT_FILTER, length: f.channels as u16, distance: f.block_length as usize, ..Default::default() });
            continue;
        }
        if main_slot == 257 {
            d.decoded.push(DecodedItem { kind: UNPDT_FULLREP, ..Default::default() });
            continue;
        }
        if main_slot < 262 {
            let length_slot = Unpack::decode_number(&mut d.inp, &d.block_tables.rd);
            let length = Unpack::slot_to_length(&mut d.inp, length_slot);
            d.decoded.push(DecodedItem { kind: UNPDT_REP, length: length as u16, distance: (main_slot - 258) as usize, ..Default::default() });
            continue;
        }
    }
}

impl Unpack {
    pub fn set_threads(&mut self, threads: u32) {
        self.max_user_threads = threads.clamp(1, 8);
    }

    /// Copy data for thread data starting at `base` from the read buffer.
    fn mt_load(d: &mut ThreadData, buf: &[u8], base: i64, data_size: i64, limit: Option<i64>) {
        let start = base as usize;
        let mut end = data_size as usize;
        if let Some(l) = limit {
            end = end.min(start + l.max(0) as usize);
        }
        let n = end.saturating_sub(start);
        d.inp.in_buf.clear();
        d.inp.in_buf.extend_from_slice(&buf[start..start + n]);
        d.inp.in_buf.resize(n + 64, 0);
        d.base = base;
    }

    pub(super) fn unpack5_mt(&mut self, solid: bool, io: &mut dyn UnpackIo) {
        let threads = self.max_user_threads as usize;
        let max_items = threads * UNP_BLOCKS_PER_THREAD;
        let mut read_buf = std::mem::take(&mut self.read_buf_mt);
        if read_buf.len() != UNP_READ_SIZE_MT + 1024 {
            read_buf = vec![0u8; UNP_READ_SIZE_MT + 1024];
        }
        let mut td = std::mem::take(&mut self.unp_thread_data);
        if td.len() != max_items {
            td = (0..max_items).map(|_| ThreadData::default()).collect();
        }
        self.unp_init_data(solid);
        for d in td.iter_mut() {
            d.large_block = false;
            d.incomplete = false;
        }
        td[0].block_header = self.block_header;
        *td[0].block_tables = (*self.block_tables).clone();
        let mut last_block_num = 0;
        let mut data_size: i64 = 0;
        let mut block_start: i64 = 0;
        let mut large_block = false;
        let mut done = false;
        let extra_dist = self.extra_dist;
        while !done {
            let to_read = ((UNP_READ_SIZE_MT as i64 - data_size) & !0xf) as usize;
            let ds = data_size as usize;
            let read_size = io.unp_read(&mut read_buf[ds..ds + to_read]) as i64;
            if read_size < 0 {
                break;
            }
            data_size += read_size;
            if data_size == 0 {
                break;
            }
            if read_size > 0 && data_size < TOO_SMALL_TO_PROCESS {
                continue;
            }
            while block_start < data_size && !done {
                let mut block_number = 0usize;
                let mut block_number_mt = 0usize;
                while block_number < max_items {
                    let d = &mut td[block_number];
                    last_block_num = block_number;
                    if d.incomplete {
                        let rest = d.block_header.block_start + d.block_header.block_size + 64;
                        Self::mt_load(d, &read_buf, 0, data_size, Some(rest));
                        d.data_size = data_size;
                    } else {
                        if data_size - block_start == 0 {
                            break;
                        }
                        // Read header from a small window first to know the block size.
                        Self::mt_load(d, &read_buf, block_start, data_size, Some(16));
                        d.inp.init_bit_input();
                        d.data_size = data_size - block_start;
                        d.damaged_data = false;
                        d.header_read = false;
                        d.table_read = false;
                    }
                    d.no_data_left = read_size == 0;
                    d.incomplete = false;
                    if !d.header_read {
                        d.header_read = true;
                        if !read_block_header_ext(&mut d.inp, &mut d.block_header) || !d.block_header.table_present && !self.tables_read5 {
                            done = true;
                            break;
                        }
                        self.tables_read5 = true;
                        self.read_border = self.read_border.min(d.block_header.block_start + d.block_header.block_size - 1);
                        let limit = d.block_header.header_size as i64 + d.block_header.block_size + 64;
                        let (a, b) = (d.inp.in_addr, d.inp.in_bit);
                        Self::mt_load(d, &read_buf, block_start, data_size, Some(limit));
                        d.inp.in_addr = a;
                        d.inp.in_bit = b;
                    }
                    if large_block || d.block_header.block_size > LARGE_BLOCK_SIZE {
                        large_block = true;
                        d.large_block = true;
                    } else {
                        block_number_mt += 1;
                    }
                    block_start += d.block_header.header_size as i64 + d.block_header.block_size;
                    block_number += 1;
                    let data_left = data_size - block_start;
                    if data_left >= 0 && d.block_header.last_block_in_file {
                        break;
                    }
                    if data_left < TOO_SMALL_TO_PROCESS {
                        break;
                    }
                }
                // Decode normal blocks in parallel.
                if block_number_mt > 0 {
                    let mut per_thread = block_number_mt / threads;
                    if !block_number_mt.is_multiple_of(threads) {
                        per_thread += 1;
                    }
                    let work = &mut td[..block_number_mt];
                    if block_number == 1 || threads == 1 {
                        for d in work.iter_mut() {
                            unpack_decode(d, extra_dist);
                        }
                    } else {
                        std::thread::scope(|s| {
                            for chunk in work.chunks_mut(per_thread) {
                                s.spawn(move || {
                                    crate::winsys::set_worker_thread_priority();
                                    for d in chunk.iter_mut() {
                                        unpack_decode(d, extra_dist);
                                    }
                                });
                            }
                        });
                    }
                }
                if block_number == 0 {
                    break;
                }
                let mut incomplete_thread = false;
                for block in 0..block_number {
                    let ok = if !td[block].large_block {
                        self.process_decoded(&td[block], io)
                    } else {
                        self.unpack_large_block(&mut td[block], io)
                    };
                    if !ok || td[block].damaged_data {
                        done = true;
                        break;
                    }
                    if td[block].incomplete {
                        let buf_pos = td[block].base + td[block].inp.in_addr as i64;
                        if data_size <= buf_pos {
                            done = true;
                            break;
                        }
                        incomplete_thread = true;
                        read_buf.copy_within(buf_pos as usize..data_size as usize, 0);
                        let d = &mut td[block];
                        d.block_header.block_size -= d.inp.in_addr as i64 - d.block_header.block_start;
                        d.block_header.header_size = 0;
                        d.block_header.block_start = 0;
                        d.inp.in_addr = 0;
                        d.base = 0;
                        if block != 0 {
                            td.swap(0, block);
                            td[block].incomplete = false;
                        }
                        block_start = 0;
                        data_size -= buf_pos;
                        break;
                    } else if td[block].block_header.last_block_in_file {
                        done = true;
                        break;
                    }
                }
                if incomplete_thread || done {
                    break;
                }
                let data_left = data_size - block_start;
                if data_left < TOO_SMALL_TO_PROCESS {
                    if data_left < 0 {
                        done = true;
                        break;
                    }
                    if data_left > 0 {
                        read_buf.copy_within(block_start as usize..data_size as usize, 0);
                    }
                    data_size = data_left;
                    block_start = 0;
                    break;
                }
            }
        }
        self.unp_ptr = self.wrap_up(self.unp_ptr);
        self.unp_write_buf(io);
        self.block_header = td[last_block_num].block_header;
        *self.block_tables = (*td[last_block_num].block_tables).clone();
        self.read_buf_mt = read_buf;
        self.unp_thread_data = td;
    }

    fn process_decoded(&mut self, d: &ThreadData, io: &mut dyn UnpackIo) -> bool {
        let items = &d.decoded;
        let mut i = 0;
        while i < items.len() {
            self.unp_ptr = self.wrap_up(self.unp_ptr);
            self.first_win_done |= self.prev_ptr > self.unp_ptr;
            self.prev_ptr = self.unp_ptr;
            if self.wrap_down(self.write_border.wrapping_sub(self.unp_ptr)) <= MAX_INC_LZ_MATCH as usize && self.write_border != self.unp_ptr {
                self.unp_write_buf(io);
                if self.written_file_size > self.dest_unp_size {
                    return false;
                }
            }
            let it = items[i];
            match it.kind {
                UNPDT_LITERAL => {
                    for k in 0..=it.length as usize {
                        let p = self.wrap_up(self.unp_ptr);
                        self.window[p] = it.literal[k];
                        self.unp_ptr += 1;
                    }
                }
                UNPDT_MATCH => {
                    self.insert_old_dist(it.distance);
                    self.last_length = it.length as u32;
                    self.copy_string(it.length as u32, it.distance);
                }
                UNPDT_REP => {
                    let distance = self.old_dist[it.distance];
                    for k in (1..=it.distance).rev() {
                        self.old_dist[k] = self.old_dist[k - 1];
                    }
                    self.old_dist[0] = distance;
                    self.last_length = it.length as u32;
                    self.copy_string(it.length as u32, distance);
                }
                UNPDT_FULLREP => {
                    if self.last_length != 0 {
                        let (l, dd) = (self.last_length, self.old_dist[0]);
                        self.copy_string(l, dd);
                    }
                }
                UNPDT_FILTER => {
                    let mut f = UnpackFilter { filter_type: it.length as u8, block_start: it.distance, ..Default::default() };
                    i += 1;
                    if i < items.len() {
                        f.channels = items[i].length as u8;
                        f.block_length = items[i].distance as u32;
                    }
                    self.add_filter_mt(f, io);
                }
                _ => {}
            }
            i += 1;
        }
        true
    }

    fn unpack_large_block(&mut self, d: &mut ThreadData, io: &mut dyn UnpackIo) -> bool {
        if !d.table_read {
            d.table_read = true;
            if !read_tables_ext(&mut d.inp, &d.block_header, &mut d.block_tables, self.extra_dist) {
                d.damaged_data = true;
                return false;
            }
        }
        if d.inp.in_addr as i64 > d.block_header.header_size as i64 + d.block_header.block_size {
            d.damaged_data = true;
            return false;
        }
        let block_border = d.block_header.block_start + d.block_header.block_size - 1;
        let data_border = d.data_size - 16;
        let read_border = block_border.min(data_border);
        loop {
            self.unp_ptr = self.wrap_up(self.unp_ptr);
            self.first_win_done |= self.prev_ptr > self.unp_ptr;
            self.prev_ptr = self.unp_ptr;
            let a = d.inp.in_addr as i64;
            if a >= read_border {
                if a > block_border || a == block_border && d.inp.in_bit >= d.block_header.block_bit_size {
                    break;
                }
                if a >= data_border && !d.no_data_left || a >= d.data_size {
                    d.incomplete = true;
                    break;
                }
            }
            if self.wrap_down(self.write_border.wrapping_sub(self.unp_ptr)) <= MAX_INC_LZ_MATCH as usize && self.write_border != self.unp_ptr {
                self.unp_write_buf(io);
                if self.written_file_size > self.dest_unp_size {
                    return false;
                }
            }
            let main_slot = Self::decode_number(&mut d.inp, &d.block_tables.ld);
            if main_slot < 256 {
                self.window[self.unp_ptr] = main_slot as u8;
                self.unp_ptr += 1;
                continue;
            }
            if main_slot >= 262 {
                let mut length = Self::slot_to_length(&mut d.inp, main_slot - 262);
                let distance = read_distance(&mut d.inp, &d.block_tables, true);
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
                let f = read_filter_ext(&mut d.inp);
                self.add_filter_mt(f, io);
                continue;
            }
            if main_slot == 257 {
                if self.last_length != 0 {
                    let (l, dd) = (self.last_length, self.old_dist[0]);
                    self.copy_string(l, dd);
                }
                continue;
            }
            if main_slot < 262 {
                let dist_num = (main_slot - 258) as usize;
                let distance = self.old_dist[dist_num];
                for k in (1..=dist_num).rev() {
                    self.old_dist[k] = self.old_dist[k - 1];
                }
                self.old_dist[0] = distance;
                let ls = Self::decode_number(&mut d.inp, &d.block_tables.rd);
                let length = Self::slot_to_length(&mut d.inp, ls);
                self.last_length = length;
                self.copy_string(length, distance);
                continue;
            }
        }
        true
    }
}
