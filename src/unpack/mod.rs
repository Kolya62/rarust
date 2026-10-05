// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Decompression of RAR 1.5, 2.x, 3.x, 5.0 and 7.0 data.

mod ppmd;
mod rarvm;
mod v15;
mod v20;
mod v30;
mod v50;
mod v50mt;

use crate::getbits::{BitInput, MAX_SIZE};
use rarvm::{RarVM, VmPreparedProgram};

/// Source of packed data and destination of unpacked data.
pub trait UnpackIo {
    /// Read packed data. Returns number of bytes read, 0 at end or -1 on error.
    fn unp_read(&mut self, buf: &mut [u8]) -> i32;
    /// Write unpacked data.
    fn unp_write(&mut self, data: &[u8]);
}

pub const MAX_QUICK_DECODE_BITS: u32 = 9;
pub const MAX_UNPACK_FILTERS: usize = 8192;
pub const MAX3_UNPACK_FILTERS: usize = 8192;
pub const MAX3_UNPACK_CHANNELS: u32 = 1024;
pub const MAX_FILTER_BLOCK_SIZE: u32 = 0x400000;
pub const UNPACK_MAX_WRITE: usize = 0x400000;
const UNPACK_MAX_DICT: u64 = 0x1000000000;

pub const MAX_LZ_MATCH: u32 = 0x1001;
pub const MAX_INC_LZ_MATCH: u32 = MAX_LZ_MATCH + 3;
pub const MAX3_LZ_MATCH: u32 = 0x101;
pub const MAX3_INC_LZ_MATCH: u32 = MAX3_LZ_MATCH + 3;
pub const LOW_DIST_REP_COUNT: u32 = 16;
pub const NC: usize = 306;
pub const DCB: usize = 64;
pub const DCX: usize = 80;
pub const LDC: usize = 16;
pub const RC: usize = 44;
pub const HUFF_TABLE_SIZEB: usize = NC + DCB + RC + LDC;
pub const HUFF_TABLE_SIZEX: usize = NC + DCX + RC + LDC;
pub const BC: usize = 20;
pub const NC30: usize = 299;
pub const DC30: usize = 60;
pub const LDC30: usize = 17;
pub const RC30: usize = 28;
pub const BC30: usize = 20;
pub const HUFF_TABLE_SIZE30: usize = NC30 + DC30 + RC30 + LDC30;
pub const NC20: usize = 298;
pub const DC20: usize = 48;
pub const RC20: usize = 28;
pub const BC20: usize = 19;
pub const MC20: usize = 257;
pub const LARGEST_TABLE_SIZE: usize = 306;

pub const FILTER_DELTA: u8 = 0;
pub const FILTER_E8: u8 = 1;
pub const FILTER_E8E9: u8 = 2;
pub const FILTER_ARM: u8 = 3;
pub const FILTER_NONE: u8 = 10;

#[derive(Clone)]
pub struct DecodeTable {
    pub max_num: u32,
    pub decode_len: [u32; 16],
    pub decode_pos: [u32; 16],
    pub quick_bits: u32,
    pub quick_len: [u8; 1 << MAX_QUICK_DECODE_BITS],
    pub quick_num: [u16; 1 << MAX_QUICK_DECODE_BITS],
    pub decode_num: [u16; LARGEST_TABLE_SIZE],
}

impl Default for DecodeTable {
    fn default() -> Self {
        DecodeTable {
            max_num: 0,
            decode_len: [0; 16],
            decode_pos: [0; 16],
            quick_bits: 0,
            quick_len: [0; 1 << MAX_QUICK_DECODE_BITS],
            quick_num: [0; 1 << MAX_QUICK_DECODE_BITS],
            decode_num: [0; LARGEST_TABLE_SIZE],
        }
    }
}

#[derive(Clone, Copy, Default, Debug)]
pub struct UnpackBlockHeader {
    pub block_size: i64,
    pub block_bit_size: u32,
    pub block_start: i64,
    pub header_size: u32,
    pub last_block_in_file: bool,
    pub table_present: bool,
}

#[derive(Clone, Default)]
pub struct UnpackBlockTables {
    pub ld: DecodeTable,
    pub dd: DecodeTable,
    pub ldd: DecodeTable,
    pub rd: DecodeTable,
    pub bd: DecodeTable,
}

#[derive(Clone, Copy, Default, Debug)]
pub struct UnpackFilter {
    pub filter_type: u8,
    pub channels: u8,
    pub next_window: bool,
    pub block_start: usize,
    pub block_length: u32,
}

#[derive(Clone, Default)]
pub struct UnpackFilter30 {
    pub block_start: u32,
    pub block_length: u32,
    pub next_window: bool,
    pub parent_filter: u32,
    pub prg: VmPreparedProgram,
}

#[derive(Clone, Copy, Default)]
pub struct AudioVariables {
    pub k1: i32,
    pub k2: i32,
    pub k3: i32,
    pub k4: i32,
    pub k5: i32,
    pub d1: i32,
    pub d2: i32,
    pub d3: i32,
    pub d4: i32,
    pub last_delta: i32,
    pub dif: [u32; 11],
    pub byte_count: u32,
    pub last_char: i32,
}

#[derive(Debug)]
pub struct AllocError;

pub struct Unpack {
    inp: BitInput,
    filter_src_memory: Vec<u8>,
    filter_dst_memory: Vec<u8>,
    filters: Vec<UnpackFilter>,
    old_dist: [usize; 4],
    old_dist_ptr: usize,
    last_length: u32,
    last_dist: u32,
    unp_ptr: usize,
    prev_ptr: usize,
    first_win_done: bool,
    wr_ptr: usize,
    read_top: i64,
    read_border: i64,
    block_header: UnpackBlockHeader,
    block_tables: Box<UnpackBlockTables>,
    write_border: usize,
    window: Vec<u8>,
    dest_unp_size: i64,
    suspended: bool,
    unp_some_read: bool,
    written_file_size: i64,
    file_extracted: bool,

    // Unpack v1.5.
    ch_set: [u16; 256],
    ch_set_a: [u16; 256],
    ch_set_b: [u16; 256],
    ch_set_c: [u16; 256],
    n_to_pl: [u8; 256],
    n_to_pl_b: [u8; 256],
    n_to_pl_c: [u8; 256],
    flag_buf: u32,
    avr_plc: u32,
    avr_plc_b: u32,
    avr_ln1: u32,
    avr_ln2: u32,
    avr_ln3: u32,
    buf60: u32,
    num_huf: i32,
    st_mode: i32,
    l_count: i32,
    flags_cnt: i32,
    nhfb: u32,
    nlzb: u32,
    max_dist3: u32,

    // Unpack v2.0.
    md: Box<[DecodeTable; 4]>,
    unp_old_table20: [u8; MC20 * 4],
    unp_audio_block: bool,
    unp_channels: u32,
    unp_cur_channel: u32,
    unp_channel_delta: i32,
    aud_v: [AudioVariables; 4],

    // Unpack v3.0.
    prev_low_dist: i32,
    low_dist_rep_count: i32,
    ppm: Option<Box<ppmd::ModelPPM>>,
    ppm_esc_char: i32,
    unp_old_table: [u8; HUFF_TABLE_SIZE30],
    unp_block_ppm: bool,
    tables_read2: bool,
    tables_read3: bool,
    tables_read5: bool,
    vm: RarVM,
    vm_code_inp: BitInput,
    filters30: Vec<UnpackFilter30>,
    prg_stack: Vec<Option<Box<UnpackFilter30>>>,
    old_filter_lengths: Vec<u32>,
    last_filter: u32,

    max_user_threads: u32,
    read_buf_mt: Vec<u8>,
    unp_thread_data: Vec<v50mt::ThreadData>,

    pub alloc_win_size: u64,
    pub max_win_size: usize,
    pub max_win_mask: usize,
    pub extra_dist: bool,
}

impl Default for Unpack {
    fn default() -> Self {
        Self::new()
    }
}

impl Unpack {
    pub fn new() -> Self {
        let mut u = Unpack {
            inp: BitInput::new(),
            filter_src_memory: Vec::new(),
            filter_dst_memory: Vec::new(),
            filters: Vec::new(),
            old_dist: [0; 4],
            old_dist_ptr: 0,
            last_length: 0,
            last_dist: 0,
            unp_ptr: 0,
            prev_ptr: 0,
            first_win_done: false,
            wr_ptr: 0,
            read_top: 0,
            read_border: 0,
            block_header: UnpackBlockHeader::default(),
            block_tables: Box::default(),
            write_border: 0,
            window: Vec::new(),
            dest_unp_size: 0,
            suspended: false,
            unp_some_read: false,
            written_file_size: 0,
            file_extracted: false,
            ch_set: [0; 256],
            ch_set_a: [0; 256],
            ch_set_b: [0; 256],
            ch_set_c: [0; 256],
            n_to_pl: [0; 256],
            n_to_pl_b: [0; 256],
            n_to_pl_c: [0; 256],
            flag_buf: 0,
            avr_plc: 0,
            avr_plc_b: 0,
            avr_ln1: 0,
            avr_ln2: 0,
            avr_ln3: 0,
            buf60: 0,
            num_huf: 0,
            st_mode: 0,
            l_count: 0,
            flags_cnt: 0,
            nhfb: 0,
            nlzb: 0,
            max_dist3: 0,
            md: Box::default(),
            unp_old_table20: [0; MC20 * 4],
            unp_audio_block: false,
            unp_channels: 1,
            unp_cur_channel: 0,
            unp_channel_delta: 0,
            aud_v: [AudioVariables::default(); 4],
            prev_low_dist: 0,
            low_dist_rep_count: 0,
            ppm: Some(Box::default()),
            ppm_esc_char: 0,
            unp_old_table: [0; HUFF_TABLE_SIZE30],
            unp_block_ppm: false,
            tables_read2: false,
            tables_read3: false,
            tables_read5: false,
            vm: RarVM::new(),
            vm_code_inp: BitInput::new(),
            filters30: Vec::new(),
            prg_stack: Vec::new(),
            old_filter_lengths: Vec::new(),
            last_filter: 0,
            max_user_threads: 1,
            read_buf_mt: Vec::new(),
            unp_thread_data: Vec::new(),
            alloc_win_size: 0,
            max_win_size: 0,
            max_win_mask: 0,
            extra_dist: false,
        };
        u.unp_init_data(false);
        u.unp_init_data15(false);
        u.init_huff();
        u
    }

    /// Prepare the dictionary. Returns error if memory cannot be allocated.
    pub fn init(&mut self, win_size: u64, solid: bool) -> Result<(), AllocError> {
        const MIN_ALLOC_SIZE: u64 = 0x40000;
        let win_size = win_size.max(MIN_ALLOC_SIZE);
        if win_size > 0x10000000000u64.min(UNPACK_MAX_DICT) {
            return Err(AllocError);
        }
        if win_size > usize::MAX as u64 / 2 {
            return Err(AllocError);
        }
        if !solid || self.window.is_empty() {
            self.max_win_size = win_size as usize;
            self.max_win_mask = self.max_win_size - 1;
        }
        if win_size <= self.alloc_win_size {
            return Ok(());
        }
        if solid && !self.window.is_empty() {
            return Err(AllocError);
        }
        self.window = Vec::new();
        let mut w: Vec<u8> = Vec::new();
        if w.try_reserve_exact(win_size as usize).is_err() {
            return Err(AllocError);
        }
        w.resize(win_size as usize, 0);
        self.window = w;
        self.alloc_win_size = win_size;
        Ok(())
    }

    pub fn set_dest_size(&mut self, size: i64) {
        self.dest_unp_size = size;
        self.file_extracted = false;
    }

    pub fn is_file_extracted(&self) -> bool {
        self.file_extracted
    }

    pub fn set_suspended(&mut self, s: bool) {
        self.suspended = s;
    }

    pub fn do_unpack(&mut self, method: u32, solid: bool, io: &mut dyn UnpackIo) {
        if self.window.is_empty() {
            return;
        }
        match method {
            15 => self.unpack15(solid, io),
            20 | 26 => self.unpack20(solid, io),
            29 => self.unpack29(solid, io),
            50 | 70 => {
                self.extra_dist = method == 70;
                if self.max_user_threads > 1 {
                    self.unpack5_mt(solid, io);
                } else {
                    self.unpack5(solid, io);
                }
            }
            _ => {}
        }
    }

    #[inline(always)]
    fn wrap_down(&self, p: usize) -> usize {
        if p >= self.max_win_size {
            p.wrapping_add(self.max_win_size)
        } else {
            p
        }
    }

    #[inline(always)]
    fn wrap_up(&self, p: usize) -> usize {
        if p >= self.max_win_size {
            p.wrapping_sub(self.max_win_size)
        } else {
            p
        }
    }

    fn unp_init_data(&mut self, solid: bool) {
        if !solid {
            self.old_dist = [usize::MAX; 4];
            self.old_dist_ptr = 0;
            self.last_dist = u32::MAX;
            self.last_length = 0;
            *self.block_tables = UnpackBlockTables::default();
            self.unp_ptr = 0;
            self.wr_ptr = 0;
            self.prev_ptr = 0;
            self.first_win_done = false;
            self.write_border = self.max_win_size.min(UNPACK_MAX_WRITE);
        }
        self.filters.clear();
        self.inp.init_bit_input();
        self.written_file_size = 0;
        self.read_top = 0;
        self.read_border = 0;
        self.block_header = UnpackBlockHeader { block_size: -1, ..Default::default() };
        self.unp_init_data20(solid);
        self.unp_init_data30(solid);
        if !solid {
            self.tables_read5 = false;
        }
    }

    /// Build Huffman decoding tables from bit lengths.
    pub fn make_decode_tables(length_table: &[u8], dec: &mut DecodeTable, size: usize) {
        dec.max_num = size as u32;
        let mut length_count = [0u32; 16];
        for &l in &length_table[..size] {
            length_count[(l & 0xf) as usize] += 1;
        }
        length_count[0] = 0;
        for x in &mut dec.decode_num[..size] {
            *x = 0;
        }
        dec.decode_pos[0] = 0;
        dec.decode_len[0] = 0;
        let mut upper_limit: u32 = 0;
        for i in 1..16 {
            upper_limit = upper_limit.wrapping_add(length_count[i]);
            let left_aligned = upper_limit.wrapping_shl(16 - i as u32);
            upper_limit = upper_limit.wrapping_mul(2);
            dec.decode_len[i] = left_aligned;
            dec.decode_pos[i] = dec.decode_pos[i - 1] + length_count[i - 1];
        }
        let mut copy_pos = dec.decode_pos;
        for (i, &l) in length_table[..size].iter().enumerate() {
            let cur = (l & 0xf) as usize;
            if cur != 0 {
                let last = copy_pos[cur] as usize;
                if last < LARGEST_TABLE_SIZE {
                    dec.decode_num[last] = i as u16;
                }
                copy_pos[cur] += 1;
            }
        }
        dec.quick_bits = match size {
            NC | NC20 | NC30 => MAX_QUICK_DECODE_BITS,
            _ => MAX_QUICK_DECODE_BITS - 3,
        };
        let quick_size = 1usize << dec.quick_bits;
        let mut cur_bit_length: usize = 1;
        for code in 0..quick_size {
            let bit_field = (code as u32) << (16 - dec.quick_bits);
            while cur_bit_length < 16 && bit_field >= dec.decode_len[cur_bit_length] {
                cur_bit_length += 1;
            }
            dec.quick_len[code] = cur_bit_length as u8;
            let mut dist = bit_field.wrapping_sub(dec.decode_len[cur_bit_length - 1]);
            dist >>= 16 - cur_bit_length as u32;
            let pos;
            if cur_bit_length < 16 && {
                pos = dec.decode_pos[cur_bit_length].wrapping_add(dist);
                (pos as usize) < size
            } {
                dec.quick_num[code] = dec.decode_num[pos as usize];
            } else {
                dec.quick_num[code] = 0;
            }
        }
    }

    #[inline(always)]
    pub fn decode_number(inp: &mut BitInput, dec: &DecodeTable) -> u32 {
        let bit_field = inp.getbits() & 0xfffe;
        if bit_field < dec.decode_len[dec.quick_bits as usize] {
            let code = (bit_field >> (16 - dec.quick_bits)) as usize;
            inp.addbits(dec.quick_len[code] as u32);
            return dec.quick_num[code] as u32;
        }
        let mut bits = 15;
        for i in dec.quick_bits + 1..15 {
            if bit_field < dec.decode_len[i as usize] {
                bits = i;
                break;
            }
        }
        inp.addbits(bits);
        let mut dist = bit_field.wrapping_sub(dec.decode_len[bits as usize - 1]);
        dist >>= 16 - bits;
        let mut pos = dec.decode_pos[bits as usize].wrapping_add(dist);
        if pos >= dec.max_num {
            pos = 0;
        }
        dec.decode_num[pos as usize] as u32
    }

    #[inline(always)]
    fn insert_old_dist(&mut self, d: usize) {
        self.old_dist[3] = self.old_dist[2];
        self.old_dist[2] = self.old_dist[1];
        self.old_dist[1] = self.old_dist[0];
        self.old_dist[0] = d;
    }

    #[inline(always)]
    fn copy_string(&mut self, length: u32, distance: usize) {
        let mut length = length as usize;
        let max = self.max_win_size;
        let mut src = self.unp_ptr.wrapping_sub(distance);
        if distance > self.unp_ptr {
            src = src.wrapping_add(max);
            if distance > max || !self.first_win_done {
                while length > 0 {
                    self.window[self.unp_ptr] = 0;
                    self.unp_ptr = self.wrap_up(self.unp_ptr + 1);
                    length -= 1;
                }
                return;
            }
        }
        let lim = max - MAX_INC_LZ_MATCH as usize;
        if src < lim && self.unp_ptr < lim {
            let dest = self.unp_ptr;
            self.unp_ptr += length;
            if distance >= length {
                self.window.copy_within(src..src + length, dest);
            } else {
                let w = &mut self.window;
                for i in 0..length {
                    w[dest + i] = w[src + i];
                }
            }
        } else {
            while length > 0 {
                let s = self.wrap_up(src);
                self.window[self.unp_ptr] = self.window[s];
                src = src.wrapping_add(1);
                self.unp_ptr = self.wrap_up(self.unp_ptr + 1);
                length -= 1;
            }
        }
    }

    #[inline(always)]
    fn slot_to_length(inp: &mut BitInput, slot: u32) -> u32 {
        let (lbits, mut length);
        if slot < 8 {
            lbits = 0;
            length = 2 + slot;
        } else {
            lbits = slot / 4 - 1;
            length = 2 + ((4 | (slot & 3)) << lbits);
        }
        if lbits > 0 {
            length += inp.getbits() >> (16 - lbits);
            inp.addbits(lbits);
        }
        length
    }

    /// Get a byte from input buffer, used by PPM decoder.
    fn get_char(&mut self, io: &mut dyn UnpackIo) -> u8 {
        if self.inp.in_addr > MAX_SIZE - 30 {
            self.unp_read_buf(io);
            if self.inp.in_addr >= MAX_SIZE {
                return 0;
            }
        }
        let c = self.inp.in_buf[self.inp.in_addr];
        self.inp.in_addr += 1;
        c
    }

    /// Fill the input buffer (RAR 5.0 version, also used for RAR 1.5-2.x).
    fn unp_read_buf(&mut self, io: &mut dyn UnpackIo) -> bool {
        let mut data_size = self.read_top - self.inp.in_addr as i64;
        if data_size < 0 {
            return false;
        }
        self.block_header.block_size -= self.inp.in_addr as i64 - self.block_header.block_start;
        if self.inp.in_addr > MAX_SIZE / 2 {
            if data_size > 0 {
                let a = self.inp.in_addr;
                self.inp.in_buf.copy_within(a..a + data_size as usize, 0);
            }
            self.inp.in_addr = 0;
            self.read_top = data_size;
        } else {
            data_size = self.read_top;
        }
        let mut read_code = 0;
        if MAX_SIZE as i64 != data_size {
            let ds = data_size as usize;
            read_code = io.unp_read(&mut self.inp.in_buf[ds..MAX_SIZE]);
        }
        if read_code > 0 {
            self.read_top += read_code as i64;
        }
        self.read_border = self.read_top - 30;
        self.block_header.block_start = self.inp.in_addr as i64;
        if self.block_header.block_size != -1 {
            self.read_border = self.read_border.min(self.block_header.block_start + self.block_header.block_size - 1);
        }
        read_code != -1
    }

    fn unp_write_area(&mut self, start: usize, end: usize, io: &mut dyn UnpackIo) {
        if end != start {
            self.unp_some_read = true;
        }
        if end < start {
            let w = std::mem::take(&mut self.window);
            self.unp_write_data(&w[start..self.max_win_size], io);
            self.unp_write_data(&w[..end], io);
            self.window = w;
        } else {
            let w = std::mem::take(&mut self.window);
            self.unp_write_data(&w[start..end], io);
            self.window = w;
        }
    }

    fn unp_write_data(&mut self, data: &[u8], io: &mut dyn UnpackIo) {
        if self.written_file_size >= self.dest_unp_size {
            return;
        }
        let left = self.dest_unp_size - self.written_file_size;
        let n = if data.len() as i64 > left { left as usize } else { data.len() };
        io.unp_write(&data[..n]);
        self.written_file_size += data.len() as i64;
    }
}
