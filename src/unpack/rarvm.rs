// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! RAR 3.x virtual machine. Only standard filters are supported.

use crate::getbits::BitInput;
use crate::hash::crc32::crc32;

pub const VM_MEMSIZE: usize = 0x40000;
pub const VM_MEMMASK: u32 = (VM_MEMSIZE - 1) as u32;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum VmStandardFilter {
    #[default]
    None,
    E8,
    E8E9,
    Itanium,
    Rgb,
    Audio,
    Delta,
}

#[derive(Clone, Default, Debug)]
pub struct VmPreparedProgram {
    pub filter_type: VmStandardFilter,
    pub init_r: [u32; 7],
    /// Offset of filtered data in VM memory, None if no data.
    pub filtered_data: Option<usize>,
    pub filtered_data_size: u32,
}

pub struct RarVM {
    pub mem: Vec<u8>,
    r: [u32; 8],
}

impl RarVM {
    pub fn new() -> Self {
        RarVM { mem: Vec::new(), r: [0; 8] }
    }

    pub fn init(&mut self) {
        if self.mem.is_empty() {
            self.mem = vec![0; VM_MEMSIZE + 4];
        }
    }

    pub fn execute(&mut self, prg: &mut VmPreparedProgram) {
        self.r[..7].copy_from_slice(&prg.init_r);
        prg.filtered_data = None;
        if prg.filter_type != VmStandardFilter::None {
            let success = self.execute_standard_filter(prg.filter_type);
            let block_size = prg.init_r[4] & VM_MEMMASK;
            prg.filtered_data_size = block_size;
            if matches!(prg.filter_type, VmStandardFilter::Delta | VmStandardFilter::Rgb | VmStandardFilter::Audio) {
                prg.filtered_data = Some(if 2 * block_size as usize > VM_MEMSIZE || !success { 0 } else { block_size as usize });
            } else {
                prg.filtered_data = Some(0);
            }
        }
    }

    pub fn prepare(&mut self, code: &[u8], prg: &mut VmPreparedProgram) {
        let mut xor_sum: u8 = 0;
        for &b in &code[1..] {
            xor_sum ^= b;
        }
        if xor_sum != code[0] {
            return;
        }
        const STD: [(usize, u32, VmStandardFilter); 6] = [
            (53, 0xad576887, VmStandardFilter::E8),
            (57, 0x3cd7e57e, VmStandardFilter::E8E9),
            (120, 0x3769893f, VmStandardFilter::Itanium),
            (29, 0x0e06077d, VmStandardFilter::Delta),
            (149, 0x1c2c5dc8, VmStandardFilter::Rgb),
            (216, 0xbc85e701, VmStandardFilter::Audio),
        ];
        let crc = crc32(0xffffffff, code) ^ 0xffffffff;
        for (len, c, t) in STD {
            if c == crc && len == code.len() {
                prg.filter_type = t;
                break;
            }
        }
    }

    pub fn read_data(inp: &mut BitInput) -> u32 {
        let mut data = inp.fgetbits();
        match data & 0xc000 {
            0 => {
                inp.faddbits(6);
                (data >> 10) & 0xf
            }
            0x4000 => {
                if data & 0x3c00 == 0 {
                    data = 0xffffff00 | ((data >> 2) & 0xff);
                    inp.faddbits(14);
                } else {
                    data = (data >> 6) & 0xff;
                    inp.faddbits(10);
                }
                data
            }
            0x8000 => {
                inp.faddbits(2);
                let d = inp.fgetbits();
                inp.faddbits(16);
                d
            }
            _ => {
                inp.faddbits(2);
                let mut d = inp.fgetbits() << 16;
                inp.faddbits(16);
                d |= inp.fgetbits();
                inp.faddbits(16);
                d
            }
        }
    }

    pub fn set_memory(&mut self, pos: usize, data: &[u8]) {
        if pos < VM_MEMSIZE {
            let n = data.len().min(VM_MEMSIZE - pos);
            self.mem[pos..pos + n].copy_from_slice(&data[..n]);
        }
    }

    /// Copy data inside VM memory (used when chaining filters).
    pub fn set_memory_from_self(&mut self, pos: usize, src: usize, size: usize) {
        if pos < VM_MEMSIZE && src != pos {
            let n = size.min(VM_MEMSIZE - pos).min(self.mem.len() - src);
            self.mem.copy_within(src..src + n, pos);
        }
    }

    fn execute_standard_filter(&mut self, t: VmStandardFilter) -> bool {
        let mem = &mut self.mem;
        match t {
            VmStandardFilter::E8 | VmStandardFilter::E8E9 => {
                let data_size = self.r[4];
                let file_offset = self.r[6];
                if data_size as usize > VM_MEMSIZE || data_size < 4 {
                    return false;
                }
                const FILE_SIZE: u32 = 0x1000000;
                let cmp2 = if t == VmStandardFilter::E8E9 { 0xe9 } else { 0xe8 };
                let mut cur: u32 = 0;
                while cur < data_size - 4 {
                    let b = mem[cur as usize];
                    cur += 1;
                    if b == 0xe8 || b == cmp2 {
                        let offset = cur.wrapping_add(file_offset);
                        let p = cur as usize;
                        let addr = u32::from_le_bytes(mem[p..p + 4].try_into().unwrap());
                        if addr & 0x80000000 != 0 {
                            if addr.wrapping_add(offset) & 0x80000000 == 0 {
                                mem[p..p + 4].copy_from_slice(&addr.wrapping_add(FILE_SIZE).to_le_bytes());
                            }
                        } else if addr.wrapping_sub(FILE_SIZE) & 0x80000000 != 0 {
                            mem[p..p + 4].copy_from_slice(&addr.wrapping_sub(offset).to_le_bytes());
                        }
                        cur += 4;
                    }
                }
            }
            VmStandardFilter::Itanium => {
                let data_size = self.r[4];
                let mut file_offset = self.r[6];
                if data_size as usize > VM_MEMSIZE || data_size < 21 {
                    return false;
                }
                let mut cur: u32 = 0;
                file_offset >>= 4;
                const MASKS: [u8; 16] = [4, 4, 6, 6, 0, 0, 7, 7, 4, 4, 0, 0, 4, 4, 0, 0];
                while cur < data_size - 21 {
                    let d = cur as usize;
                    let byte = (mem[d] & 0x1f) as i32 - 0x10;
                    if byte >= 0 {
                        let cmd_mask = MASKS[byte as usize];
                        if cmd_mask != 0 {
                            for i in 0..=2u32 {
                                if cmd_mask & (1 << i) != 0 {
                                    let start = i * 41 + 5;
                                    let op_type = itanium_get_bits(&mem[d..], start + 37, 4);
                                    if op_type == 5 {
                                        let offset = itanium_get_bits(&mem[d..], start + 13, 20);
                                        itanium_set_bits(&mut mem[d..], offset.wrapping_sub(file_offset) & 0xfffff, start + 13, 20);
                                    }
                                }
                            }
                        }
                    }
                    cur += 16;
                    file_offset = file_offset.wrapping_add(1);
                }
            }
            VmStandardFilter::Delta => {
                let data_size = self.r[4] as usize;
                let channels = self.r[0];
                let border = data_size * 2;
                if data_size > VM_MEMSIZE / 2 || channels > super::MAX3_UNPACK_CHANNELS || channels == 0 {
                    return false;
                }
                let mut src = 0;
                for ch in 0..channels as usize {
                    let mut prev: u8 = 0;
                    let mut d = data_size + ch;
                    while d < border {
                        prev = prev.wrapping_sub(mem[src]);
                        mem[d] = prev;
                        src += 1;
                        d += channels as usize;
                    }
                }
            }
            VmStandardFilter::Rgb => {
                let data_size = self.r[4] as usize;
                let width = self.r[0].wrapping_sub(3) as usize;
                let pos_r = self.r[1] as usize;
                if data_size > VM_MEMSIZE / 2 || data_size < 3 || width > data_size || pos_r > 2 {
                    return false;
                }
                let dest = data_size;
                let mut src = 0;
                for ch in 0..3usize {
                    let mut prev: u32 = 0;
                    let mut i = ch;
                    while i < data_size {
                        
                        let predicted = if i >= width + 3 {
                            let upper = dest + i - width;
                            let upper_byte = mem[upper] as u32;
                            let upper_left = mem[upper - 3] as u32;
                            let p = prev.wrapping_add(upper_byte).wrapping_sub(upper_left);
                            let pa = (p.wrapping_sub(prev) as i32).unsigned_abs();
                            let pb = (p.wrapping_sub(upper_byte) as i32).unsigned_abs();
                            let pc = (p.wrapping_sub(upper_left) as i32).unsigned_abs();
                            if pa <= pb && pa <= pc {
                                prev
                            } else if pb <= pc {
                                upper_byte
                            } else {
                                upper_left
                            }
                        } else {
                            prev
                        };
                        let v = predicted.wrapping_sub(mem[src] as u32) as u8;
                        src += 1;
                        mem[dest + i] = v;
                        prev = v as u32;
                        i += 3;
                    }
                }
                let mut i = pos_r;
                let border = data_size - 2;
                while i < border {
                    let g = mem[dest + i + 1];
                    mem[dest + i] = mem[dest + i].wrapping_add(g);
                    mem[dest + i + 2] = mem[dest + i + 2].wrapping_add(g);
                    i += 3;
                }
            }
            VmStandardFilter::Audio => {
                let data_size = self.r[4] as usize;
                let channels = self.r[0] as usize;
                if data_size > VM_MEMSIZE / 2 || channels > 128 || channels == 0 {
                    return false;
                }
                let dest = data_size;
                let mut src = 0;
                for ch in 0..channels {
                    let mut prev_byte: u32 = 0;
                    let mut prev_delta: u32 = 0;
                    let mut dif = [0u32; 7];
                    let (mut d1, mut d2, mut d3): (i32, i32, i32);
                    d1 = 0;
                    d2 = 0;
                    let (mut k1, mut k2, mut k3) = (0i32, 0i32, 0i32);
                    let mut i = ch;
                    let mut byte_count: u32 = 0;
                    while i < data_size {
                        d3 = d2;
                        d2 = (prev_delta as i32).wrapping_sub(d1);
                        d1 = prev_delta as i32;
                        let mut predicted = (8u32.wrapping_mul(prev_byte))
                            .wrapping_add(k1.wrapping_mul(d1) as u32)
                            .wrapping_add(k2.wrapping_mul(d2) as u32)
                            .wrapping_add(k3.wrapping_mul(d3) as u32);
                        predicted = (predicted >> 3) & 0xff;
                        let cur_byte = mem[src] as u32;
                        src += 1;
                        predicted = predicted.wrapping_sub(cur_byte);
                        mem[dest + i] = predicted as u8;
                        prev_delta = (predicted.wrapping_sub(prev_byte) as u8 as i8) as i32 as u32;
                        prev_byte = predicted;
                        let d = ((cur_byte as u8 as i8) as i32 as u32).wrapping_shl(3) as i32;
                        dif[0] = dif[0].wrapping_add(d.unsigned_abs());
                        dif[1] = dif[1].wrapping_add(d.wrapping_sub(d1).unsigned_abs());
                        dif[2] = dif[2].wrapping_add(d.wrapping_add(d1).unsigned_abs());
                        dif[3] = dif[3].wrapping_add(d.wrapping_sub(d2).unsigned_abs());
                        dif[4] = dif[4].wrapping_add(d.wrapping_add(d2).unsigned_abs());
                        dif[5] = dif[5].wrapping_add(d.wrapping_sub(d3).unsigned_abs());
                        dif[6] = dif[6].wrapping_add(d.wrapping_add(d3).unsigned_abs());
                        if byte_count & 0x1f == 0 {
                            let mut min_dif = dif[0];
                            let mut num_min = 0;
                            dif[0] = 0;
                            for j in 1..7 {
                                if dif[j] < min_dif {
                                    min_dif = dif[j];
                                    num_min = j;
                                }
                                dif[j] = 0;
                            }
                            match num_min {
                                1 => {
                                    if k1 >= -16 {
                                        k1 -= 1
                                    }
                                }
                                2 => {
                                    if k1 < 16 {
                                        k1 += 1
                                    }
                                }
                                3 => {
                                    if k2 >= -16 {
                                        k2 -= 1
                                    }
                                }
                                4 => {
                                    if k2 < 16 {
                                        k2 += 1
                                    }
                                }
                                5 => {
                                    if k3 >= -16 {
                                        k3 -= 1
                                    }
                                }
                                6
                                    if k3 < 16 => {
                                        k3 += 1
                                    }
                                _ => {}
                            }
                        }
                        i += channels;
                        byte_count += 1;
                    }
                }
            }
            VmStandardFilter::None => {}
        }
        true
    }
}

fn itanium_get_bits(data: &[u8], bit_pos: u32, bit_count: u32) -> u32 {
    let a = (bit_pos / 8) as usize;
    let b = bit_pos & 7;
    let mut bf = data[a] as u32 | (data[a + 1] as u32) << 8 | (data[a + 2] as u32) << 16 | (data[a + 3] as u32) << 24;
    bf >>= b;
    bf & (0xffffffffu32 >> (32 - bit_count))
}

fn itanium_set_bits(data: &mut [u8], bit_field: u32, bit_pos: u32, bit_count: u32) {
    let a = (bit_pos / 8) as usize;
    let b = bit_pos & 7;
    let mut and_mask = 0xffffffffu32 >> (32 - bit_count);
    and_mask = !(and_mask << b);
    let mut bf = bit_field << b;
    for i in 0..4 {
        data[a + i] &= and_mask as u8;
        data[a + i] |= bf as u8;
        and_mask = (and_mask >> 8) | 0xff000000;
        bf >>= 8;
    }
}
