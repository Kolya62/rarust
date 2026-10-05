// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! RAR 2.x decompression.

use super::*;

const LDECODE: [u8; 28] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 14, 16, 20, 24, 28, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224];
const LBITS: [u8; 28] = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5];
const DDECODE: [u32; 48] = [
    0, 1, 2, 3, 4, 6, 8, 12, 16, 24, 32, 48, 64, 96, 128, 192, 256, 384, 512, 768, 1024, 1536, 2048, 3072, 4096, 6144,
    8192, 12288, 16384, 24576, 32768, 49152, 65536, 98304, 131072, 196608, 262144, 327680, 393216, 458752, 524288,
    589824, 655360, 720896, 786432, 851968, 917504, 983040,
];
const DBITS: [u8; 48] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13, 14, 14, 15, 15, 16,
    16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
];
const SDDECODE: [u8; 8] = [0, 4, 8, 16, 32, 64, 128, 192];
const SDBITS: [u8; 8] = [2, 2, 3, 4, 5, 6, 6, 6];

impl Unpack {
    pub(super) fn copy_string20(&mut self, length: u32, distance: u32) {
        self.last_dist = distance;
        self.old_dist[self.old_dist_ptr] = distance as usize;
        self.old_dist_ptr = (self.old_dist_ptr + 1) & 3;
        self.last_length = length;
        self.dest_unp_size -= length as i64;
        self.copy_string(length, distance as usize);
    }

    pub(super) fn unpack20(&mut self, solid: bool, io: &mut dyn UnpackIo) {
        if self.suspended {
            self.unp_ptr = self.wr_ptr;
        } else {
            self.unp_init_data(solid);
            if !self.unp_read_buf(io) {
                return;
            }
            if (!solid || !self.tables_read2) && !self.read_tables20(io) {
                return;
            }
            self.dest_unp_size -= 1;
        }
        while self.dest_unp_size >= 0 {
            self.unp_ptr &= self.max_win_mask;
            self.first_win_done |= self.prev_ptr > self.unp_ptr;
            self.prev_ptr = self.unp_ptr;
            if self.inp.in_addr as i64 > self.read_top - 30 && !self.unp_read_buf(io) {
                break;
            }
            if (self.wr_ptr.wrapping_sub(self.unp_ptr) & self.max_win_mask) < 270 && self.wr_ptr != self.unp_ptr {
                self.unp_write_buf20(io);
                if self.suspended {
                    return;
                }
            }
            if self.unp_audio_block {
                let ch = self.unp_cur_channel as usize;
                let audio_number = Self::decode_number(&mut self.inp, &self.md[ch]);
                if audio_number == 256 {
                    if !self.read_tables20(io) {
                        break;
                    }
                    continue;
                }
                let b = self.decode_audio(audio_number as i32);
                self.window[self.unp_ptr] = b;
                self.unp_ptr += 1;
                self.unp_cur_channel += 1;
                if self.unp_cur_channel == self.unp_channels {
                    self.unp_cur_channel = 0;
                }
                self.dest_unp_size -= 1;
                continue;
            }
            let number = Self::decode_number(&mut self.inp, &self.block_tables.ld);
            if number < 256 {
                self.window[self.unp_ptr] = number as u8;
                self.unp_ptr += 1;
                self.dest_unp_size -= 1;
                continue;
            }
            if number > 269 {
                let n = ((number - 270) as usize).min(LDECODE.len() - 1);
                let mut length = LDECODE[n] as u32 + 3;
                let bits = LBITS[n] as u32;
                if bits > 0 {
                    length += self.inp.getbits() >> (16 - bits);
                    self.inp.addbits(bits);
                }
                let dist_number = (Self::decode_number(&mut self.inp, &self.block_tables.dd) as usize).min(DDECODE.len() - 1);
                let mut distance = DDECODE[dist_number] + 1;
                let bits = DBITS[dist_number] as u32;
                if bits > 0 {
                    distance += self.inp.getbits() >> (16 - bits);
                    self.inp.addbits(bits);
                }
                if distance >= 0x2000 {
                    length += 1;
                    if distance >= 0x40000 {
                        length += 1;
                    }
                }
                self.copy_string20(length, distance);
                continue;
            }
            if number == 269 {
                if !self.read_tables20(io) {
                    break;
                }
                continue;
            }
            if number == 256 {
                let (l, d) = (self.last_length, self.last_dist);
                self.copy_string20(l, d);
                continue;
            }
            if number < 261 {
                let distance = self.old_dist[(self.old_dist_ptr.wrapping_sub((number - 256) as usize)) & 3] as u32;
                let length_number = (Self::decode_number(&mut self.inp, &self.block_tables.rd) as usize).min(LDECODE.len() - 1);
                let mut length = LDECODE[length_number] as u32 + 2;
                let bits = LBITS[length_number] as u32;
                if bits > 0 {
                    length += self.inp.getbits() >> (16 - bits);
                    self.inp.addbits(bits);
                }
                if distance >= 0x101 {
                    length += 1;
                    if distance >= 0x2000 {
                        length += 1;
                        if distance >= 0x40000 {
                            length += 1;
                        }
                    }
                }
                self.copy_string20(length, distance);
                continue;
            }
            if number < 270 {
                let n = (number - 261) as usize;
                let mut distance = SDDECODE[n] as u32 + 1;
                let bits = SDBITS[n] as u32;
                if bits > 0 {
                    distance += self.inp.getbits() >> (16 - bits);
                    self.inp.addbits(bits);
                }
                self.copy_string20(2, distance);
                continue;
            }
        }
        self.read_last_tables(io);
        self.unp_write_buf20(io);
    }

    pub(super) fn unp_write_buf20(&mut self, io: &mut dyn UnpackIo) {
        if self.unp_ptr != self.wr_ptr {
            self.unp_some_read = true;
        }
        if self.unp_ptr < self.wr_ptr {
            let n = self.wr_ptr.wrapping_neg() & self.max_win_mask;
            io.unp_write(&self.window[self.wr_ptr..self.wr_ptr + n]);
            io.unp_write(&self.window[..self.unp_ptr]);
        } else {
            io.unp_write(&self.window[self.wr_ptr..self.unp_ptr]);
        }
        self.wr_ptr = self.unp_ptr;
    }

    fn read_tables20(&mut self, io: &mut dyn UnpackIo) -> bool {
        let mut bit_length = [0u8; BC20];
        let mut table = [0u8; MC20 * 4];
        if self.inp.in_addr as i64 > self.read_top - 25 && !self.unp_read_buf(io) {
            return false;
        }
        let bit_field = self.inp.getbits();
        self.unp_audio_block = bit_field & 0x8000 != 0;
        if bit_field & 0x4000 == 0 {
            self.unp_old_table20 = [0; MC20 * 4];
        }
        self.inp.addbits(2);
        
        let table_size = if self.unp_audio_block {
            self.unp_channels = ((bit_field >> 12) & 3) + 1;
            if self.unp_cur_channel >= self.unp_channels {
                self.unp_cur_channel = 0;
            }
            self.inp.addbits(2);
            MC20 * self.unp_channels as usize
        } else {
            NC20 + DC20 + RC20
        };
        for b in bit_length.iter_mut() {
            *b = (self.inp.getbits() >> 12) as u8;
            self.inp.addbits(4);
        }
        Self::make_decode_tables(&bit_length, &mut self.block_tables.bd, BC20);
        let mut i = 0;
        while i < table_size {
            if self.inp.in_addr as i64 > self.read_top - 5 && !self.unp_read_buf(io) {
                return false;
            }
            let number = Self::decode_number(&mut self.inp, &self.block_tables.bd);
            if number < 16 {
                table[i] = ((number as u8).wrapping_add(self.unp_old_table20[i])) & 0xf;
                i += 1;
            } else if number == 16 {
                let mut n = (self.inp.getbits() >> 14) + 3;
                self.inp.addbits(2);
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
                if number == 17 {
                    n = (self.inp.getbits() >> 13) + 3;
                    self.inp.addbits(3);
                } else {
                    n = (self.inp.getbits() >> 9) + 11;
                    self.inp.addbits(7);
                }
                while n > 0 && i < table_size {
                    table[i] = 0;
                    i += 1;
                    n -= 1;
                }
            }
        }
        self.tables_read2 = true;
        if self.inp.in_addr as i64 > self.read_top {
            return true;
        }
        if self.unp_audio_block {
            for i in 0..self.unp_channels as usize {
                Self::make_decode_tables(&table[i * MC20..], &mut self.md[i], MC20);
            }
        } else {
            let bt = &mut *self.block_tables;
            Self::make_decode_tables(&table[0..], &mut bt.ld, NC20);
            Self::make_decode_tables(&table[NC20..], &mut bt.dd, DC20);
            Self::make_decode_tables(&table[NC20 + DC20..], &mut bt.rd, RC20);
        }
        self.unp_old_table20[..table_size].copy_from_slice(&table[..table_size]);
        true
    }

    fn read_last_tables(&mut self, io: &mut dyn UnpackIo) {
        if self.read_top >= self.inp.in_addr as i64 + 5 {
            if self.unp_audio_block {
                let ch = self.unp_cur_channel as usize;
                if Self::decode_number(&mut self.inp, &self.md[ch]) == 256 {
                    self.read_tables20(io);
                }
            } else if Self::decode_number(&mut self.inp, &self.block_tables.ld) == 269 {
                self.read_tables20(io);
            }
        }
    }

    pub(super) fn unp_init_data20(&mut self, solid: bool) {
        if !solid {
            self.tables_read2 = false;
            self.unp_audio_block = false;
            self.unp_channel_delta = 0;
            self.unp_cur_channel = 0;
            self.unp_channels = 1;
            self.aud_v = [AudioVariables::default(); 4];
            self.unp_old_table20 = [0; MC20 * 4];
            for m in self.md.iter_mut() {
                *m = DecodeTable::default();
            }
        }
    }

    fn decode_audio(&mut self, delta: i32) -> u8 {
        let cd = self.unp_channel_delta;
        let v = &mut self.aud_v[self.unp_cur_channel as usize];
        v.byte_count = v.byte_count.wrapping_add(1);
        v.d4 = v.d3;
        v.d3 = v.d2;
        v.d2 = v.last_delta.wrapping_sub(v.d1);
        v.d1 = v.last_delta;
        let mut pch = 8i32
            .wrapping_mul(v.last_char)
            .wrapping_add(v.k1.wrapping_mul(v.d1))
            .wrapping_add(v.k2.wrapping_mul(v.d2))
            .wrapping_add(v.k3.wrapping_mul(v.d3))
            .wrapping_add(v.k4.wrapping_mul(v.d4))
            .wrapping_add(v.k5.wrapping_mul(cd));
        pch = (pch >> 3) & 0xff;
        let ch = (pch as u32).wrapping_sub(delta as u32);
        let d = ((delta as u8 as i8) as i32 as u32).wrapping_shl(3) as i32;
        v.dif[0] = v.dif[0].wrapping_add(d.unsigned_abs());
        v.dif[1] = v.dif[1].wrapping_add(d.wrapping_sub(v.d1).unsigned_abs());
        v.dif[2] = v.dif[2].wrapping_add(d.wrapping_add(v.d1).unsigned_abs());
        v.dif[3] = v.dif[3].wrapping_add(d.wrapping_sub(v.d2).unsigned_abs());
        v.dif[4] = v.dif[4].wrapping_add(d.wrapping_add(v.d2).unsigned_abs());
        v.dif[5] = v.dif[5].wrapping_add(d.wrapping_sub(v.d3).unsigned_abs());
        v.dif[6] = v.dif[6].wrapping_add(d.wrapping_add(v.d3).unsigned_abs());
        v.dif[7] = v.dif[7].wrapping_add(d.wrapping_sub(v.d4).unsigned_abs());
        v.dif[8] = v.dif[8].wrapping_add(d.wrapping_add(v.d4).unsigned_abs());
        v.dif[9] = v.dif[9].wrapping_add(d.wrapping_sub(cd).unsigned_abs());
        v.dif[10] = v.dif[10].wrapping_add(d.wrapping_add(cd).unsigned_abs());
        let new_delta = (ch.wrapping_sub(v.last_char as u32) as u8 as i8) as i32;
        v.last_delta = new_delta;
        v.last_char = ch as i32;
        if v.byte_count & 0x1f == 0 {
            let mut min_dif = v.dif[0];
            let mut num_min = 0;
            v.dif[0] = 0;
            for i in 1..11 {
                if v.dif[i] < min_dif {
                    min_dif = v.dif[i];
                    num_min = i;
                }
                v.dif[i] = 0;
            }
            match num_min {
                1 => {
                    if v.k1 >= -16 {
                        v.k1 -= 1
                    }
                }
                2 => {
                    if v.k1 < 16 {
                        v.k1 += 1
                    }
                }
                3 => {
                    if v.k2 >= -16 {
                        v.k2 -= 1
                    }
                }
                4 => {
                    if v.k2 < 16 {
                        v.k2 += 1
                    }
                }
                5 => {
                    if v.k3 >= -16 {
                        v.k3 -= 1
                    }
                }
                6 => {
                    if v.k3 < 16 {
                        v.k3 += 1
                    }
                }
                7 => {
                    if v.k4 >= -16 {
                        v.k4 -= 1
                    }
                }
                8 => {
                    if v.k4 < 16 {
                        v.k4 += 1
                    }
                }
                9 => {
                    if v.k5 >= -16 {
                        v.k5 -= 1
                    }
                }
                10
                    if v.k5 < 16 => {
                        v.k5 += 1
                    }
                _ => {}
            }
        }
        self.unp_channel_delta = new_delta;
        ch as u8
    }
}
