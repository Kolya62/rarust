// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! RAR 1.5 decompression.

use super::*;

const STARTL1: u32 = 2;
const DEC_L1: [u32; 11] = [0x8000, 0xa000, 0xc000, 0xd000, 0xe000, 0xea00, 0xee00, 0xf000, 0xf200, 0xf200, 0xffff];
const POS_L1: [u32; 13] = [0, 0, 0, 2, 3, 5, 7, 11, 16, 20, 24, 32, 32];
const STARTL2: u32 = 3;
const DEC_L2: [u32; 10] = [0xa000, 0xc000, 0xd000, 0xe000, 0xea00, 0xee00, 0xf000, 0xf200, 0xf240, 0xffff];
const POS_L2: [u32; 13] = [0, 0, 0, 0, 5, 7, 9, 13, 18, 22, 26, 34, 36];
const STARTHF0: u32 = 4;
const DEC_HF0: [u32; 9] = [0x8000, 0xc000, 0xe000, 0xf200, 0xf200, 0xf200, 0xf200, 0xf200, 0xffff];
const POS_HF0: [u32; 13] = [0, 0, 0, 0, 0, 8, 16, 24, 33, 33, 33, 33, 33];
const STARTHF1: u32 = 5;
const DEC_HF1: [u32; 8] = [0x2000, 0xc000, 0xe000, 0xf000, 0xf200, 0xf200, 0xf7e0, 0xffff];
const POS_HF1: [u32; 13] = [0, 0, 0, 0, 0, 0, 4, 44, 60, 76, 80, 80, 127];
const STARTHF2: u32 = 5;
const DEC_HF2: [u32; 8] = [0x1000, 0x2400, 0x8000, 0xc000, 0xfa00, 0xffff, 0xffff, 0xffff];
const POS_HF2: [u32; 13] = [0, 0, 0, 0, 0, 0, 2, 7, 53, 117, 233, 0, 0];
const STARTHF3: u32 = 6;
const DEC_HF3: [u32; 7] = [0x800, 0x2400, 0xee00, 0xfe80, 0xffff, 0xffff, 0xffff];
const POS_HF3: [u32; 13] = [0, 0, 0, 0, 0, 0, 0, 2, 16, 218, 251, 0, 0];
const STARTHF4: u32 = 8;
const DEC_HF4: [u32; 6] = [0xff00, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff];
const POS_HF4: [u32; 13] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0];

const SHORT_LEN1: [u32; 16] = [1, 3, 4, 4, 5, 6, 7, 8, 8, 4, 4, 5, 6, 6, 4, 0];
const SHORT_XOR1: [u32; 16] = [0, 0xa0, 0xd0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe, 0xff, 0xc0, 0x80, 0x90, 0x98, 0x9c, 0xb0, 0];
const SHORT_LEN2: [u32; 16] = [2, 3, 3, 3, 4, 4, 5, 6, 6, 4, 4, 5, 6, 6, 4, 0];
const SHORT_XOR2: [u32; 16] = [0, 0x40, 0x60, 0xa0, 0xd0, 0xe0, 0xf0, 0xf8, 0xfc, 0xc0, 0x80, 0x90, 0x98, 0x9c, 0xb0, 0];

impl Unpack {
    pub(super) fn unpack15(&mut self, solid: bool, io: &mut dyn UnpackIo) {
        self.unp_init_data(solid);
        self.unp_init_data15(solid);
        self.unp_read_buf(io);
        if !solid {
            self.init_huff();
            self.unp_ptr = 0;
        } else {
            self.unp_ptr = self.wr_ptr;
        }
        self.dest_unp_size -= 1;
        if self.dest_unp_size >= 0 {
            self.get_flags_buf();
            self.flags_cnt = 8;
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
            }
            if self.st_mode != 0 {
                self.huff_decode();
                continue;
            }
            self.flags_cnt -= 1;
            if self.flags_cnt < 0 {
                self.get_flags_buf();
                self.flags_cnt = 7;
            }
            if self.flag_buf & 0x80 != 0 {
                self.flag_buf <<= 1;
                if self.nlzb > self.nhfb {
                    self.long_lz();
                } else {
                    self.huff_decode();
                }
            } else {
                self.flag_buf <<= 1;
                self.flags_cnt -= 1;
                if self.flags_cnt < 0 {
                    self.get_flags_buf();
                    self.flags_cnt = 7;
                }
                if self.flag_buf & 0x80 != 0 {
                    self.flag_buf <<= 1;
                    if self.nlzb > self.nhfb {
                        self.huff_decode();
                    } else {
                        self.long_lz();
                    }
                } else {
                    self.flag_buf <<= 1;
                    self.short_lz();
                }
            }
        }
        self.unp_write_buf20(io);
    }

    fn short_lz(&mut self) {
        self.num_huf = 0;
        let mut bit_field = self.inp.fgetbits();
        if self.l_count == 2 {
            self.inp.faddbits(1);
            if bit_field >= 0x8000 {
                let (d, l) = (self.last_dist, self.last_length);
                self.copy_string15(d, l);
                return;
            }
            bit_field <<= 1;
            self.l_count = 0;
        }
        bit_field >>= 8;
        let buf60 = self.buf60;
        let len1 = |p: usize| if p == 1 { buf60 + 3 } else { SHORT_LEN1[p] };
        let len2 = |p: usize| if p == 3 { buf60 + 3 } else { SHORT_LEN2[p] };
        let mut length: usize = 0;
        if self.avr_ln1 < 37 {
            loop {
                if ((bit_field ^ SHORT_XOR1[length]) & !(0xffu32.wrapping_shr(len1(length)))) & 0xff == 0 || length >= 15 {
                    break;
                }
                length += 1;
            }
            self.inp.faddbits(len1(length));
        } else {
            loop {
                if ((bit_field ^ SHORT_XOR2[length]) & !(0xffu32.wrapping_shr(len2(length)))) & 0xff == 0 || length >= 15 {
                    break;
                }
                length += 1;
            }
            self.inp.faddbits(len2(length));
        }
        let mut length = length as u32;
        if length >= 9 {
            if length == 9 {
                self.l_count += 1;
                let (d, l) = (self.last_dist, self.last_length);
                self.copy_string15(d, l);
                return;
            }
            if length == 14 {
                self.l_count = 0;
                length = self.decode_num(self.inp.fgetbits(), STARTL2, &DEC_L2, &POS_L2) + 5;
                let distance = (self.inp.fgetbits() >> 1) | 0x8000;
                self.inp.faddbits(15);
                self.last_length = length;
                self.last_dist = distance;
                self.copy_string15(distance, length);
                return;
            }
            self.l_count = 0;
            let save_length = length;
            let distance = self.old_dist[self.old_dist_ptr.wrapping_sub((length - 9) as usize) & 3] as u32;
            length = self.decode_num(self.inp.fgetbits(), STARTL1, &DEC_L1, &POS_L1) + 2;
            if length == 0x101 && save_length == 10 {
                self.buf60 ^= 1;
                return;
            }
            if distance > 256 {
                length += 1;
            }
            if distance >= self.max_dist3 {
                length += 1;
            }
            self.old_dist[self.old_dist_ptr] = distance as usize;
            self.old_dist_ptr = (self.old_dist_ptr + 1) & 3;
            self.last_length = length;
            self.last_dist = distance;
            self.copy_string15(distance, length);
            return;
        }
        self.l_count = 0;
        self.avr_ln1 += length;
        self.avr_ln1 -= self.avr_ln1 >> 4;
        let mut distance_place = (self.decode_num(self.inp.fgetbits(), STARTHF2, &DEC_HF2, &POS_HF2) & 0xff) as i32;
        let mut distance = self.ch_set_a[distance_place as usize] as u32;
        distance_place -= 1;
        if distance_place != -1 {
            let last_distance = self.ch_set_a[distance_place as usize];
            self.ch_set_a[distance_place as usize + 1] = last_distance;
            self.ch_set_a[distance_place as usize] = distance as u16;
        }
        length += 2;
        distance += 1;
        self.old_dist[self.old_dist_ptr] = distance as usize;
        self.old_dist_ptr = (self.old_dist_ptr + 1) & 3;
        self.last_length = length;
        self.last_dist = distance;
        self.copy_string15(distance, length);
    }

    fn long_lz(&mut self) {
        self.num_huf = 0;
        self.nlzb += 16;
        if self.nlzb > 0xff {
            self.nlzb = 0x90;
            self.nhfb >>= 1;
        }
        let old_avr2 = self.avr_ln2;
        let bit_field = self.inp.fgetbits();
        let mut length;
        if self.avr_ln2 >= 122 {
            length = self.decode_num(bit_field, STARTL2, &DEC_L2, &POS_L2);
        } else if self.avr_ln2 >= 64 {
            length = self.decode_num(bit_field, STARTL1, &DEC_L1, &POS_L1);
        } else if bit_field < 0x100 {
            length = bit_field;
            self.inp.faddbits(16);
        } else {
            length = 0;
            while ((bit_field << length) & 0x8000) == 0 {
                length += 1;
            }
            self.inp.faddbits(length + 1);
        }
        self.avr_ln2 += length;
        self.avr_ln2 -= self.avr_ln2 >> 5;
        let bit_field = self.inp.fgetbits();
        let distance_place = if self.avr_plc_b > 0x28ff {
            self.decode_num(bit_field, STARTHF2, &DEC_HF2, &POS_HF2)
        } else if self.avr_plc_b > 0x6ff {
            self.decode_num(bit_field, STARTHF1, &DEC_HF1, &POS_HF1)
        } else {
            self.decode_num(bit_field, STARTHF0, &DEC_HF0, &POS_HF0)
        };
        self.avr_plc_b += distance_place;
        self.avr_plc_b -= self.avr_plc_b >> 8;
        let mut distance;
        let mut new_distance_place;
        loop {
            distance = self.ch_set_b[(distance_place & 0xff) as usize] as u32;
            let idx = (distance & 0xff) as usize;
            new_distance_place = self.n_to_pl_b[idx] as u32;
            self.n_to_pl_b[idx] = self.n_to_pl_b[idx].wrapping_add(1);
            distance += 1;
            if distance & 0xff == 0 {
                Self::corr_huff(&mut self.ch_set_b, &mut self.n_to_pl_b);
            } else {
                break;
            }
        }
        self.ch_set_b[(distance_place & 0xff) as usize] = self.ch_set_b[new_distance_place as usize];
        self.ch_set_b[new_distance_place as usize] = distance as u16;
        distance = ((distance & 0xff00) | (self.inp.fgetbits() >> 8)) >> 1;
        self.inp.faddbits(7);
        let old_avr3 = self.avr_ln3;
        if length != 1 && length != 4 {
            if length == 0 && distance <= self.max_dist3 {
                self.avr_ln3 += 1;
                self.avr_ln3 -= self.avr_ln3 >> 8;
            } else if self.avr_ln3 > 0 {
                self.avr_ln3 -= 1;
            }
        }
        length += 3;
        if distance >= self.max_dist3 {
            length += 1;
        }
        if distance <= 256 {
            length += 8;
        }
        if old_avr3 > 0xb0 || self.avr_plc >= 0x2a00 && old_avr2 < 0x40 {
            self.max_dist3 = 0x7f00;
        } else {
            self.max_dist3 = 0x2001;
        }
        self.old_dist[self.old_dist_ptr] = distance as usize;
        self.old_dist_ptr = (self.old_dist_ptr + 1) & 3;
        self.last_length = length;
        self.last_dist = distance;
        self.copy_string15(distance, length);
    }

    fn huff_decode(&mut self) {
        let mut bit_field = self.inp.fgetbits();
        let mut byte_place: i32 = if self.avr_plc > 0x75ff {
            self.decode_num(bit_field, STARTHF4, &DEC_HF4, &POS_HF4)
        } else if self.avr_plc > 0x5dff {
            self.decode_num(bit_field, STARTHF3, &DEC_HF3, &POS_HF3)
        } else if self.avr_plc > 0x35ff {
            self.decode_num(bit_field, STARTHF2, &DEC_HF2, &POS_HF2)
        } else if self.avr_plc > 0x0dff {
            self.decode_num(bit_field, STARTHF1, &DEC_HF1, &POS_HF1)
        } else {
            self.decode_num(bit_field, STARTHF0, &DEC_HF0, &POS_HF0)
        } as i32;
        byte_place &= 0xff;
        if self.st_mode != 0 {
            if byte_place == 0 && bit_field > 0xfff {
                byte_place = 0x100;
            }
            byte_place -= 1;
            if byte_place == -1 {
                bit_field = self.inp.fgetbits();
                self.inp.faddbits(1);
                if bit_field & 0x8000 != 0 {
                    self.num_huf = 0;
                    self.st_mode = 0;
                    return;
                } else {
                    let length = if bit_field & 0x4000 != 0 { 4 } else { 3 };
                    self.inp.faddbits(1);
                    let mut distance = self.decode_num(self.inp.fgetbits(), STARTHF2, &DEC_HF2, &POS_HF2);
                    distance = (distance << 5) | (self.inp.fgetbits() >> 11);
                    self.inp.faddbits(5);
                    self.copy_string15(distance, length);
                    return;
                }
            }
        } else {
            let nh = self.num_huf;
            self.num_huf += 1;
            if nh >= 16 && self.flags_cnt == 0 {
                self.st_mode = 1;
            }
        }
        self.avr_plc += byte_place as u32;
        self.avr_plc -= self.avr_plc >> 8;
        self.nhfb += 16;
        if self.nhfb > 0xff {
            self.nhfb = 0x90;
            self.nlzb >>= 1;
        }
        let bp = byte_place as usize & 0xff;
        self.window[self.unp_ptr] = (self.ch_set[bp] >> 8) as u8;
        self.unp_ptr += 1;
        self.dest_unp_size -= 1;
        let mut cur_byte;
        let mut new_byte_place;
        loop {
            cur_byte = self.ch_set[bp] as u32;
            let idx = (cur_byte & 0xff) as usize;
            new_byte_place = self.n_to_pl[idx] as u32;
            self.n_to_pl[idx] = self.n_to_pl[idx].wrapping_add(1);
            cur_byte += 1;
            if (cur_byte & 0xff) > 0xa1 {
                Self::corr_huff(&mut self.ch_set, &mut self.n_to_pl);
            } else {
                break;
            }
        }
        self.ch_set[bp] = self.ch_set[new_byte_place as usize];
        self.ch_set[new_byte_place as usize] = cur_byte as u16;
    }

    fn get_flags_buf(&mut self) {
        let flags_place = self.decode_num(self.inp.fgetbits(), STARTHF2, &DEC_HF2, &POS_HF2);
        if flags_place as usize >= self.ch_set_c.len() {
            return;
        }
        let mut flags;
        let mut new_flags_place;
        loop {
            flags = self.ch_set_c[flags_place as usize] as u32;
            self.flag_buf = flags >> 8;
            let idx = (flags & 0xff) as usize;
            new_flags_place = self.n_to_pl_c[idx] as u32;
            self.n_to_pl_c[idx] = self.n_to_pl_c[idx].wrapping_add(1);
            flags += 1;
            if flags & 0xff != 0 {
                break;
            }
            Self::corr_huff(&mut self.ch_set_c, &mut self.n_to_pl_c);
        }
        self.ch_set_c[flags_place as usize] = self.ch_set_c[new_flags_place as usize];
        self.ch_set_c[new_flags_place as usize] = flags as u16;
    }

    pub(super) fn unp_init_data15(&mut self, solid: bool) {
        if !solid {
            self.avr_plc_b = 0;
            self.avr_ln1 = 0;
            self.avr_ln2 = 0;
            self.avr_ln3 = 0;
            self.num_huf = 0;
            self.buf60 = 0;
            self.avr_plc = 0x3500;
            self.max_dist3 = 0x2001;
            self.nhfb = 0x80;
            self.nlzb = 0x80;
        }
        self.flags_cnt = 0;
        self.flag_buf = 0;
        self.st_mode = 0;
        self.l_count = 0;
        self.read_top = 0;
    }

    pub(super) fn init_huff(&mut self) {
        for i in 0..256u32 {
            self.ch_set[i as usize] = (i << 8) as u16;
            self.ch_set_b[i as usize] = (i << 8) as u16;
            self.ch_set_a[i as usize] = i as u16;
            self.ch_set_c[i as usize] = ((((!i).wrapping_add(1)) & 0xff) << 8) as u16;
        }
        self.n_to_pl = [0; 256];
        self.n_to_pl_b = [0; 256];
        self.n_to_pl_c = [0; 256];
        Self::corr_huff(&mut self.ch_set_b, &mut self.n_to_pl_b);
    }

    fn corr_huff(char_set: &mut [u16; 256], num_to_place: &mut [u8; 256]) {
        let mut k = 0;
        for i in (0..=7u16).rev() {
            for _ in 0..32 {
                char_set[k] = (char_set[k] & !0xff) | i;
                k += 1;
            }
        }
        *num_to_place = [0; 256];
        for i in (0..=6usize).rev() {
            num_to_place[i] = ((7 - i) * 32) as u8;
        }
    }

    fn copy_string15(&mut self, distance: u32, length: u32) {
        self.dest_unp_size -= length as i64;
        let distance = distance as usize;
        let mask = self.max_win_mask;
        let mut length = length;
        if !self.first_win_done && distance > self.unp_ptr || distance > self.max_win_size || distance == 0 {
            while length > 0 {
                self.window[self.unp_ptr] = 0;
                self.unp_ptr = (self.unp_ptr + 1) & mask;
                length -= 1;
            }
        } else {
            while length > 0 {
                self.window[self.unp_ptr] = self.window[self.unp_ptr.wrapping_sub(distance) & mask];
                self.unp_ptr = (self.unp_ptr + 1) & mask;
                length -= 1;
            }
        }
    }

    fn decode_num(&mut self, num: u32, start_pos: u32, dec_tab: &[u32], pos_tab: &[u32; 13]) -> u32 {
        let num = num & 0xfff0;
        let mut i = 0;
        let mut sp = start_pos;
        while i < dec_tab.len() && dec_tab[i] <= num {
            sp += 1;
            i += 1;
        }
        self.inp.faddbits(sp);
        let base = if i > 0 { dec_tab[i - 1] } else { 0 };
        ((num.wrapping_sub(base)) >> (16 - sp)).wrapping_add(pos_tab[(sp as usize).min(12)])
    }
}
