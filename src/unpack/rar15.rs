// SPDX-License-Identifier: GPL-3.0-or-later

//! Decoder for RAR 1.5 compression (method 15).
//!
//! RAR 1.5 has no transmitted tables. Symbols are coded with a few fixed
//! prefix codes and mapped through adaptive "rank" tables: each table
//! lists byte values (or distance groups) by recent use, and a decoded
//! rank is moved towards the front as it is used. A flag byte, itself
//! rank coded, tells for every following item whether it is a literal or
//! one of two kinds of match; statistics of recent lengths and ranks
//! choose which fixed code is used next. After a run of literals the
//! decoder can switch to a literal-only mode.

use super::bitstream::StreamBits;
use super::huffman::BitSource;
use super::{Unpack, UnpackIo};

/// A fixed prefix code: `start` is the shortest code length, `limits` the
/// left aligned upper bounds of each length, `base` the first value of
/// each length.
struct Code {
    start: u32,
    limits: &'static [u32],
    base: [u32; 13],
}

const L1: Code = Code {
    start: 2,
    limits: &[0x8000, 0xa000, 0xc000, 0xd000, 0xe000, 0xea00, 0xee00, 0xf000, 0xf200, 0xf200, 0xffff],
    base: [0, 0, 0, 2, 3, 5, 7, 11, 16, 20, 24, 32, 32],
};
const L2: Code = Code {
    start: 3,
    limits: &[0xa000, 0xc000, 0xd000, 0xe000, 0xea00, 0xee00, 0xf000, 0xf200, 0xf240, 0xffff],
    base: [0, 0, 0, 0, 5, 7, 9, 13, 18, 22, 26, 34, 36],
};
const HF0: Code = Code {
    start: 4,
    limits: &[0x8000, 0xc000, 0xe000, 0xf200, 0xf200, 0xf200, 0xf200, 0xf200, 0xffff],
    base: [0, 0, 0, 0, 0, 8, 16, 24, 33, 33, 33, 33, 33],
};
const HF1: Code = Code {
    start: 5,
    limits: &[0x2000, 0xc000, 0xe000, 0xf000, 0xf200, 0xf200, 0xf7e0, 0xffff],
    base: [0, 0, 0, 0, 0, 0, 4, 44, 60, 76, 80, 80, 127],
};
const HF2: Code = Code {
    start: 5,
    limits: &[0x1000, 0x2400, 0x8000, 0xc000, 0xfa00, 0xffff, 0xffff, 0xffff],
    base: [0, 0, 0, 0, 0, 0, 2, 7, 53, 117, 233, 0, 0],
};
const HF3: Code = Code {
    start: 6,
    limits: &[0x800, 0x2400, 0xee00, 0xfe80, 0xffff, 0xffff, 0xffff],
    base: [0, 0, 0, 0, 0, 0, 0, 2, 16, 218, 251, 0, 0],
};
const HF4: Code = Code {
    start: 8,
    limits: &[0xff00, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff],
    base: [0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0],
};

/// Short match lengths: prefix length and pattern for each length value,
/// two variants depending on the recent average length. Entries 1 and 3
/// (in the respective table) have a variable prefix length.
const SHORT_LEN1: [u32; 16] = [1, 3, 4, 4, 5, 6, 7, 8, 8, 4, 4, 5, 6, 6, 4, 0];
const SHORT_XOR1: [u32; 16] = [0, 0xa0, 0xd0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe, 0xff, 0xc0, 0x80, 0x90, 0x98, 0x9c, 0xb0, 0];
const SHORT_LEN2: [u32; 16] = [2, 3, 3, 3, 4, 4, 5, 6, 6, 4, 4, 5, 6, 6, 4, 0];
const SHORT_XOR2: [u32; 16] = [0, 0x40, 0x60, 0xa0, 0xd0, 0xe0, 0xf0, 0xf8, 0xfc, 0xc0, 0x80, 0x90, 0x98, 0x9c, 0xb0, 0];

fn peek16(inp: &mut StreamBits) -> u32 {
    inp.peek32() >> 16
}

fn decode(inp: &mut StreamBits, code: &Code) -> u32 {
    let v = peek16(inp) & 0xfff0;
    let mut len = code.start;
    let mut i = 0;
    while code.limits[i] <= v {
        len += 1;
        i += 1;
    }
    inp.skip(len);
    let below = if i > 0 { code.limits[i - 1] } else { 0 };
    ((v - below) >> (16 - len)) + code.base[len as usize]
}

/// Rank table: high byte value, low byte a counter used for reordering.
struct Ranks {
    set: [u16; 256],
    /// Next free position for each counter value.
    place: [u8; 256],
}

impl Ranks {
    /// Spreads the counters: positions 0-31 get 7, 32-63 get 6, ... and
    /// the start positions for counters 0-6 are reset.
    fn reset_counts(&mut self) {
        for (i, v) in self.set.iter_mut().enumerate() {
            *v = (*v & !0xff) | (7 - (i / 32) as u16);
        }
        self.place = [0; 256];
        for i in 0..7 {
            self.place[i] = ((7 - i) * 32) as u8;
        }
    }

    /// Takes the entry at `pos`, increments its counter and swaps it with
    /// the entry at the next free position for the new counter. Counters
    /// that overflow `limit` (or wrap to zero when `limit` is None) cause a
    /// reset of all counters.
    fn use_at(&mut self, pos: usize, limit: Option<u16>) -> u16 {
        let (value, new_pos) = loop {
            let v = self.set[pos];
            let np = self.place[(v & 0xff) as usize] as usize;
            self.place[(v & 0xff) as usize] = self.place[(v & 0xff) as usize].wrapping_add(1);
            let v1 = v.wrapping_add(1);
            let overflow = match limit {
                Some(l) => (v1 & 0xff) > l,
                None => v1 & 0xff == 0,
            };
            if overflow {
                self.reset_counts();
            } else {
                break (v1, np);
            }
        };
        self.set[pos] = self.set[new_pos];
        self.set[new_pos] = value;
        value
    }
}

pub(super) struct Rar15 {
    literals: Ranks,
    distances: Ranks,
    flags: Ranks,
    /// Short match distance ranks.
    short: [u16; 256],
    flag_buf: u32,
    flags_left: i32,
    avr_plc: u32,
    avr_plc_b: u32,
    avr_ln1: u32,
    avr_ln2: u32,
    avr_ln3: u32,
    buf60: u32,
    num_huf: u32,
    literal_mode: bool,
    repeat_count: u32,
    nhfb: u32,
    nlzb: u32,
    max_dist3: u32,
    recent: [u32; 4],
    recent_pos: usize,
    last_dist: u32,
    last_len: u32,
}

impl Default for Rar15 {
    fn default() -> Self {
        let mut r = Rar15 {
            literals: Ranks { set: [0; 256], place: [0; 256] },
            distances: Ranks { set: [0; 256], place: [0; 256] },
            flags: Ranks { set: [0; 256], place: [0; 256] },
            short: [0; 256],
            flag_buf: 0,
            flags_left: 0,
            avr_plc: 0x3500,
            avr_plc_b: 0,
            avr_ln1: 0,
            avr_ln2: 0,
            avr_ln3: 0,
            buf60: 0,
            num_huf: 0,
            literal_mode: false,
            repeat_count: 0,
            nhfb: 0x80,
            nlzb: 0x80,
            max_dist3: 0x2001,
            recent: [u32::MAX; 4],
            recent_pos: 0,
            last_dist: u32::MAX,
            last_len: 0,
        };
        for i in 0..256u16 {
            r.literals.set[i as usize] = i << 8;
            r.distances.set[i as usize] = i << 8;
            r.short[i as usize] = i;
            r.flags.set[i as usize] = (i.wrapping_neg() & 0xff) << 8;
        }
        r.distances.reset_counts();
        r
    }
}

impl Unpack {
    pub(super) fn unpack_rar15(&mut self, solid: bool, io: &mut dyn UnpackIo) {
        self.lz_start(solid);
        let mut st = std::mem::take(&mut self.rar15);
        let mut inp = std::mem::take(&mut self.stream);
        inp.reset();
        if !solid {
            *st = Rar15::default();
        }
        st.flags_left = 0;
        st.flag_buf = 0;
        st.literal_mode = false;
        st.repeat_count = 0;
        inp.fill(io);
        let mut left = self.dest_unp_size;
        if left > 0 {
            self.next_flags15(&mut st, &mut inp);
            st.flags_left = 8;
        }
        while left > 0 {
            self.lz_track_wrap();
            if !inp.fill(io) || inp.overrun() {
                break;
            }
            self.lz_flush_if_full(io);
            if st.literal_mode {
                left -= self.huff15(&mut st, &mut inp);
                continue;
            }
            st.flags_left -= 1;
            if st.flags_left < 0 {
                self.next_flags15(&mut st, &mut inp);
                st.flags_left = 7;
            }
            let first = st.flag_buf & 0x80 != 0;
            st.flag_buf <<= 1;
            if first {
                left -= if st.nlzb > st.nhfb { self.long_lz15(&mut st, &mut inp) } else { self.huff15(&mut st, &mut inp) };
                continue;
            }
            st.flags_left -= 1;
            if st.flags_left < 0 {
                self.next_flags15(&mut st, &mut inp);
                st.flags_left = 7;
            }
            let second = st.flag_buf & 0x80 != 0;
            st.flag_buf <<= 1;
            left -= if second {
                if st.nlzb > st.nhfb {
                    self.huff15(&mut st, &mut inp)
                } else {
                    self.long_lz15(&mut st, &mut inp)
                }
            } else {
                self.short_lz15(&mut st, &mut inp)
            };
        }
        self.lz_flush(io);
        self.rar15 = st;
        self.stream = inp;
    }

    fn next_flags15(&mut self, st: &mut Rar15, inp: &mut StreamBits) {
        let pos = decode(inp, &HF2) as usize;
        if pos >= 256 {
            return;
        }
        let v = st.flags.set[pos];
        st.flag_buf = (v >> 8) as u32;
        st.flags.use_at(pos, None);
    }

    /// Match copy; distances before the start of the data produce zeros.
    fn copy15(&mut self, dist: u32, len: u32) -> i64 {
        self.lz_copy(len, dist as usize);
        len as i64
    }

    fn short_lz15(&mut self, st: &mut Rar15, inp: &mut StreamBits) -> i64 {
        st.num_huf = 0;
        let mut bits = peek16(inp);
        if st.repeat_count == 2 {
            inp.skip(1);
            if bits >= 0x8000 {
                return self.copy15(st.last_dist, st.last_len);
            }
            bits <<= 1;
            st.repeat_count = 0;
        }
        bits >>= 8;
        let (lens, xors, var) = if st.avr_ln1 < 37 { (&SHORT_LEN1, &SHORT_XOR1, 1) } else { (&SHORT_LEN2, &SHORT_XOR2, 3) };
        let prefix = |i: usize| if i == var { st.buf60 + 3 } else { lens[i] };
        let mut len = 0usize;
        while ((bits ^ xors[len]) & !(0xffu32 >> prefix(len))) != 0 {
            len += 1;
        }
        inp.skip(prefix(len));
        if len >= 9 {
            if len == 9 {
                st.repeat_count += 1;
                return self.copy15(st.last_dist, st.last_len);
            }
            if len == 14 {
                st.repeat_count = 0;
                let l = decode(inp, &L2) + 5;
                let d = (peek16(inp) >> 1) | 0x8000;
                inp.skip(15);
                st.last_len = l;
                st.last_dist = d;
                return self.copy15(d, l);
            }
            st.repeat_count = 0;
            let dist = st.recent[st.recent_pos.wrapping_sub(len - 9) & 3];
            let mut l = decode(inp, &L1) + 2;
            if l == 0x101 && len == 10 {
                st.buf60 ^= 1;
                return 0;
            }
            if dist > 256 {
                l += 1;
            }
            if dist >= st.max_dist3 {
                l += 1;
            }
            st.recent[st.recent_pos] = dist;
            st.recent_pos = (st.recent_pos + 1) & 3;
            st.last_len = l;
            st.last_dist = dist;
            return self.copy15(dist, l);
        }
        st.repeat_count = 0;
        st.avr_ln1 += len as u32;
        st.avr_ln1 -= st.avr_ln1 >> 4;
        let place = (decode(inp, &HF2) & 0xff) as usize;
        let mut dist = st.short[place] as u32;
        if place > 0 {
            st.short[place] = st.short[place - 1];
            st.short[place - 1] = dist as u16;
        }
        let l = len as u32 + 2;
        dist += 1;
        st.recent[st.recent_pos] = dist;
        st.recent_pos = (st.recent_pos + 1) & 3;
        st.last_len = l;
        st.last_dist = dist;
        self.copy15(dist, l)
    }

    fn long_lz15(&mut self, st: &mut Rar15, inp: &mut StreamBits) -> i64 {
        st.num_huf = 0;
        st.nlzb += 16;
        if st.nlzb > 0xff {
            st.nlzb = 0x90;
            st.nhfb >>= 1;
        }
        let old_avr2 = st.avr_ln2;
        let bits = peek16(inp);
        let mut len = if st.avr_ln2 >= 122 {
            decode(inp, &L2)
        } else if st.avr_ln2 >= 64 {
            decode(inp, &L1)
        } else if bits < 0x100 {
            inp.skip(16);
            bits
        } else {
            // Unary: number of zero bits before the first one.
            let n = (bits << 16).leading_zeros();
            inp.skip(n + 1);
            n
        };
        st.avr_ln2 += len;
        st.avr_ln2 -= st.avr_ln2 >> 5;
        let code = if st.avr_plc_b > 0x28ff {
            &HF2
        } else if st.avr_plc_b > 0x6ff {
            &HF1
        } else {
            &HF0
        };
        let place = decode(inp, code);
        st.avr_plc_b += place;
        st.avr_plc_b -= st.avr_plc_b >> 8;
        let hi = st.distances.use_at((place & 0xff) as usize, None) as u32;
        let dist = ((hi & 0xff00) | (peek16(inp) >> 8)) >> 1;
        inp.skip(7);
        let old_avr3 = st.avr_ln3;
        if len != 1 && len != 4 {
            if len == 0 && dist <= st.max_dist3 {
                st.avr_ln3 += 1;
                st.avr_ln3 -= st.avr_ln3 >> 8;
            } else if st.avr_ln3 > 0 {
                st.avr_ln3 -= 1;
            }
        }
        len += 3;
        if dist >= st.max_dist3 {
            len += 1;
        }
        if dist <= 256 {
            len += 8;
        }
        st.max_dist3 = if old_avr3 > 0xb0 || (st.avr_plc >= 0x2a00 && old_avr2 < 0x40) { 0x7f00 } else { 0x2001 };
        st.recent[st.recent_pos] = dist;
        st.recent_pos = (st.recent_pos + 1) & 3;
        st.last_len = len;
        st.last_dist = dist;
        self.copy15(dist, len)
    }

    fn huff15(&mut self, st: &mut Rar15, inp: &mut StreamBits) -> i64 {
        let bits = peek16(inp);
        let code = match st.avr_plc {
            0x7600.. => &HF4,
            0x5e00.. => &HF3,
            0x3600.. => &HF2,
            0x0e00.. => &HF1,
            _ => &HF0,
        };
        let mut place = (decode(inp, code) & 0xff) as i32;
        if st.literal_mode {
            if place == 0 && bits > 0xfff {
                place = 0x100;
            }
            place -= 1;
            if place == -1 {
                // Rank 0 in literal mode: leave the mode, or a match.
                let b = peek16(inp);
                inp.skip(1);
                if b & 0x8000 != 0 {
                    st.num_huf = 0;
                    st.literal_mode = false;
                    return 0;
                }
                let len = if b & 0x4000 != 0 { 4 } else { 3 };
                inp.skip(1);
                let d = decode(inp, &HF2);
                let d = (d << 5) | (peek16(inp) >> 11);
                inp.skip(5);
                return self.copy15(d, len);
            }
        } else {
            let n = st.num_huf;
            st.num_huf += 1;
            if n >= 16 && st.flags_left == 0 {
                st.literal_mode = true;
            }
        }
        st.avr_plc += place as u32;
        st.avr_plc -= st.avr_plc >> 8;
        st.nhfb += 16;
        if st.nhfb > 0xff {
            st.nhfb = 0x90;
            st.nlzb >>= 1;
        }
        let pos = place as usize & 0xff;
        let b = (st.literals.set[pos] >> 8) as u8;
        self.lz_put(b);
        st.literals.use_at(pos, Some(0xa1));
        1
    }
}
