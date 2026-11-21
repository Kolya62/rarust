// SPDX-License-Identifier: GPL-3.0-or-later

//! Decoder for RAR 2.x compression (methods 20 and 26).
//!
//! The stream starts with a table section and may switch tables at any
//! time. A table section begins with two flag bits: audio mode, and "keep
//! previous lengths" (when clear, the previous lengths are reset to zero).
//! Audio mode is followed by a 2-bit channel count minus one. Then come 19
//! 4-bit lengths of the level code, and the code lengths coded with it:
//!
//! - 0-15: length = (value + previous length of this symbol) mod 16
//! - 16: repeat the last length 3 + 2 bits times
//! - 17: 3 + 3 bits zeros, 18: 11 + 7 bits zeros
//!
//! LZ mode uses a main code of 298 symbols, a 48-symbol distance code and a
//! 28-symbol length code for matches with recent distances. Audio mode
//! uses one 257-symbol code per channel: 0-255 are prediction errors, 256
//! switches tables.

use super::bitstream::StreamBits;
use super::huffman::Huffman;
use super::{Unpack, UnpackIo};

const MAIN: usize = 298;
const DIST: usize = 48;
const REP: usize = 28;
const AUDIO: usize = 257;
const LEVEL: usize = 19;
const MAX_TABLE: usize = AUDIO * 4;

/// Main code symbols.
const SYM_REPEAT_LAST: u16 = 256;
const SYM_NEW_TABLES: u16 = 269;

/// Match length slots: base and extra bits.
const LEN_BASE: [u8; 28] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 14, 16, 20, 24, 28, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224];
const LEN_BITS: [u8; 28] = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5];

/// Distance slots: two slots per bit count up to 16 bits, then 16-bit
/// slots in 64 KB steps.
const fn dist_tables() -> ([u32; DIST], [u8; DIST]) {
    let mut base = [0u32; DIST];
    let mut bits = [0u8; DIST];
    let mut i = 0;
    let mut next = 0u32;
    while i < DIST {
        let b = if i < 4 { 0 } else if i < 34 { (i / 2 - 1) as u8 } else { 16 };
        base[i] = next;
        bits[i] = b;
        next += 1 << b;
        i += 1;
    }
    (base, bits)
}
const DIST_BASE: [u32; DIST] = dist_tables().0;
const DIST_BITS: [u8; DIST] = dist_tables().1;

/// Short matches (length 2) with small distances: symbols 261-268.
const SHORT_BASE: [u8; 8] = [0, 4, 8, 16, 32, 64, 128, 192];
const SHORT_BITS: [u8; 8] = [2, 2, 3, 4, 5, 6, 6, 6];

/// Adaptive linear predictor of one audio channel. The prediction is a
/// weighted sum of the last byte and the last four deltas, plus the delta
/// of the previous channel. Every 32 bytes the weight whose adjustment
/// would have given the smallest total error is moved by one step.
#[derive(Clone, Copy, Default)]
struct Channel {
    k: [i32; 5],
    d: [i32; 4],
    last_delta: i32,
    last_byte: i32,
    errors: [u32; 11],
    count: u32,
}

impl Channel {
    fn decode(&mut self, err: u8, cross_delta: &mut i32) -> u8 {
        self.count = self.count.wrapping_add(1);
        self.d = [self.last_delta, self.last_delta.wrapping_sub(self.d[0]), self.d[1], self.d[2]];
        let cd = *cross_delta;
        let mut predicted = self.last_byte.wrapping_mul(8);
        for i in 0..4 {
            predicted = predicted.wrapping_add(self.k[i].wrapping_mul(self.d[i]));
        }
        predicted = predicted.wrapping_add(self.k[4].wrapping_mul(cd));
        let byte = (((predicted >> 3) & 0xff) as u32).wrapping_sub(err as u32);

        // Error each candidate weight change would have produced.
        let e = ((err as i8) as i32).wrapping_mul(8);
        let cand = [0, self.d[0], self.d[1], self.d[2], self.d[3], cd];
        self.errors[0] = self.errors[0].wrapping_add(e.unsigned_abs());
        for j in 1..6 {
            self.errors[2 * j - 1] = self.errors[2 * j - 1].wrapping_add(e.wrapping_sub(cand[j]).unsigned_abs());
            self.errors[2 * j] = self.errors[2 * j].wrapping_add(e.wrapping_add(cand[j]).unsigned_abs());
        }

        self.last_delta = (byte.wrapping_sub(self.last_byte as u32) as u8 as i8) as i32;
        *cross_delta = self.last_delta;
        self.last_byte = byte as i32;

        if self.count & 31 == 0 {
            let mut best = 0;
            for i in 1..11 {
                if self.errors[i] < self.errors[best] {
                    best = i;
                }
            }
            self.errors = [0; 11];
            if best > 0 {
                let w = &mut self.k[(best - 1) / 2];
                if best % 2 == 1 {
                    if *w >= -16 {
                        *w -= 1;
                    }
                } else if *w < 16 {
                    *w += 1;
                }
            }
        }
        byte as u8
    }
}

pub(super) struct Rar2 {
    main: Huffman,
    dist: Huffman,
    rep: Huffman,
    audio: [Huffman; 4],
    prev_lengths: [u8; MAX_TABLE],
    tables_read: bool,
    audio_mode: bool,
    channels: usize,
    channel: usize,
    cross_delta: i32,
    predictors: [Channel; 4],
    recent: [u32; 4],
    recent_pos: usize,
    last_dist: u32,
    last_len: u32,
}

impl Default for Rar2 {
    fn default() -> Self {
        Rar2 {
            main: Huffman::default(),
            dist: Huffman::default(),
            rep: Huffman::default(),
            audio: Default::default(),
            prev_lengths: [0; MAX_TABLE],
            tables_read: false,
            audio_mode: false,
            channels: 1,
            channel: 0,
            cross_delta: 0,
            predictors: Default::default(),
            recent: [u32::MAX; 4],
            recent_pos: 0,
            last_dist: u32::MAX,
            last_len: 0,
        }
    }
}

impl Rar2 {
    /// Reads a table section. Returns false if the input ended inside it.
    fn read_tables(&mut self, inp: &mut StreamBits, io: &mut dyn UnpackIo) -> bool {
        if !inp.fill(io) {
            return false;
        }
        self.audio_mode = inp.take(1) == 1;
        if inp.take(1) == 0 {
            self.prev_lengths = [0; MAX_TABLE];
        }
        let size = if self.audio_mode {
            self.channels = inp.take(2) as usize + 1;
            if self.channel >= self.channels {
                self.channel = 0;
            }
            AUDIO * self.channels
        } else {
            MAIN + DIST + REP
        };
        let mut level = [0u8; LEVEL];
        for l in level.iter_mut() {
            *l = inp.take(4) as u8;
        }
        let level = Huffman::new(&level);
        let mut lens = [0u8; MAX_TABLE];
        let mut i = 0;
        while i < size {
            if !inp.fill(io) {
                return false;
            }
            match level.decode(inp) {
                v @ 0..=15 => {
                    lens[i] = (v as u8).wrapping_add(self.prev_lengths[i]) & 15;
                    i += 1;
                }
                16 => {
                    let n = 3 + inp.take(2) as usize;
                    if i == 0 {
                        return false;
                    }
                    let end = (i + n).min(size);
                    let v = lens[i - 1];
                    lens[i..end].fill(v);
                    i = end;
                }
                v => {
                    let n = if v == 17 { 3 + inp.take(3) } else { 11 + inp.take(7) } as usize;
                    let end = (i + n).min(size);
                    lens[i..end].fill(0);
                    i = end;
                }
            }
        }
        self.tables_read = true;
        // Truncated input: the section is consumed but not used.
        if inp.overrun() {
            return true;
        }
        if self.audio_mode {
            for c in 0..self.channels {
                self.audio[c].build(&lens[c * AUDIO..(c + 1) * AUDIO]);
            }
        } else {
            self.main.build(&lens[..MAIN]);
            self.dist.build(&lens[MAIN..MAIN + DIST]);
            self.rep.build(&lens[MAIN + DIST..MAIN + DIST + REP]);
        }
        self.prev_lengths[..size].copy_from_slice(&lens[..size]);
        true
    }
}

fn length(inp: &mut StreamBits, slot: usize, base: u32) -> u32 {
    let slot = slot.min(LEN_BASE.len() - 1);
    LEN_BASE[slot] as u32 + base + inp.take(LEN_BITS[slot] as u32)
}

impl Unpack {
    pub(super) fn unpack_rar2(&mut self, solid: bool, io: &mut dyn UnpackIo) {
        self.lz_start(solid);
        let mut st = std::mem::take(&mut self.rar2);
        let mut inp = std::mem::take(&mut self.stream);
        inp.reset();
        if !solid {
            *st = Rar2::default();
        }
        if (!solid || !st.tables_read) && !st.read_tables(&mut inp, io) {
            self.rar2 = st;
            self.stream = inp;
            return;
        }
        // The file ends once its size has been produced.
        let mut left = self.dest_unp_size;
        while left > 0 {
            self.lz_track_wrap();
            if !inp.fill(io) || inp.overrun() {
                break;
            }
            self.lz_flush_if_full(io);
            if st.audio_mode {
                let ch = st.channel;
                let sym = st.audio[ch].decode(&mut inp);
                if sym == 256 {
                    if !st.read_tables(&mut inp, io) {
                        break;
                    }
                    continue;
                }
                let b = st.predictors[ch].decode(sym as u8, &mut st.cross_delta);
                self.lz_put(b);
                st.channel = (ch + 1) % st.channels;
                left -= 1;
                continue;
            }
            let sym = st.main.decode(&mut inp);
            let (len, dist) = match sym {
                0..=255 => {
                    self.lz_put(sym as u8);
                    left -= 1;
                    continue;
                }
                SYM_REPEAT_LAST => (st.last_len, st.last_dist),
                257..=260 => {
                    let dist = st.recent[st.recent_pos.wrapping_sub((sym - 256) as usize) & 3];
                    let slot = st.rep.decode(&mut inp) as usize;
                    let len = length(&mut inp, slot, 2);
                    (len + (dist >= 0x101) as u32 + (dist >= 0x2000) as u32 + (dist >= 0x40000) as u32, dist)
                }
                261..=268 => {
                    let i = (sym - 261) as usize;
                    (2, SHORT_BASE[i] as u32 + 1 + inp.take(SHORT_BITS[i] as u32))
                }
                SYM_NEW_TABLES => {
                    if !st.read_tables(&mut inp, io) {
                        break;
                    }
                    continue;
                }
                _ => {
                    let len = length(&mut inp, (sym - 270) as usize, 3);
                    let slot = (st.dist.decode(&mut inp) as usize).min(DIST - 1);
                    let dist = DIST_BASE[slot] + 1 + inp.take(DIST_BITS[slot] as u32);
                    (len + (dist >= 0x2000) as u32 + (dist >= 0x40000) as u32, dist)
                }
            };
            st.last_dist = dist;
            st.recent[st.recent_pos] = dist;
            st.recent_pos = (st.recent_pos + 1) & 3;
            st.last_len = len;
            left -= len as i64;
            self.lz_copy(len, dist as usize);
        }
        // A table switch right after the end of the file belongs to the
        // next file of a solid archive.
        if inp.fill(io) && inp.bytes_left() >= 5 {
            let sym = if st.audio_mode { st.audio[st.channel].decode(&mut inp) } else { st.main.decode(&mut inp) };
            if sym == if st.audio_mode { 256 } else { SYM_NEW_TABLES } {
                st.read_tables(&mut inp, io);
            }
        }
        self.lz_flush(io);
        self.rar2 = st;
        self.stream = inp;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distance_slots() {
        assert_eq!(&DIST_BASE[..8], &[0, 1, 2, 3, 4, 6, 8, 12]);
        assert_eq!(DIST_BASE[33], 98304);
        assert_eq!(DIST_BASE[34], 131072);
        assert_eq!(DIST_BASE[47], 983040);
        assert_eq!(DIST_BITS[33], 15);
        assert_eq!(DIST_BITS[34], 16);
    }
}
