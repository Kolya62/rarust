// SPDX-License-Identifier: GPL-3.0-or-later

//! Decoder for RAR 3.x compression (method 29): LZ blocks, PPMd blocks
//! and the standard filters of the RAR 3.x virtual machine.
//!
//! A table section starts at a byte boundary. Its first bit selects PPMd
//! (the rest of the section is PPMd parameters). For LZ, the next bit
//! keeps the previous code lengths (they are reset when it is clear),
//! then come 20 level code lengths (4 bits; 15 is followed by a 4-bit
//! count: 0 means length 15, n means n + 2 zero lengths) and the lengths
//! of the main (299), distance (60), low distance (17) and repeat length
//! (28) codes:
//!
//! - 0-15: length = (value + previous length) mod 16
//! - 16, 17: repeat the last length 3 + 3 bits or 11 + 7 bits times
//! - 18, 19: 3 + 3 bits or 11 + 7 bits zeros
//!
//! Main code: 0-255 literals, 256 end of block, 257 filter definition,
//! 258 repeat last match, 259-262 match with a recent distance, 263-270
//! length 2 matches with short distances, 271-298 matches.
//!
//! Filters are tiny VM programs. Only the standard programs that RAR
//! itself writes are recognized (by CRC); others leave their block empty.

use super::bitstream::StreamBits;
use super::huffman::{BitSource, Huffman};
use super::ppmd::{ByteReader, ModelPPM};
use super::{Unpack, UnpackIo};
use crate::hash::crc32::crc32;

const MAIN: usize = 299;
const DIST: usize = 60;
const LOW: usize = 17;
const REP: usize = 28;
const LEVEL: usize = 20;
const TABLES: usize = MAIN + DIST + LOW + REP;

const LEN_BASE: [u8; 28] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 14, 16, 20, 24, 28, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224];
const LEN_BITS: [u8; 28] = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5];
const SHORT_BASE: [u8; 8] = [0, 4, 8, 16, 32, 64, 128, 192];
const SHORT_BITS: [u8; 8] = [2, 2, 3, 4, 5, 6, 6, 6];

/// Distance slots: 4 slots without extra bits, two slots per bit count
/// from 1 to 15, then 14 slots of 16 bits and 12 slots of 18 bits.
const fn dist_tables() -> ([u32; DIST], [u8; DIST]) {
    const COUNT_PER_BITS: [usize; 19] = [4, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 14, 0, 12];
    let mut base = [0u32; DIST];
    let mut bits = [0u8; DIST];
    let (mut slot, mut next, mut b) = (0, 0u32, 0);
    while b < COUNT_PER_BITS.len() {
        let mut n = 0;
        while n < COUNT_PER_BITS[b] {
            base[slot] = next;
            bits[slot] = b as u8;
            next += 1 << b;
            slot += 1;
            n += 1;
        }
        b += 1;
    }
    (base, bits)
}
const DIST_BASE: [u32; DIST] = dist_tables().0;
const DIST_BITS: [u8; DIST] = dist_tables().1;

/// After symbol 16 of the low distance code, the previous low distance is
/// reused this many more times without being coded.
const LOW_REPEAT: u32 = 15;

/// Size of the VM memory that filters work in.
const VM_SIZE: usize = 0x40000;
const MAX_FILTERS: usize = 8192;
const MAX_CHANNELS: u32 = 1024;
/// Longest match, flushing keeps this much room in the window.
const MAX_MATCH: usize = 0x101 + 3;

#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
enum FilterKind {
    #[default]
    Unknown,
    E8,
    E8E9,
    Itanium,
    Delta,
    Rgb,
    Audio,
}

impl FilterKind {
    /// Standard filter programs, identified by length and CRC32.
    fn identify(code: &[u8]) -> FilterKind {
        // The first byte is an XOR checksum of the rest.
        if code.is_empty() || code[1..].iter().fold(0, |a, &b| a ^ b) != code[0] {
            return FilterKind::Unknown;
        }
        let crc = crc32(!0, code) ^ !0;
        match (code.len(), crc) {
            (53, 0xad57_6887) => FilterKind::E8,
            (57, 0x3cd7_e57e) => FilterKind::E8E9,
            (120, 0x3769_893f) => FilterKind::Itanium,
            (29, 0x0e06_077d) => FilterKind::Delta,
            (149, 0x1c2c_5dc8) => FilterKind::Rgb,
            (216, 0xbc85_e701) => FilterKind::Audio,
            _ => FilterKind::Unknown,
        }
    }
}

/// A filter waiting for its block to be decoded.
#[derive(Clone, Copy, Debug)]
struct Pending {
    kind: FilterKind,
    /// Window position of the block.
    start: usize,
    len: u32,
    /// The block starts after the window wraps around; skip one flush.
    next_window: bool,
    regs: [u32; 7],
}

/// MSB-first reader over filter definition bytes; zeros past the end.
struct CodeBits<'a> {
    data: &'a [u8],
    pos: usize,
}

impl CodeBits<'_> {
    fn take(&mut self, n: u32) -> u32 {
        let mut v = 0;
        for _ in 0..n {
            let byte = self.data.get(self.pos >> 3).copied().unwrap_or(0);
            v = v << 1 | ((byte >> (7 - (self.pos & 7))) & 1) as u32;
            self.pos += 1;
        }
        v
    }

    /// Variable length number: 2-bit selector, then 4 bits, 8 bits (or
    /// 0xffffff00 | 8 bits when the first 4 bits are zero), 16 or 32 bits.
    fn number(&mut self) -> u32 {
        match self.take(2) {
            0 => self.take(4),
            1 => {
                let v = self.take(4);
                let low = self.take(4);
                if v == 0 {
                    0xffff_ff00 | low << 4 | self.take(4)
                } else {
                    v << 4 | low
                }
            }
            2 => self.take(16),
            _ => self.take(32),
        }
    }
}

struct PpmBytes<'a> {
    inp: &'a mut StreamBits,
    io: &'a mut dyn UnpackIo,
}

impl ByteReader for PpmBytes<'_> {
    #[inline(always)]
    fn byte(&mut self) -> u8 {
        self.inp.fill(self.io);
        self.inp.take(8) as u8
    }
}

pub(super) struct Rar3 {
    main: Huffman,
    dist: Huffman,
    low: Huffman,
    rep: Huffman,
    prev_lengths: [u8; TABLES],
    tables_read: bool,
    ppm_mode: bool,
    ppm: Box<ModelPPM>,
    esc: i32,
    recent: [usize; 4],
    last_len: u32,
    low_dist: u32,
    low_repeat: u32,
    /// Filter kinds by filter number and the last block length of each.
    defs: Vec<(FilterKind, u32)>,
    last_def: usize,
    /// Pending filters in definition order; executed entries become None.
    pending: Vec<Option<Pending>>,
    mem: Vec<u8>,
}

impl Default for Rar3 {
    fn default() -> Self {
        Rar3 {
            main: Huffman::default(),
            dist: Huffman::default(),
            low: Huffman::default(),
            rep: Huffman::default(),
            prev_lengths: [0; TABLES],
            tables_read: false,
            ppm_mode: false,
            ppm: Box::default(),
            esc: 2,
            recent: [usize::MAX; 4],
            last_len: 0,
            low_dist: 0,
            low_repeat: 0,
            defs: Vec::new(),
            last_def: 0,
            pending: Vec::new(),
            mem: Vec::new(),
        }
    }
}

enum Step {
    Continue,
    Stop,
}

impl Unpack {
    pub(super) fn unpack_rar3(&mut self, solid: bool, io: &mut dyn UnpackIo) {
        self.lz_start(solid);
        let mut st = std::mem::take(&mut self.rar3);
        let mut inp = std::mem::take(&mut self.stream);
        inp.reset();
        if !solid {
            let ppm = std::mem::replace(&mut st.ppm, Box::default());
            // The PPMd model survives: a non-solid file starts it anew
            // with its own parameters.
            *st = Rar3 { ppm, ..Rar3::default() };
        } else {
            st.pending.clear();
        }
        if st.mem.is_empty() {
            st.mem = vec![0; VM_SIZE + 4];
        }
        self.decode_rar3(&mut st, &mut inp, solid, io);
        self.rar3 = st;
        self.stream = inp;
    }

    fn decode_rar3(&mut self, st: &mut Rar3, inp: &mut StreamBits, solid: bool, io: &mut dyn UnpackIo) {
        if !inp.fill(io) {
            return;
        }
        if (!solid || !st.tables_read) && !self.read_tables3(st, inp, io) {
            return;
        }
        loop {
            self.lz_track_wrap();
            if !inp.fill(io) || inp.overrun() {
                break;
            }
            // Keep room for the longest match before unwritten data.
            if self.wr_ptr != self.unp_ptr && (self.wr_ptr.wrapping_sub(self.unp_ptr) & self.max_win_mask) <= MAX_MATCH {
                self.flush3(st, io);
                if self.written_file_size > self.dest_unp_size {
                    return;
                }
            }
            let step = if st.ppm_mode { self.ppm_step(st, inp, io) } else { self.lz_step(st, inp, io) };
            if let Step::Stop = step {
                break;
            }
        }
        self.flush3(st, io);
    }

    fn ppm_char(st: &mut Rar3, inp: &mut StreamBits, io: &mut dyn UnpackIo) -> i32 {
        let c = st.ppm.decode_char(&mut PpmBytes { inp, io });
        if c < 0 {
            st.ppm.clean_up();
            st.ppm_mode = false;
        }
        c
    }

    fn ppm_step(&mut self, st: &mut Rar3, inp: &mut StreamBits, io: &mut dyn UnpackIo) -> Step {
        let c = Self::ppm_char(st, inp, io);
        if c < 0 {
            return Step::Stop;
        }
        if c == st.esc {
            // Escape codes: 0 new tables, 2 end of file, 3 filter,
            // 4 match (3 distance bytes, length byte), 5 run of the last
            // byte; anything else stands for the escape byte itself.
            match Self::ppm_char(st, inp, io) {
                -1 | 2 => return Step::Stop,
                0 => return if self.read_tables3(st, inp, io) { Step::Continue } else { Step::Stop },
                3 => {
                    let mut bytes = || Self::ppm_char(st, inp, io);
                    let ok = (|| {
                        let first = u32::try_from(bytes()).ok()?;
                        let len = match first & 7 {
                            6 => u32::try_from(bytes()).ok()? + 7,
                            7 => u32::try_from(bytes()).ok()? << 8 | u32::try_from(bytes()).ok()?,
                            n => n + 1,
                        };
                        if len == 0 {
                            return None;
                        }
                        let code = (0..len).map(|_| u8::try_from(bytes()).ok()).collect::<Option<Vec<u8>>>()?;
                        Some((first, code))
                    })();
                    return match ok {
                        Some((first, code)) if self.add_filter3(st, first, &code) => Step::Continue,
                        _ => Step::Stop,
                    };
                }
                4 => {
                    let mut v = [0u32; 4];
                    for x in v.iter_mut() {
                        let c = Self::ppm_char(st, inp, io);
                        if c < 0 {
                            return Step::Stop;
                        }
                        *x = c as u32 & 0xff;
                    }
                    let dist = (v[0] << 16 | v[1] << 8 | v[2]) as usize + 2;
                    self.lz_copy(v[3] + 32, dist);
                    return Step::Continue;
                }
                5 => {
                    let c = Self::ppm_char(st, inp, io);
                    if c < 0 {
                        return Step::Stop;
                    }
                    self.lz_copy(c as u32 + 4, 1);
                    return Step::Continue;
                }
                _ => {}
            }
        }
        self.lz_put(c as u8);
        Step::Continue
    }

    fn lz_step(&mut self, st: &mut Rar3, inp: &mut StreamBits, io: &mut dyn UnpackIo) -> Step {
        let sym = st.main.decode(inp) as usize;
        match sym {
            0..=255 => self.lz_put(sym as u8),
            256 => {
                // End of block: "1" new tables follow; "00" end of file;
                // "01" end of file, the next file starts with new tables.
                let (new_file, new_tables) = if inp.take(1) == 1 { (false, true) } else { (true, inp.take(1) == 1) };
                st.tables_read = !new_tables;
                if new_file || !self.read_tables3(st, inp, io) {
                    return Step::Stop;
                }
            }
            257 => {
                let first = inp.take(8);
                let len = match first & 7 {
                    6 => inp.take(8) + 7,
                    7 => inp.take(16),
                    n => n + 1,
                };
                if len == 0 {
                    return Step::Stop;
                }
                let mut code = vec![0u8; len as usize];
                for b in code.iter_mut() {
                    inp.fill(io);
                    *b = inp.take(8) as u8;
                }
                if !self.add_filter3(st, first, &code) {
                    return Step::Stop;
                }
            }
            258 => {
                if st.last_len != 0 {
                    self.lz_copy(st.last_len, st.recent[0]);
                }
            }
            259..=262 => {
                let i = sym - 259;
                let dist = st.recent[i];
                st.recent.copy_within(0..i, 1);
                st.recent[0] = dist;
                let slot = (st.rep.decode(inp) as usize).min(REP - 1);
                let len = LEN_BASE[slot] as u32 + 2 + inp.take(LEN_BITS[slot] as u32);
                st.last_len = len;
                self.lz_copy(len, dist);
            }
            263..=270 => {
                let i = sym - 263;
                let dist = SHORT_BASE[i] as usize + 1 + inp.take(SHORT_BITS[i] as u32) as usize;
                st.recent.copy_within(0..3, 1);
                st.recent[0] = dist;
                st.last_len = 2;
                self.lz_copy(2, dist);
            }
            _ => {
                let slot = sym - 271;
                if slot >= LEN_BASE.len() {
                    return Step::Continue;
                }
                let mut len = LEN_BASE[slot] as u32 + 3 + inp.take(LEN_BITS[slot] as u32);
                let ds = (st.dist.decode(inp) as usize).min(DIST - 1);
                let bits = DIST_BITS[ds] as u32;
                let mut dist = DIST_BASE[ds] + 1;
                if ds > 9 {
                    // The low 4 bits come from the low distance code, which
                    // can also repeat the previous low part.
                    if bits > 4 {
                        dist = dist.wrapping_add(inp.take(bits - 4) << 4);
                    }
                    if st.low_repeat > 0 {
                        st.low_repeat -= 1;
                        dist = dist.wrapping_add(st.low_dist);
                    } else {
                        let low = st.low.decode(inp) as u32;
                        if low == 16 {
                            st.low_repeat = LOW_REPEAT;
                            dist = dist.wrapping_add(st.low_dist);
                        } else {
                            dist = dist.wrapping_add(low);
                            st.low_dist = low;
                        }
                    }
                } else {
                    dist += inp.take(bits);
                }
                len += (dist >= 0x2000) as u32 + (dist >= 0x40000) as u32;
                st.recent.copy_within(0..3, 1);
                st.recent[0] = dist as usize;
                st.last_len = len;
                self.lz_copy(len, dist as usize);
            }
        }
        Step::Continue
    }

    fn read_tables3(&mut self, st: &mut Rar3, inp: &mut StreamBits, io: &mut dyn UnpackIo) -> bool {
        if !inp.fill(io) {
            return false;
        }
        inp.align();
        if inp.peek32() & 0x8000_0000 != 0 {
            st.ppm_mode = true;
            let mut esc = st.esc;
            let ok = st.ppm.decode_init(&mut esc, &mut PpmBytes { inp, io });
            st.esc = esc;
            return ok;
        }
        inp.take(1);
        st.ppm_mode = false;
        st.low_dist = 0;
        st.low_repeat = 0;
        if inp.take(1) == 0 {
            st.prev_lengths = [0; TABLES];
        }
        let mut level = [0u8; LEVEL];
        let mut i = 0;
        while i < LEVEL {
            let l = inp.take(4) as u8;
            if l == 15 {
                let zeros = inp.take(4) as usize;
                if zeros == 0 {
                    level[i] = 15;
                    i += 1;
                } else {
                    let end = (i + zeros + 2).min(LEVEL);
                    level[i..end].fill(0);
                    i = end;
                }
            } else {
                level[i] = l;
                i += 1;
            }
        }
        let level = Huffman::new(&level);
        let mut lens = [0u8; TABLES];
        let mut i = 0;
        while i < TABLES {
            if !inp.fill(io) {
                return false;
            }
            match level.decode(inp) {
                v @ 0..=15 => {
                    lens[i] = (v as u8).wrapping_add(st.prev_lengths[i]) & 15;
                    i += 1;
                }
                v @ (16 | 17) => {
                    let n = if v == 16 { 3 + inp.take(3) } else { 11 + inp.take(7) } as usize;
                    if i == 0 {
                        return false;
                    }
                    let end = (i + n).min(TABLES);
                    let prev = lens[i - 1];
                    lens[i..end].fill(prev);
                    i = end;
                }
                v => {
                    let n = if v == 18 { 3 + inp.take(3) } else { 11 + inp.take(7) } as usize;
                    let end = (i + n).min(TABLES);
                    lens[i..end].fill(0);
                    i = end;
                }
            }
        }
        st.tables_read = true;
        if inp.overrun() {
            return false;
        }
        st.main.build(&lens[..MAIN]);
        st.dist.build(&lens[MAIN..MAIN + DIST]);
        st.low.build(&lens[MAIN + DIST..MAIN + DIST + LOW]);
        st.rep.build(&lens[MAIN + DIST + LOW..]);
        st.prev_lengths = lens;
        true
    }

    /// Parses a filter definition. Flags in `first`: 0x80 explicit filter
    /// number (0 resets all), 0x40 start offset + 258, 0x20 explicit block
    /// length, 0x10 initial register values follow.
    fn add_filter3(&mut self, st: &mut Rar3, first: u32, code: &[u8]) -> bool {
        let mut c = CodeBits { data: code, pos: 0 };
        let num = if first & 0x80 != 0 {
            let n = c.number() as usize;
            if n == 0 {
                st.defs.clear();
                st.last_def = 0;
                st.pending.clear();
                0
            } else {
                n - 1
            }
        } else {
            st.last_def
        };
        if num > st.defs.len() {
            return false;
        }
        st.last_def = num;
        let is_new = num == st.defs.len();
        if is_new {
            if num > MAX_FILTERS {
                return false;
            }
            st.defs.push((FilterKind::Unknown, 0));
        }
        // Drop executed entries, keeping the order of the others.
        st.pending.retain(Option::is_some);
        if st.pending.len() > MAX_FILTERS {
            return false;
        }
        let mut offset = c.number();
        if first & 0x40 != 0 {
            offset = offset.wrapping_add(258);
        }
        let len = if first & 0x20 != 0 {
            let l = c.number();
            st.defs[num].1 = l;
            l
        } else {
            st.defs[num].1
        };
        let unflushed_gap = self.wr_ptr.wrapping_sub(self.unp_ptr) & self.max_win_mask;
        let mut f = Pending {
            kind: FilterKind::Unknown,
            start: (offset as usize).wrapping_add(self.unp_ptr) & self.max_win_mask,
            len,
            next_window: self.wr_ptr != self.unp_ptr && unflushed_gap <= offset as usize,
            regs: [0; 7],
        };
        f.regs[4] = len;
        if first & 0x10 != 0 {
            let mask = c.take(7);
            for i in 0..7 {
                if mask & (1 << i) != 0 {
                    f.regs[i] = c.number();
                }
            }
        }
        if is_new {
            let size = c.number() as usize;
            let at = c.pos / 8;
            if size == 0 || size >= 0x10000 || at + size > code.len() {
                st.pending.push(Some(f));
                return false;
            }
            let prog: Vec<u8> = (0..size).map(|_| c.take(8) as u8).collect();
            st.defs[num].0 = FilterKind::identify(&prog);
        }
        f.kind = st.defs[num].0;
        st.pending.push(Some(f));
        true
    }

    /// Writes decoded data, running filters whose blocks are complete.
    fn flush3(&mut self, st: &mut Rar3, io: &mut dyn UnpackIo) {
        let mask = self.max_win_mask;
        let mut border = self.wr_ptr;
        let mut avail = self.unp_ptr.wrapping_sub(border) & mask;
        let mut i = 0;
        while i < st.pending.len() {
            let Some(f) = st.pending[i] else {
                i += 1;
                continue;
            };
            if f.next_window {
                st.pending[i].as_mut().unwrap().next_window = false;
                i += 1;
                continue;
            }
            if (f.start.wrapping_sub(border) & mask) < avail {
                if border != f.start {
                    self.write_window3(border, f.start, io);
                    border = f.start;
                    avail = self.unp_ptr.wrapping_sub(border) & mask;
                }
                let len = f.len as usize;
                if len > avail {
                    // Not decoded yet: wait for the next flush.
                    for p in st.pending[i..].iter_mut().flatten() {
                        p.next_window = false;
                    }
                    self.wr_ptr = border;
                    return;
                }
                let end = (f.start + len) & mask;
                let n = len.min(VM_SIZE);
                for k in 0..n {
                    st.mem[k] = self.window[(f.start + k) & mask];
                }
                st.pending[i] = None;
                let mut out = run_filter(&mut st.mem, &f, self.written_file_size as u32);
                // Filters on the same block with matching sizes are chained.
                while let Some(Some(next)) = st.pending.get(i + 1).copied() {
                    if next.start != f.start || next.len != out.1 || next.next_window {
                        break;
                    }
                    if let Some(off) = out.0 {
                        let n = (out.1 as usize).min(VM_SIZE).min(st.mem.len() - off);
                        st.mem.copy_within(off..off + n, 0);
                    }
                    st.pending[i + 1] = None;
                    out = run_filter(&mut st.mem, &next, self.written_file_size as u32);
                    i += 1;
                }
                if let Some(off) = out.0 {
                    let stop = (off + out.1 as usize).min(VM_SIZE + 4);
                    io.unp_write(&st.mem[off..stop]);
                }
                self.unp_some_read = true;
                self.written_file_size += out.1 as i64;
                border = end;
                avail = self.unp_ptr.wrapping_sub(border) & mask;
            }
            i += 1;
        }
        self.write_window3(border, self.unp_ptr, io);
        self.wr_ptr = self.unp_ptr;
    }

    /// Writes window data `[from, to)`, not past the file size.
    fn write_window3(&mut self, from: usize, to: usize, io: &mut dyn UnpackIo) {
        if from != to {
            self.unp_some_read = true;
        }
        let w = std::mem::take(&mut self.window);
        if to < from {
            self.write_limited3(&w[from..self.max_win_size], io);
            self.write_limited3(&w[..to], io);
        } else {
            self.write_limited3(&w[from..to], io);
        }
        self.window = w;
    }

    fn write_limited3(&mut self, data: &[u8], io: &mut dyn UnpackIo) {
        if self.written_file_size < self.dest_unp_size {
            let left = (self.dest_unp_size - self.written_file_size) as usize;
            io.unp_write(&data[..data.len().min(left)]);
        }
        self.written_file_size += data.len() as i64;
    }
}

/// Runs a filter on `mem[..len]`. Returns the output offset in `mem` (None
/// for unknown programs, which produce nothing) and the output size.
fn run_filter(mem: &mut [u8], f: &Pending, file_pos: u32) -> (Option<usize>, u32) {
    let mut r = f.regs;
    r[6] = file_pos;
    let size = r[4] as usize & (VM_SIZE - 1);
    let ok = match f.kind {
        FilterKind::Unknown => return (None, 0),
        FilterKind::E8 => x86_filter(mem, r[4], r[6], false),
        FilterKind::E8E9 => x86_filter(mem, r[4], r[6], true),
        FilterKind::Itanium => itanium_filter(mem, r[4], r[6]),
        FilterKind::Delta => delta_filter(mem, r[4] as usize, r[0]),
        FilterKind::Rgb => rgb_filter(mem, r[4] as usize, r[0].wrapping_sub(3) as usize, r[1] as usize),
        FilterKind::Audio => audio_filter(mem, r[4] as usize, r[0] as usize),
    };
    // Filters that write a separate output put it after the input.
    let separate = matches!(f.kind, FilterKind::Delta | FilterKind::Rgb | FilterKind::Audio);
    let off = if separate && ok && 2 * size <= VM_SIZE { size } else { 0 };
    (Some(off), size as u32)
}

/// x86 CALL (E8) and optionally JMP (E9) targets were converted to
/// absolute addresses.
fn x86_filter(mem: &mut [u8], size: u32, file_pos: u32, e9: bool) -> bool {
    if size as usize > VM_SIZE || size < 4 {
        return false;
    }
    const SPAN: u32 = 0x100_0000;
    let mut i = 0u32;
    while i < size - 4 {
        let b = mem[i as usize];
        i += 1;
        if b == 0xe8 || (e9 && b == 0xe9) {
            let here = i.wrapping_add(file_pos);
            let p = i as usize;
            let addr = u32::from_le_bytes(mem[p..p + 4].try_into().unwrap());
            let fixed = if addr & 0x8000_0000 != 0 {
                (addr.wrapping_add(here) & 0x8000_0000 == 0).then(|| addr.wrapping_add(SPAN))
            } else {
                (addr.wrapping_sub(SPAN) & 0x8000_0000 != 0).then(|| addr.wrapping_sub(here))
            };
            if let Some(v) = fixed {
                mem[p..p + 4].copy_from_slice(&v.to_le_bytes());
            }
            i += 4;
        }
    }
    true
}

/// IA-64 bundles: 16-byte bundles whose template selects which of the
/// three 41-bit slots hold branch instructions; their 20-bit relative
/// targets were made absolute (in bundle units).
fn itanium_filter(mem: &mut [u8], size: u32, file_pos: u32) -> bool {
    if size as usize > VM_SIZE || size < 21 {
        return false;
    }
    const BRANCH_SLOTS: [u8; 16] = [4, 4, 6, 6, 0, 0, 7, 7, 4, 4, 0, 0, 4, 4, 0, 0];
    let mut bundle = file_pos >> 4;
    let mut at = 0usize;
    while (at as u32) < size - 21 {
        let template = (mem[at] & 0x1f) as i32 - 0x10;
        if template >= 0 {
            let slots = BRANCH_SLOTS[template as usize];
            for s in 0..3 {
                if slots & (1 << s) != 0 {
                    let bit = s * 41 + 5;
                    if bits_le(&mem[at..], bit + 37, 4) == 5 {
                        let target = bits_le(&mem[at..], bit + 13, 20);
                        set_bits_le(&mut mem[at..], target.wrapping_sub(bundle) & 0xfffff, bit + 13, 20);
                    }
                }
            }
        }
        at += 16;
        bundle = bundle.wrapping_add(1);
    }
    true
}

fn bits_le(d: &[u8], pos: u32, n: u32) -> u32 {
    let a = (pos / 8) as usize;
    let v = u32::from_le_bytes([d[a], d[a + 1], d[a + 2], d[a + 3]]) >> (pos & 7);
    v & (u32::MAX >> (32 - n))
}

fn set_bits_le(d: &mut [u8], value: u32, pos: u32, n: u32) {
    let a = (pos / 8) as usize;
    let shift = pos & 7;
    let keep = !((u32::MAX >> (32 - n)) << shift);
    let old = u32::from_le_bytes([d[a], d[a + 1], d[a + 2], d[a + 3]]);
    let new = (old & keep) | (value << shift);
    d[a..a + 4].copy_from_slice(&new.to_le_bytes());
}

/// Bytes were stored channel by channel as differences.
fn delta_filter(mem: &mut [u8], size: usize, channels: u32) -> bool {
    if size > VM_SIZE / 2 || channels == 0 || channels > MAX_CHANNELS {
        return false;
    }
    let ch = channels as usize;
    let mut src = 0;
    for c in 0..ch {
        let mut prev = 0u8;
        let mut d = size + c;
        while d < 2 * size {
            prev = prev.wrapping_sub(mem[src]);
            mem[d] = prev;
            src += 1;
            d += ch;
        }
    }
    true
}

/// 24-bit images: each colour channel is predicted with the Paeth
/// predictor from the left, upper and upper-left pixels; afterwards green
/// is added back to red and blue.
fn rgb_filter(mem: &mut [u8], size: usize, width: usize, red_pos: usize) -> bool {
    if size > VM_SIZE / 2 || size < 3 || width > size || red_pos > 2 {
        return false;
    }
    let out = size;
    let mut src = 0;
    for c in 0..3 {
        let mut prev = 0u32;
        let mut i = c;
        while i < size {
            let pred = if i >= width + 3 {
                let up = mem[out + i - width] as u32;
                let up_left = mem[out + i - width - 3] as u32;
                let p = prev.wrapping_add(up).wrapping_sub(up_left);
                let da = (p.wrapping_sub(prev) as i32).unsigned_abs();
                let db = (p.wrapping_sub(up) as i32).unsigned_abs();
                let dc = (p.wrapping_sub(up_left) as i32).unsigned_abs();
                if da <= db && da <= dc {
                    prev
                } else if db <= dc {
                    up
                } else {
                    up_left
                }
            } else {
                prev
            };
            let v = pred.wrapping_sub(mem[src] as u32) as u8;
            src += 1;
            mem[out + i] = v;
            prev = v as u32;
            i += 3;
        }
    }
    let mut i = red_pos;
    while i + 2 < size {
        let g = mem[out + i + 1];
        mem[out + i] = mem[out + i].wrapping_add(g);
        mem[out + i + 2] = mem[out + i + 2].wrapping_add(g);
        i += 3;
    }
    true
}

/// Audio: per channel adaptive predictor from the last byte and the last
/// three deltas; weights adapt every 32 bytes like in RAR 2.x audio mode.
fn audio_filter(mem: &mut [u8], size: usize, channels: usize) -> bool {
    if size > VM_SIZE / 2 || channels == 0 || channels > 128 {
        return false;
    }
    let out = size;
    let mut src = 0;
    for c in 0..channels {
        let mut last_byte = 0u32;
        let mut last_delta = 0i32;
        let mut d = [0i32; 3];
        let mut k = [0i32; 3];
        let mut errors = [0u32; 7];
        let mut count = 0u32;
        let mut i = c;
        while i < size {
            d = [last_delta, last_delta.wrapping_sub(d[0]), d[1]];
            let mut pred = last_byte.wrapping_mul(8);
            for j in 0..3 {
                pred = pred.wrapping_add(k[j].wrapping_mul(d[j]) as u32);
            }
            let err = mem[src];
            src += 1;
            let v = ((pred >> 3) & 0xff).wrapping_sub(err as u32);
            mem[out + i] = v as u8;
            last_delta = (v.wrapping_sub(last_byte) as u8 as i8) as i32;
            last_byte = v;
            let e = ((err as i8) as i32).wrapping_mul(8);
            errors[0] = errors[0].wrapping_add(e.unsigned_abs());
            for j in 0..3 {
                errors[2 * j + 1] = errors[2 * j + 1].wrapping_add(e.wrapping_sub(d[j]).unsigned_abs());
                errors[2 * j + 2] = errors[2 * j + 2].wrapping_add(e.wrapping_add(d[j]).unsigned_abs());
            }
            if count & 31 == 0 {
                let mut best = 0;
                for j in 1..7 {
                    if errors[j] < errors[best] {
                        best = j;
                    }
                }
                errors = [0; 7];
                if best > 0 {
                    let w = &mut k[(best - 1) / 2];
                    if best % 2 == 1 {
                        if *w >= -16 {
                            *w -= 1;
                        }
                    } else if *w < 16 {
                        *w += 1;
                    }
                }
            }
            count += 1;
            i += channels;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distance_slots() {
        assert_eq!(DIST_BASE[4], 4);
        assert_eq!(DIST_BITS[33], 15);
        assert_eq!(DIST_BITS[34], 16);
        assert_eq!(DIST_BITS[47], 16);
        assert_eq!(DIST_BITS[48], 18);
        assert_eq!(DIST_BASE[48], DIST_BASE[47] + 0x10000);
        assert_eq!(DIST_BASE[59] + (1 << 18), DIST_BASE[48] + 12 * (1 << 18));
    }

    #[test]
    fn number_coding() {
        // 00 0101 -> 5; 01 0000 1010 1010 -> 0xffffffaa; 10 + 16 bits
        let data = [0b0001_0101, 0b0000_1010, 0b1010_1000, 0b0000_0001, 0b0000_0000];
        let mut c = CodeBits { data: &data, pos: 0 };
        assert_eq!(c.number(), 5);
        assert_eq!(c.number(), 0xffff_ffaa);
    }
}
