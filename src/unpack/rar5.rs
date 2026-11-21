// SPDX-License-Identifier: GPL-3.0-or-later

//! Decoder for the RAR 5.0 / 7.0 compression format (methods 50 and 70).
//!
//! The packed stream is a sequence of byte aligned blocks:
//!
//! ```text
//! flags     u8   bits 0-2: valid bits in the last byte minus 1
//!                bits 3-4: number of block size bytes minus 1 (1..3)
//!                bit 6:    last block of the file
//!                bit 7:    block starts with Huffman tables
//! check     u8   0x5A ^ flags ^ every block size byte
//! size      1-3 bytes, little endian, size of the block data in bytes
//! data      MSB-first bit stream
//! ```
//!
//! Block data holds an optional table section followed by symbols of the
//! main code: literals (0-255), a filter (256), repeat of the last match
//! (257), matches with one of four recent distances (258-261) and new
//! matches (262+).

use super::huffman::{BitSource, Huffman};
use super::UnpackIo;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// Main code: 256 literals, filter, last match, 4 recent distances,
/// 44 length slots.
const MAIN_CODES: usize = 306;
/// Distance slots, RAR 5.0 and RAR 7.0 (dictionaries above 4 GB).
const DIST_CODES_50: usize = 64;
const DIST_CODES_70: usize = 80;
/// Low 4 bits of large distances.
const LOW_DIST_CODES: usize = 16;
/// Length slots for matches with a recent distance.
const REP_LEN_CODES: usize = 44;
/// Code used to transmit the bit lengths of the other codes.
const LEVEL_CODES: usize = 20;


/// The longest match: length slot 43 with all extra bits set plus three
/// extra bytes added for long distances.
const MAX_MATCH: u64 = 0x1001 + 3;

const MAX_FILTERS: usize = 8192;
const MAX_FILTER_LEN: u32 = 0x40_0000;
/// Unflushed output is written once it reaches this size.
const FLUSH_SIZE: u64 = 0x40_0000;
/// Packed bytes per thread decoded in one parallel batch.
const BATCH_PER_THREAD: usize = 0x10_0000;

/// One decoded symbol of the main code. Parsing a block into operations
/// needs only its Huffman tables, so blocks can be parsed in parallel;
/// operations are then applied to the dictionary in order.
#[derive(Clone, Copy)]
enum Op {
    Literal(u8),
    /// The next `n` bytes of the job's literal buffer.
    Literals(u32),
    Filter { kind: FilterKind, offset: u64, len: u32 },
    /// Repeat the last match.
    RepeatLast,
    /// Match with recent distance number `idx`.
    Recent { idx: u8, len: u32 },
    Match { len: u32, dist: u64 },
}

/// Decodes the next operation from a block.
#[inline(always)]
fn next_op(inp: &mut Bits, t: &Tables) -> Option<Op> {
    let sym = t.main.decode(inp) as u32;
    Some(match sym {
        0..=255 => Op::Literal(sym as u8),
        256 => {
            // Start offset from the current position, length, 3-bit
            // type, and for delta the channel count.
            fn number(inp: &mut Bits) -> u32 {
                let bytes = inp.take(2) + 1;
                (0..bytes).fold(0, |v, i| v | inp.take(8) << (i * 8))
            }
            let offset = number(inp) as u64;
            let len = number(inp);
            let kind = match inp.take(3) {
                0 => FilterKind::Delta(inp.take(5) + 1),
                1 => FilterKind::E8,
                2 => FilterKind::E8E9,
                3 => FilterKind::Arm,
                _ => return None, // Unknown filter: ignored.
            };
            Op::Filter { kind, offset, len }
        }
        257 => Op::RepeatLast,
        258..=261 => {
            let slot = t.rep_len.decode(inp) as u32;
            Op::Recent { idx: (sym - 258) as u8, len: slot_length(inp, slot) }
        }
        _ => {
            let mut len = slot_length(inp, sym - 262);
            let dist = distance(inp, t);
            if dist > 0x100 {
                len += 1 + (dist > 0x2000) as u32 + (dist > 0x40000) as u32;
            }
            Op::Match { len, dist }
        }
    })
}

/// Distance of a new match. Slots 0-3 are distances 1-4; each further
/// pair of slots doubles the range. With 4 or more extra bits the lowest
/// 4 are coded separately by the low distance code.
#[inline(always)]
fn distance(inp: &mut Bits, t: &Tables) -> u64 {
    let slot = t.dist.decode(inp) as u32;
    if slot < 4 {
        return slot as u64 + 1;
    }
    let extra = slot / 2 - 1;
    let mut dist = ((2 | (slot & 1)) as u64) << extra;
    if extra >= 4 {
        if extra > 4 {
            dist += inp.take_long(extra - 4) << 4;
        }
        dist += t.low_dist.decode(inp) as u64;
    } else {
        dist += inp.take(extra) as u64;
    }
    dist + 1
}

/// Longest literal run stored as one operation; below `MAX_MATCH`, so the
/// flush rules for matches cover it.
const MAX_LITERAL_RUN: u32 = 0x1000;

/// Operations of one block and the bytes of its literal runs.
#[derive(Default)]
struct Parsed {
    ops: Vec<Op>,
    literals: Vec<u8>,
}

/// A block read and prepared for parallel parsing.
struct Job {
    data: Vec<u8>,
    start: u64,
    bit_len: u64,
    tables: Arc<Tables>,
}

impl Job {
    fn parse(&self) -> Parsed {
        let mut inp = Bits { data: &self.data, pos: self.start };
        let mut p = Parsed { ops: Vec::with_capacity(self.data.len() / 4), literals: Vec::with_capacity(self.data.len()) };
        while inp.pos < self.bit_len {
            match next_op(&mut inp, &self.tables) {
                Some(Op::Literal(b)) => {
                    p.literals.push(b);
                    match p.ops.last_mut() {
                        Some(Op::Literals(n)) if *n < MAX_LITERAL_RUN => *n += 1,
                        _ => p.ops.push(Op::Literals(1)),
                    }
                }
                Some(op) => p.ops.push(op),
                None => {}
            }
        }
        p
    }
}

/// MSB-first reader over one block. Reads past the end return zero bits, so
/// corrupt data can never index outside the buffer.
struct Bits<'a> {
    data: &'a [u8],
    pos: u64,
}

impl BitSource for Bits<'_> {
    #[inline(always)]
    fn peek32(&mut self) -> u32 {
        Bits::peek32(self)
    }
    #[inline(always)]
    fn skip(&mut self, n: u32) {
        Bits::skip(self, n)
    }
}

impl Bits<'_> {
    #[inline(always)]
    fn peek32(&self) -> u32 {
        let byte = (self.pos >> 3) as usize;
        let mut w = [0u8; 8];
        if byte + 8 <= self.data.len() {
            w.copy_from_slice(&self.data[byte..byte + 8]);
        } else if byte < self.data.len() {
            let n = self.data.len() - byte;
            w[..n].copy_from_slice(&self.data[byte..]);
        }
        (u64::from_be_bytes(w) << (self.pos & 7) >> 32) as u32
    }

    #[inline(always)]
    fn skip(&mut self, n: u32) {
        self.pos += n as u64;
    }

    /// Reads up to 32 bits.
    #[inline(always)]
    fn take(&mut self, n: u32) -> u32 {
        if n == 0 {
            return 0;
        }
        let v = self.peek32() >> (32 - n);
        self.skip(n);
        v
    }

    /// Reads up to 64 bits.
    fn take_long(&mut self, n: u32) -> u64 {
        if n <= 32 {
            self.take(n) as u64
        } else {
            let hi = self.take(n - 32) as u64;
            hi << 32 | self.take(32) as u64
        }
    }
}

#[derive(Clone, Default)]
struct Tables {
    main: Huffman,
    dist: Huffman,
    low_dist: Huffman,
    rep_len: Huffman,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FilterKind {
    Delta(u32),
    E8,
    E8E9,
    Arm,
}

#[derive(Clone, Copy)]
struct Filter {
    kind: FilterKind,
    /// Absolute position in the decoded stream.
    start: u64,
    len: u32,
}

/// Length of a match from its slot: slots 0-7 are lengths 2-9, then each
/// group of four slots doubles the range and adds one extra bit.
#[inline(always)]
fn slot_length(inp: &mut Bits, slot: u32) -> u32 {
    if slot < 8 {
        slot + 2
    } else {
        let extra = slot / 4 - 1;
        ((4 | (slot & 3)) << extra) + 2 + inp.take(extra)
    }
}

pub(super) struct Rar5 {
    tables: Arc<Tables>,
    tables_ok: bool,
    /// Bytes decoded since the dictionary was created.
    pos: u64,
    /// Bytes of `pos` already passed to the output.
    flushed: u64,
    /// Stream position where the current file starts.
    file_start: u64,
    recent: [u64; 4],
    last_len: u32,
    filters: Vec<Filter>,
    block: Vec<u8>,
    /// Bytes of the current file passed to `UnpackIo`.
    written: i64,
}

impl Default for Rar5 {
    fn default() -> Self {
        Rar5 {
            tables: Arc::default(),
            tables_ok: false,
            pos: 0,
            flushed: 0,
            file_start: 0,
            recent: [u64::MAX; 4],
            last_len: 0,
            filters: Vec::new(),
            block: Vec::new(),
            written: 0,
        }
    }
}

/// Buffered packed input. Reads are large and 16-byte aligned, which
/// encrypted data requires.
struct Input<'a> {
    io: &'a mut dyn UnpackIo,
    buf: Vec<u8>,
    pos: usize,
    len: usize,
}

impl Input<'_> {
    const CHUNK: usize = 0x10000;

    /// Reads exactly `out.len()` bytes unless the input ends.
    fn read_full(&mut self, out: &mut [u8]) -> bool {
        let mut got = 0;
        while got < out.len() {
            if self.pos == self.len {
                self.buf.resize(Self::CHUNK, 0);
                let n = self.io.unp_read(&mut self.buf);
                if n <= 0 {
                    return false;
                }
                self.pos = 0;
                self.len = n as usize;
            }
            let n = (self.len - self.pos).min(out.len() - got);
            out[got..got + n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
            self.pos += n;
            got += n;
        }
        true
    }
}

impl Rar5 {
    /// Decodes one file. `window` is the dictionary, `dest_size` the
    /// unpacked size of the file (negative if unknown).
    pub(super) fn unpack(
        &mut self,
        window: &mut [u8],
        solid: bool,
        large_dist: bool,
        threads: usize,
        dest_size: i64,
        io: &mut dyn UnpackIo,
    ) {
        if !solid {
            let tables = std::mem::take(&mut self.tables);
            *self = Rar5 { tables, block: std::mem::take(&mut self.block), ..Default::default() };
        }
        self.filters.clear();
        self.file_start = self.pos;
        self.written = 0;
        let input = Input { io, buf: Vec::new(), pos: 0, len: 0 };
        let wpos = (self.pos % window.len() as u64) as usize;
        let flush_limit = (window.len() as u64 / 2).min(FLUSH_SIZE);
        let mut dec = Decoder { st: self, win: window, wpos, flush_limit, dest_size, input };
        if threads > 1 {
            dec.run_parallel(large_dist, threads);
        } else {
            dec.run(large_dist);
        }
    }
}

struct Decoder<'a> {
    st: &'a mut Rar5,
    win: &'a mut [u8],
    /// `st.pos` modulo the window size.
    wpos: usize,
    /// Unflushed size that triggers a flush.
    flush_limit: u64,
    dest_size: i64,
    input: Input<'a>,
}

impl Decoder<'_> {
    fn run(&mut self, large_dist: bool) {
        let dist_codes = if large_dist { DIST_CODES_70 } else { DIST_CODES_50 };
        let mut block = std::mem::take(&mut self.st.block);
        while let Some((bit_len, last, has_tables)) = self.read_block(&mut block) {
            let mut inp = Bits { data: &block, pos: 0 };
            if has_tables {
                let Some(t) = read_tables(&mut inp, dist_codes) else { break };
                self.st.tables = Arc::new(t);
                self.st.tables_ok = true;
            }
            if !self.st.tables_ok {
                break;
            }
            let tables = self.st.tables.clone();
            let mut ok = true;
            while ok && inp.pos < bit_len {
                if let Some(op) = next_op(&mut inp, &tables) {
                    ok = self.apply(op, &mut &[][..]);
                }
            }
            if !ok {
                break;
            }
            if last {
                break;
            }
        }
        self.st.block = block;
        self.flush(true);
    }

    /// Reads blocks and Huffman tables for one batch. Returns the jobs and
    /// whether the input ended.
    fn read_batch(&mut self, dist_codes: usize, threads: usize) -> (Vec<Job>, bool) {
        let mut jobs = Vec::new();
        let mut bytes = 0;
        while jobs.len() < threads * 8 && bytes < threads * BATCH_PER_THREAD {
            let mut data = Vec::new();
            let Some((bit_len, last, has_tables)) = self.read_block(&mut data) else { return (jobs, true) };
            let mut inp = Bits { data: &data, pos: 0 };
            if has_tables {
                let Some(t) = read_tables(&mut inp, dist_codes) else { return (jobs, true) };
                self.st.tables = Arc::new(t);
                self.st.tables_ok = true;
            }
            if !self.st.tables_ok {
                return (jobs, true);
            }
            let start = inp.pos;
            bytes += data.len();
            jobs.push(Job { data, start, bit_len, tables: self.st.tables.clone() });
            if last {
                return (jobs, true);
            }
        }
        (jobs, false)
    }

    /// Pipeline: while batch N is applied to the dictionary on this thread,
    /// worker threads parse batch N + 1.
    fn run_parallel(&mut self, large_dist: bool, threads: usize) {
        let dist_codes = if large_dist { DIST_CODES_70 } else { DIST_CODES_50 };
        let mut pending: Option<Pending> = None;
        loop {
            let (jobs, done) = self.read_batch(dist_codes, threads);
            let started = (!jobs.is_empty()).then(|| Pending::start(jobs, threads));
            if let Some(p) = pending.take() {
                if !self.apply_all(p.finish()) {
                    break;
                }
            }
            pending = started;
            if done {
                if let Some(p) = pending.take() {
                    self.apply_all(p.finish());
                }
                break;
            }
        }
        self.flush(true);
    }

    fn apply_all(&mut self, parsed: Vec<Parsed>) -> bool {
        for p in parsed {
            let mut lits = &p.literals[..];
            for &op in &p.ops {
                if !self.apply(op, &mut lits) {
                    return false;
                }
            }
        }
        true
    }

    /// Reads the next block header and data. Returns the number of data
    /// bits, the last block flag and the table flag.
    fn read_block(&mut self, block: &mut Vec<u8>) -> Option<(u64, bool, bool)> {
        let mut head = [0u8; 2];
        if !self.input.read_full(&mut head) {
            return None;
        }
        let flags = head[0];
        let size_bytes = ((flags >> 3) & 3) as usize + 1;
        if size_bytes > 3 {
            return None;
        }
        let mut size = [0u8; 3];
        if !self.input.read_full(&mut size[..size_bytes]) {
            return None;
        }
        let check = size[..size_bytes].iter().fold(0x5a ^ flags, |c, &b| c ^ b);
        if check != head[1] {
            return None;
        }
        let len = u32::from_le_bytes([size[0], size[1], size[2], 0]) as usize;
        block.clear();
        block.resize(len, 0);
        if !self.input.read_full(block) {
            return None;
        }
        let last_bits = (flags & 7) as u64 + 1;
        let bit_len = if len == 0 { 0 } else { (len as u64 - 1) * 8 + last_bits };
        Some((bit_len, flags & 0x40 != 0, flags & 0x80 != 0))
    }

    /// Applies one operation to the dictionary. Returns false if decoding
    /// cannot continue.
    #[inline(always)]
    fn apply(&mut self, op: Op, lits: &mut &[u8]) -> bool {
        if self.st.pos - self.st.flushed >= self.flush_limit {
            self.flush(false);
            if self.st.pos - self.st.flushed + MAX_MATCH >= self.win.len() as u64 {
                return false;
            }
        }
        match op {
            Op::Literal(b) => {
                self.win[self.wpos] = b;
                self.advance(1);
            }
            Op::Literals(n) => {
                let n = (n as usize).min(lits.len());
                let (run, rest) = lits.split_at(n);
                *lits = rest;
                let first = run.len().min(self.win.len() - self.wpos);
                self.win[self.wpos..self.wpos + first].copy_from_slice(&run[..first]);
                self.win[..run.len() - first].copy_from_slice(&run[first..]);
                self.advance(run.len());
            }
            Op::Filter { kind, offset, len } => return self.add_filter(kind, offset, len),
            Op::RepeatLast => {
                if self.st.last_len != 0 {
                    self.copy(self.st.last_len, self.st.recent[0]);
                }
            }
            Op::Recent { idx, len } => {
                let i = idx as usize;
                let dist = self.st.recent[i];
                self.st.recent.copy_within(0..i, 1);
                self.st.recent[0] = dist;
                self.st.last_len = len;
                self.copy(len, dist);
            }
            Op::Match { len, dist } => {
                self.st.recent.copy_within(0..3, 1);
                self.st.recent[0] = dist;
                self.st.last_len = len;
                self.copy(len, dist);
            }
        }
        true
    }

    #[inline(always)]
    fn advance(&mut self, n: usize) {
        self.st.pos += n as u64;
        self.wpos += n;
        if self.wpos >= self.win.len() {
            self.wpos -= self.win.len();
        }
    }

    #[inline(always)]
    fn copy(&mut self, len: u32, dist: u64) {
        let n = self.win.len();
        let dst = self.wpos;
        let src = if dist <= dst as u64 {
            dst - dist as usize
        } else {
            // Wraps around; distances beyond the dictionary come from
            // corrupt data and are reduced so indices stay in range.
            (dst + n - (dist % n as u64) as usize) % n
        };
        let len_u = len as usize;
        if dist >= len as u64 && src + len_u <= self.win.len() && dst + len_u <= self.win.len() {
            self.win.copy_within(src..src + len_u, dst);
        } else {
            let (mut s, mut d) = (src, dst);
            for _ in 0..len {
                self.win[d] = self.win[s];
                s += 1;
                d += 1;
                if s == self.win.len() {
                    s = 0;
                }
                if d == self.win.len() {
                    d = 0;
                }
            }
        }
        self.advance(len as usize);
    }

    fn add_filter(&mut self, kind: FilterKind, offset: u64, len: u32) -> bool {
        if self.st.filters.len() >= MAX_FILTERS {
            self.flush(false);
            if self.st.filters.len() >= MAX_FILTERS {
                return false;
            }
        }
        // A filtered block must fit into the unflushed part of the window.
        if len == 0 || len > MAX_FILTER_LEN || len as u64 + 2 * MAX_MATCH >= self.win.len() as u64 {
            return true;
        }
        self.st.filters.push(Filter { kind, start: self.st.pos + offset, len });
        true
    }

    /// Copies decoded bytes `[from, to)` of the stream out of the window.
    fn window_slice(&self, from: u64, to: u64, out: &mut Vec<u8>) {
        let n = self.win.len() as u64;
        out.clear();
        let mut p = from;
        while p < to {
            let i = (p % n) as usize;
            let run = ((to - p) as usize).min(self.win.len() - i);
            out.extend_from_slice(&self.win[i..i + run]);
            p += run as u64;
        }
    }

    fn emit(&mut self, data: &[u8]) {
        if self.dest_size >= 0 {
            let left = (self.dest_size - self.st.written).max(0) as usize;
            self.input.io.unp_write(&data[..data.len().min(left)]);
        } else {
            self.input.io.unp_write(data);
        }
        self.st.written += data.len() as i64;
    }

    fn emit_window(&mut self, from: u64, to: u64) {
        let n = self.win.len() as u64;
        let mut p = from;
        while p < to {
            let i = (p % n) as usize;
            let run = ((to - p) as usize).min(self.win.len() - i);
            let w = std::mem::take(&mut self.win);
            self.emit(&w[i..i + run]);
            self.win = w;
            p += run as u64;
        }
    }

    /// Writes decoded data, applying filters whose blocks are complete.
    /// With `end`, the remaining data is written even if a filter block is
    /// incomplete (the file ended inside it).
    fn flush(&mut self, end: bool) {
        let mut tmp = Vec::new();
        let mut i = 0;
        while i < self.st.filters.len() {
            let f = self.st.filters[i];
            if f.start < self.st.flushed {
                // Overlaps already written data.
                i += 1;
                continue;
            }
            let f_end = f.start + f.len as u64;
            if f.start >= self.st.pos || f_end > self.st.pos {
                break;
            }
            self.emit_window(self.st.flushed, f.start);
            self.window_slice(f.start, f_end, &mut tmp);
            let file_pos = f.start - self.st.file_start;
            let out = apply_filter(f.kind, &mut tmp, file_pos);
            self.emit(&out);
            self.st.flushed = f_end;
            i += 1;
        }
        self.st.filters.drain(..i);
        let limit = match self.st.filters.first() {
            Some(f) if !end => f.start.min(self.st.pos),
            _ => self.st.pos,
        };
        if limit > self.st.flushed {
            self.emit_window(self.st.flushed, limit);
            self.st.flushed = limit;
        }
        if end {
            self.st.filters.clear();
        }
    }
}

/// Reads the Huffman tables at the start of a block.
fn read_tables(inp: &mut Bits, dist_codes: usize) -> Option<Tables> {
    // Bit lengths of the level code: 4 bits each, 15 is followed by a
    // 4-bit count of zero lengths (count 0 means the length is 15).
    let mut level = [0u8; LEVEL_CODES];
    let mut i = 0;
    while i < LEVEL_CODES {
        let l = inp.take(4) as u8;
        if l == 15 {
            let zeros = inp.take(4) as usize;
            if zeros == 0 {
                level[i] = 15;
                i += 1;
            } else {
                let end = (i + zeros + 2).min(LEVEL_CODES);
                level[i..end].fill(0);
                i = end;
            }
        } else {
            level[i] = l;
            i += 1;
        }
    }
    let mut level_code = Huffman::default();
    level_code.build(&level);

    let total = MAIN_CODES + dist_codes + LOW_DIST_CODES + REP_LEN_CODES;
    let mut lens = vec![0u8; total];
    let mut i = 0;
    while i < total {
        let sym = level_code.decode(inp);
        match sym {
            0..=15 => {
                lens[i] = sym as u8;
                i += 1;
            }
            16 | 17 => {
                // Repeat the previous length.
                let n = if sym == 16 { 3 + inp.take(3) } else { 11 + inp.take(7) } as usize;
                if i == 0 {
                    return None;
                }
                let prev = lens[i - 1];
                let end = (i + n).min(total);
                lens[i..end].fill(prev);
                i = end;
            }
            _ => {
                // Run of zero lengths.
                let n = if sym == 18 { 3 + inp.take(3) } else { 11 + inp.take(7) } as usize;
                let end = (i + n).min(total);
                lens[i..end].fill(0);
                i = end;
            }
        }
    }
    let (main, rest) = lens.split_at(MAIN_CODES);
    let (dist, rest) = rest.split_at(dist_codes);
    let (low, rep) = rest.split_at(LOW_DIST_CODES);
    let mut t = Tables::default();
    t.main.build(main);
    t.dist.build(dist);
    t.low_dist.build(low);
    t.rep_len.build(rep);
    Some(t)
}

/// A batch being parsed by worker threads.
struct Pending {
    workers: Vec<std::thread::JoinHandle<Vec<(usize, Parsed)>>>,
    count: usize,
}

impl Pending {
    fn start(jobs: Vec<Job>, threads: usize) -> Pending {
        let count = jobs.len();
        let jobs = Arc::new(jobs);
        let next = Arc::new(AtomicUsize::new(0));
        let workers = (0..threads.min(count))
            .map(|_| {
                let (jobs, next) = (jobs.clone(), next.clone());
                std::thread::spawn(move || {
                    let mut out = Vec::new();
                    loop {
                        let i = next.fetch_add(1, Ordering::Relaxed);
                        let Some(job) = jobs.get(i) else { break };
                        out.push((i, job.parse()));
                    }
                    out
                })
            })
            .collect();
        Pending { workers, count }
    }

    /// Waits for the workers; results are in block order.
    fn finish(self) -> Vec<Parsed> {
        let mut slots: Vec<Option<Parsed>> = (0..self.count).map(|_| None).collect();
        for w in self.workers {
            for (i, p) in w.join().unwrap_or_default() {
                slots[i] = Some(p);
            }
        }
        // A missing result (a panicked worker) ends the batch there.
        slots.into_iter().map_while(|p| p).collect()
    }
}

/// Reverses an encoder filter on `data`, which starts `file_pos` bytes into
/// the file.
fn apply_filter(kind: FilterKind, data: &mut Vec<u8>, file_pos: u64) -> Vec<u8> {
    let len = data.len();
    match kind {
        FilterKind::Delta(channels) => {
            // Bytes are stored channel by channel as differences.
            let ch = channels as usize;
            let mut out = vec![0u8; len];
            let mut src = 0;
            for c in 0..ch {
                let mut prev = 0u8;
                let mut j = c;
                while j < len {
                    prev = prev.wrapping_sub(data[src]);
                    out[j] = prev;
                    src += 1;
                    j += ch;
                }
            }
            out
        }
        FilterKind::E8 | FilterKind::E8E9 => {
            // x86 CALL (E8) and JMP (E9) targets were made absolute.
            const SPAN: u32 = 0x100_0000;
            let e9 = kind == FilterKind::E8E9;
            let mut i = 0;
            while i + 4 < len {
                let b = data[i];
                i += 1;
                if b == 0xe8 || (e9 && b == 0xe9) {
                    let here = ((file_pos + i as u64) % SPAN as u64) as u32;
                    let addr = u32::from_le_bytes(data[i..i + 4].try_into().unwrap());
                    let fixed = if addr & 0x8000_0000 != 0 {
                        // Negative: was a backward target if it lands in range.
                        (addr.wrapping_add(here) & 0x8000_0000 == 0).then(|| addr.wrapping_add(SPAN))
                    } else {
                        (addr.wrapping_sub(SPAN) & 0x8000_0000 != 0).then(|| addr.wrapping_sub(here))
                    };
                    if let Some(v) = fixed {
                        data[i..i + 4].copy_from_slice(&v.to_le_bytes());
                    }
                    i += 4;
                }
            }
            std::mem::take(data)
        }
        FilterKind::Arm => {
            // ARM BL instructions: 24-bit word offsets were made absolute.
            let mut i = 0;
            while i + 3 < len {
                if data[i + 3] == 0xeb {
                    let v = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], 0]);
                    let v = v.wrapping_sub(((file_pos + i as u64) / 4) as u32);
                    data[i..i + 3].copy_from_slice(&v.to_le_bytes()[..3]);
                }
                i += 4;
            }
            std::mem::take(data)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delta_filter() {
        let mut d = vec![0xff, 0xff, 0xf6, 0xff];
        // Two channels: [1, 2], [10, 11]
        assert_eq!(apply_filter(FilterKind::Delta(2), &mut d, 0), vec![1, 10, 2, 11]);
    }
}
