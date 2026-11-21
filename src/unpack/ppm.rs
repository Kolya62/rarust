// SPDX-License-Identifier: GPL-3.0-or-later

//! PPMd variant H (Dmitry Shkarin's PPM model with information
//! inheritance and secondary escape estimation) with the range coder used
//! by RAR 3.x.
//!
//! The model lives in one memory block. Its lower part holds the text
//! (recent symbols, which also serve as "raw" successors), the upper part
//! 12-byte units: contexts and arrays of symbol states. Units are managed
//! by a size class allocator; when memory runs out the model restarts.
//! Decoding is only correct if the model evolves exactly as the encoder's,
//! including allocation, so all structures are kept in the same layout.
//!
//! Layout in memory (offsets are u32, 0 = none):
//!
//! ```text
//! state   (6 bytes):  symbol u8, freq u8, successor u32
//! context (12 bytes): num_stats u16, summ_freq u16, stats u32, suffix u32
//!                     a context with one symbol keeps its state at +2
//! free    (12 bytes): stamp u16, units u16, next u32, prev u32
//!                     (a free list link is the first u32)
//! ```

const UNIT: u32 = 12;
const INDEXES: usize = 38;
const MAX_O: usize = 64;
const MAX_FREQ: u32 = 124;
const INT_BITS: u32 = 7;
const PERIOD_BITS: u32 = 7;
const TOT_BITS: u32 = INT_BITS + PERIOD_BITS;
const INTERVAL: u32 = 1 << INT_BITS;
const BIN_SCALE: u32 = 1 << TOT_BITS;
const TOP: u32 = 1 << 24;
const BOT: u32 = 1 << 15;
/// Offset of the model memory in `heap`; offset 0 stays "none".
const BASE: u32 = UNIT;

const INIT_BIN_ESC: [u16; 8] = [0x3cdd, 0x1f3f, 0x59bf, 0x48f3, 0x64a1, 0x5abc, 0x6632, 0x6051];
const EXP_ESCAPE: [u8; 16] = [25, 14, 9, 7, 5, 5, 4, 4, 4, 3, 3, 3, 2, 2, 2, 2];

/// Source of packed bytes for the range decoder.
pub trait ByteReader {
    fn byte(&mut self) -> u8;
}

/// Secondary escape estimation context.
#[derive(Clone, Copy, Default)]
struct See {
    summ: u16,
    shift: u8,
    count: u8,
}

impl See {
    fn new(init: u32) -> See {
        See { summ: (init << (PERIOD_BITS - 4)) as u16, shift: (PERIOD_BITS - 4) as u8, count: 4 }
    }

    fn mean(&mut self) -> u32 {
        let r = (self.summ >> self.shift) as u32;
        self.summ = self.summ.wrapping_sub(r as u16);
        r + (r == 0) as u32
    }

    fn update(&mut self) {
        if (self.shift as u32) < PERIOD_BITS {
            self.count = self.count.wrapping_sub(1);
            if self.count == 0 {
                self.summ = self.summ.wrapping_add(self.summ);
                self.count = (3u32 << self.shift) as u8;
                self.shift += 1;
            }
        }
    }
}

/// Which escape estimator a symbol decoded after an escape updates.
#[derive(Clone, Copy)]
enum SeeRef {
    Dummy,
    At(usize, usize),
}

#[derive(Default)]
struct Coder {
    low: u32,
    code: u32,
    range: u32,
}

impl Coder {
    fn init(&mut self, rd: &mut impl ByteReader) {
        self.low = 0;
        self.code = 0;
        self.range = u32::MAX;
        for _ in 0..4 {
            self.code = self.code << 8 | rd.byte() as u32;
        }
    }

    fn count(&mut self, scale: u32) -> u32 {
        self.range /= scale;
        self.code.wrapping_sub(self.low) / self.range
    }

    fn count_shift(&mut self, shift: u32) -> u32 {
        self.range >>= shift;
        self.code.wrapping_sub(self.low) / self.range
    }

    fn decode(&mut self, lo: u32, hi: u32) {
        self.low = self.low.wrapping_add(self.range.wrapping_mul(lo));
        self.range = self.range.wrapping_mul(hi - lo);
    }

    /// Carry-less normalization (Subbotin).
    fn normalize(&mut self, rd: &mut impl ByteReader) {
        loop {
            if (self.low ^ self.low.wrapping_add(self.range)) >= TOP {
                if self.range >= BOT {
                    break;
                }
                self.range = self.low.wrapping_neg() & (BOT - 1);
            }
            self.code = self.code << 8 | rd.byte() as u32;
            self.range <<= 8;
            self.low <<= 8;
        }
    }
}

pub struct Ppm {
    mem: Vec<u8>,
    /// Model memory size in bytes (0 = not allocated).
    size: u32,
    heap_end: u32,
    text: u32,
    units_start: u32,
    lo_unit: u32,
    hi_unit: u32,
    free: [u32; INDEXES],
    glue_count: u32,
    indx2units: [u8; INDEXES],
    units2indx: [u8; 128],

    min_ctx: u32,
    max_ctx: u32,
    found: u32,
    order_fall: i32,
    max_order: i32,
    init_esc: u32,
    prev_success: u32,
    run_length: i32,
    init_rl: i32,
    hi_bits_flag: u32,
    num_masked: u32,
    esc_count: u8,
    char_mask: [u8; 256],
    ns2indx: [u8; 256],
    ns2bsindx: [u8; 256],
    hb2flag: [u8; 256],
    see: [[See; 16]; 25],
    dummy_see: See,
    bin_summ: Box<[[u16; 64]; 128]>,
    coder: Coder,
    /// Range of the symbol found by the current decoding step.
    sub: (u32, u32),
}

impl Default for Ppm {
    fn default() -> Self {
        let mut indx2units = [0u8; INDEXES];
        let mut units2indx = [0u8; 128];
        // Size classes: 1-4 units in steps of 1, then steps of 2, 3, 4.
        let mut k = 0usize;
        for (i, u) in indx2units.iter_mut().enumerate() {
            let step = if i < 4 { 1 } else if i < 8 { 2 } else if i < 12 { 3 } else { 4 };
            k += step;
            *u = k as u8;
        }
        let mut i = 0;
        for (n, x) in units2indx.iter_mut().enumerate() {
            if indx2units[i] as usize <= n {
                i += 1;
            }
            *x = i as u8;
        }
        let mut ns2indx = [0u8; 256];
        let (mut m, mut step, mut left) = (3u8, 1, 1);
        for (i, x) in ns2indx.iter_mut().enumerate() {
            if i < 3 {
                *x = i as u8;
                continue;
            }
            *x = m;
            left -= 1;
            if left == 0 {
                step += 1;
                left = step;
                m += 1;
            }
        }
        let mut ns2bsindx = [0u8; 256];
        for (i, x) in ns2bsindx.iter_mut().enumerate() {
            *x = match i {
                0 => 0,
                1 => 2,
                2..=10 => 4,
                _ => 6,
            };
        }
        let mut hb2flag = [0u8; 256];
        hb2flag[0x40..].fill(8);
        Ppm {
            mem: Vec::new(),
            size: 0,
            heap_end: 0,
            text: 0,
            units_start: 0,
            lo_unit: 0,
            hi_unit: 0,
            free: [0; INDEXES],
            glue_count: 0,
            indx2units,
            units2indx,
            min_ctx: 0,
            max_ctx: 0,
            found: 0,
            order_fall: 0,
            max_order: 0,
            init_esc: 0,
            prev_success: 0,
            run_length: 0,
            init_rl: 0,
            hi_bits_flag: 0,
            num_masked: 0,
            esc_count: 0,
            char_mask: [0; 256],
            ns2indx,
            ns2bsindx,
            hb2flag,
            see: [[See::default(); 16]; 25],
            dummy_see: See { summ: 0, shift: PERIOD_BITS as u8, count: 0 },
            bin_summ: Box::new([[0; 64]; 128]),
            coder: Coder::default(),
            sub: (0, 0),
        }
    }
}

// Memory accessors.
impl Ppm {
    fn u16_at(&self, o: u32) -> u32 {
        let o = o as usize;
        u16::from_le_bytes([self.mem[o], self.mem[o + 1]]) as u32
    }
    fn set_u16(&mut self, o: u32, v: u32) {
        let o = o as usize;
        self.mem[o..o + 2].copy_from_slice(&(v as u16).to_le_bytes());
    }
    fn u32_at(&self, o: u32) -> u32 {
        let o = o as usize;
        u32::from_le_bytes(self.mem[o..o + 4].try_into().unwrap())
    }
    fn set_u32(&mut self, o: u32, v: u32) {
        let o = o as usize;
        self.mem[o..o + 4].copy_from_slice(&v.to_le_bytes());
    }

    // State fields.
    fn sym(&self, s: u32) -> u32 {
        self.mem[s as usize] as u32
    }
    fn freq(&self, s: u32) -> u32 {
        self.mem[s as usize + 1] as u32
    }
    fn set_freq(&mut self, s: u32, f: u32) {
        self.mem[s as usize + 1] = f as u8;
    }
    fn succ(&self, s: u32) -> u32 {
        self.u32_at(s + 2)
    }
    fn set_succ(&mut self, s: u32, v: u32) {
        self.set_u32(s + 2, v);
    }
    fn copy_state(&mut self, dst: u32, src: u32) {
        self.mem.copy_within(src as usize..src as usize + 6, dst as usize);
    }
    fn swap_states(&mut self, a: u32, b: u32) {
        let mut t = [0u8; 6];
        t.copy_from_slice(&self.mem[a as usize..a as usize + 6]);
        self.copy_state(a, b);
        self.mem[b as usize..b as usize + 6].copy_from_slice(&t);
    }

    // Context fields.
    fn num_stats(&self, c: u32) -> u32 {
        self.u16_at(c)
    }
    fn set_num_stats(&mut self, c: u32, v: u32) {
        self.set_u16(c, v);
    }
    fn summ(&self, c: u32) -> u32 {
        self.u16_at(c + 2)
    }
    fn set_summ(&mut self, c: u32, v: u32) {
        self.set_u16(c + 2, v);
    }
    fn stats(&self, c: u32) -> u32 {
        self.u32_at(c + 4)
    }
    fn set_stats(&mut self, c: u32, v: u32) {
        self.set_u32(c + 4, v);
    }
    fn suffix(&self, c: u32) -> u32 {
        self.u32_at(c + 8)
    }
    fn set_suffix(&mut self, c: u32, v: u32) {
        self.set_u32(c + 8, v);
    }
    fn one_state(c: u32) -> u32 {
        c + 2
    }
}

// Unit allocator.
impl Ppm {
    fn i2u(&self, i: usize) -> u32 {
        self.indx2units[i] as u32
    }
    fn u2i(&self, nu: u32) -> usize {
        self.units2indx[nu as usize - 1] as usize
    }

    fn start_alloc(&mut self, mb: u32) -> bool {
        let size = mb << 20;
        if self.size == size {
            return true;
        }
        self.stop_alloc();
        let bytes = (BASE + size / 12 * UNIT + 2 * UNIT) as usize;
        match super::alloc_zeroed(bytes) {
            Ok(m) => self.mem = m,
            Err(_) => crate::errhnd::memory_error(),
        }
        self.heap_end = BASE + size / 12 * UNIT + UNIT;
        self.size = size;
        true
    }

    fn stop_alloc(&mut self) {
        self.size = 0;
        self.mem = Vec::new();
    }

    /// Lower 1/8 of memory is text, the rest units.
    fn init_alloc(&mut self) {
        self.free = [0; INDEXES];
        self.text = BASE;
        let units = UNIT * (self.size / 8 / UNIT * 7);
        self.hi_unit = BASE + self.size;
        self.lo_unit = self.hi_unit - units;
        self.units_start = self.lo_unit;
        self.glue_count = 0;
    }

    fn insert_node(&mut self, p: u32, i: usize) {
        let head = self.free[i];
        self.set_u32(p, head);
        self.free[i] = p;
    }

    fn remove_node(&mut self, i: usize) -> u32 {
        let p = self.free[i];
        self.free[i] = self.u32_at(p);
        p
    }

    /// Returns the tail of a block of class `old` beyond class `new` to the
    /// free lists.
    fn split_block(&mut self, p: u32, old: usize, new: usize) {
        let diff = self.i2u(old) - self.i2u(new);
        let p = p + self.i2u(new) * UNIT;
        let mut i = self.u2i(diff);
        if self.i2u(i) != diff {
            i -= 1;
            let k = self.i2u(i);
            self.insert_node(p + k * UNIT, (diff - k - 1) as usize);
        }
        self.insert_node(p, i);
    }

    /// Merges physically adjacent free blocks and refills the free lists.
    fn glue_free_blocks(&mut self) {
        const FREE: u32 = 0xffff;
        if self.lo_unit != self.hi_unit {
            self.mem[self.lo_unit as usize] = 0;
        }
        // Doubly linked list of all free blocks; a sentinel node sits in
        // front of the model memory, newest blocks first.
        let head = 0u32;
        self.set_u32(head + 4, head);
        self.set_u32(head + 8, head);
        for i in 0..INDEXES {
            while self.free[i] != 0 {
                let p = self.remove_node(i);
                let next = self.u32_at(head + 4);
                self.set_u32(p + 4, next);
                self.set_u32(p + 8, head);
                self.set_u32(next + 8, p);
                self.set_u32(head + 4, p);
                self.set_u16(p, FREE);
                self.set_u16(p + 2, self.i2u(i));
            }
        }
        let mut p = self.u32_at(head + 4);
        while p != head {
            loop {
                let nu = self.u16_at(p + 2);
                let p1 = p + nu * UNIT;
                if self.u16_at(p1) != FREE || nu + self.u16_at(p1 + 2) >= 0x10000 {
                    break;
                }
                let (n1, v1) = (self.u32_at(p1 + 4), self.u32_at(p1 + 8));
                self.set_u32(v1 + 4, n1);
                self.set_u32(n1 + 8, v1);
                let merged = nu + self.u16_at(p1 + 2);
                self.set_u16(p + 2, merged);
            }
            p = self.u32_at(p + 4);
        }
        loop {
            let p0 = self.u32_at(head + 4);
            if p0 == head {
                break;
            }
            let (n, v) = (self.u32_at(p0 + 4), self.u32_at(p0 + 8));
            self.set_u32(v + 4, n);
            self.set_u32(n + 8, v);
            let mut p = p0;
            let mut sz = self.u16_at(p + 2);
            while sz > 128 {
                self.insert_node(p, INDEXES - 1);
                sz -= 128;
                p += 128 * UNIT;
            }
            let mut i = self.u2i(sz);
            if self.i2u(i) != sz {
                i -= 1;
                let k = sz - self.i2u(i);
                self.insert_node(p + (sz - k) * UNIT, (k - 1) as usize);
            }
            self.insert_node(p, i);
        }
    }

    fn alloc_units_rare(&mut self, indx: usize) -> u32 {
        if self.glue_count == 0 {
            self.glue_count = 255;
            self.glue_free_blocks();
            if self.free[indx] != 0 {
                return self.remove_node(indx);
            }
        }
        let mut i = indx;
        loop {
            i += 1;
            if i == INDEXES {
                self.glue_count -= 1;
                let bytes = self.i2u(indx) * UNIT;
                if self.units_start - self.text > bytes {
                    self.units_start -= bytes;
                    return self.units_start;
                }
                return 0;
            }
            if self.free[i] != 0 {
                break;
            }
        }
        let p = self.remove_node(i);
        self.split_block(p, i, indx);
        p
    }

    fn alloc_units(&mut self, nu: u32) -> u32 {
        let indx = self.u2i(nu);
        if self.free[indx] != 0 {
            return self.remove_node(indx);
        }
        let bytes = self.i2u(indx) * UNIT;
        if bytes <= self.hi_unit - self.lo_unit {
            let p = self.lo_unit;
            self.lo_unit += bytes;
            return p;
        }
        self.alloc_units_rare(indx)
    }

    fn alloc_context(&mut self) -> u32 {
        if self.hi_unit != self.lo_unit {
            self.hi_unit -= UNIT;
            return self.hi_unit;
        }
        if self.free[0] != 0 {
            return self.remove_node(0);
        }
        self.alloc_units_rare(0)
    }

    /// Grows a state array of `old_nu` units by one unit.
    fn expand_units(&mut self, p: u32, old_nu: u32) -> u32 {
        let i0 = self.u2i(old_nu);
        let i1 = self.u2i(old_nu + 1);
        if i0 == i1 {
            return p;
        }
        let n = self.alloc_units(old_nu + 1);
        if n != 0 {
            self.mem.copy_within(p as usize..(p + old_nu * UNIT) as usize, n as usize);
            self.insert_node(p, i0);
        }
        n
    }

    fn shrink_units(&mut self, p: u32, old_nu: u32, new_nu: u32) -> u32 {
        let i0 = self.u2i(old_nu);
        let i1 = self.u2i(new_nu);
        if i0 == i1 {
            return p;
        }
        if self.free[i1] != 0 {
            let n = self.remove_node(i1);
            self.mem.copy_within(p as usize..(p + new_nu * UNIT) as usize, n as usize);
            self.insert_node(p, i0);
            return n;
        }
        self.split_block(p, i0, i1);
        p
    }

    fn free_units(&mut self, p: u32, nu: u32) {
        let i = self.u2i(nu);
        self.insert_node(p, i);
    }
}

// Model.
impl Ppm {
    fn restart_model(&mut self) {
        self.char_mask = [0; 256];
        self.init_alloc();
        self.init_rl = -(self.max_order.min(12)) - 1;
        let c = self.alloc_context();
        self.min_ctx = c;
        self.max_ctx = c;
        self.set_suffix(c, 0);
        self.order_fall = self.max_order;
        self.set_num_stats(c, 256);
        self.set_summ(c, 257);
        let stats = self.alloc_units(128);
        self.found = stats;
        self.set_stats(c, stats);
        self.run_length = self.init_rl;
        self.prev_success = 0;
        for i in 0..256u32 {
            let s = stats + i * 6;
            self.mem[s as usize] = i as u8;
            self.mem[s as usize + 1] = 1;
            self.set_succ(s, 0);
        }
        for i in 0..128 {
            for k in 0..8 {
                let v = (BIN_SCALE - INIT_BIN_ESC[k] as u32 / (i as u32 + 2)) as u16;
                for m in (0..64).step_by(8) {
                    self.bin_summ[i][k + m] = v;
                }
            }
        }
        for i in 0..25 {
            for k in 0..16 {
                self.see[i][k] = See::new(5 * i as u32 + 10);
            }
        }
    }

    fn start_model(&mut self, max_order: i32) {
        self.esc_count = 1;
        self.max_order = max_order;
        self.restart_model();
        self.dummy_see.shift = PERIOD_BITS as u8;
    }

    fn clear_mask(&mut self) {
        self.esc_count = 1;
        self.char_mask = [0; 256];
    }

    /// Halves the frequencies of the current context, dropping symbols
    /// that reach zero.
    fn rescale(&mut self) {
        let c = self.min_ctx;
        let stats = self.stats(c);
        let old_ns = self.num_stats(c);
        // Move the found state to the front.
        let mut p = self.found;
        while p != stats {
            self.swap_states(p, p - 6);
            p -= 6;
        }
        self.set_freq(stats, self.freq(stats) + 4);
        self.set_summ(c, self.summ(c) + 4);
        let mut esc = self.summ(c) - self.freq(stats);
        let adder = (self.order_fall != 0) as u32;
        let f = (self.freq(stats) + adder) >> 1;
        self.set_freq(stats, f);
        let mut summ = f;
        let mut i = old_ns - 1;
        let mut p = stats;
        while i > 0 {
            p += 6;
            esc -= self.freq(p);
            let f = (self.freq(p) + adder) >> 1;
            self.set_freq(p, f);
            summ += f;
            if f > self.freq(p - 6) {
                // Keep states sorted by frequency.
                let mut tmp = [0u8; 6];
                tmp.copy_from_slice(&self.mem[p as usize..p as usize + 6]);
                let mut p1 = p;
                loop {
                    self.copy_state(p1, p1 - 6);
                    p1 -= 6;
                    if p1 == stats || tmp[1] as u32 <= self.freq(p1 - 6) {
                        break;
                    }
                }
                self.mem[p1 as usize..p1 as usize + 6].copy_from_slice(&tmp);
            }
            i -= 1;
        }
        self.set_summ(c, summ);
        if self.freq(p) == 0 {
            let mut i = 0;
            loop {
                i += 1;
                p -= 6;
                if self.freq(p) != 0 {
                    break;
                }
            }
            esc += i;
            let ns = old_ns - i;
            self.set_num_stats(c, ns);
            if ns == 1 {
                let mut tmp = [0u8; 6];
                tmp.copy_from_slice(&self.mem[stats as usize..stats as usize + 6]);
                loop {
                    tmp[1] -= tmp[1] >> 1;
                    esc >>= 1;
                    if esc <= 1 {
                        break;
                    }
                }
                self.free_units(stats, (old_ns + 1) >> 1);
                let os = Self::one_state(c);
                self.mem[os as usize..os as usize + 6].copy_from_slice(&tmp);
                self.found = os;
                return;
            }
        }
        esc -= esc >> 1;
        self.set_summ(c, self.summ(c) + esc);
        let n0 = (old_ns + 1) >> 1;
        let n1 = (self.num_stats(c) + 1) >> 1;
        if n0 != n1 {
            let s = self.shrink_units(stats, n0, n1);
            self.set_stats(c, s);
        }
        self.found = self.stats(c);
    }

    /// Creates contexts for the found symbol from the current context up
    /// to the highest order. `p1` is the found symbol's state in the
    /// suffix of the current context, if already known.
    fn create_successors(&mut self, skip: bool, p1: u32) -> u32 {
        let fs_sym = self.sym(self.found);
        let up_branch = self.succ(self.found);
        let mut pc = self.min_ctx;
        let mut ps = [0u32; MAX_O];
        let mut n = 0;
        if !skip {
            ps[n] = self.found;
            n += 1;
        }
        if skip || self.suffix(pc) != 0 {
            let mut p1 = p1;
            loop {
                pc = self.suffix(pc);
                let p = if p1 != 0 {
                    std::mem::take(&mut p1)
                } else if self.num_stats(pc) != 1 {
                    let mut p = self.stats(pc);
                    while self.sym(p) != fs_sym {
                        p += 6;
                    }
                    p
                } else {
                    Self::one_state(pc)
                };
                if self.succ(p) != up_branch {
                    pc = self.succ(p);
                    break;
                }
                if n >= MAX_O {
                    return 0;
                }
                ps[n] = p;
                n += 1;
                if self.suffix(pc) == 0 {
                    break;
                }
            }
        }
        if n == 0 {
            return pc;
        }
        let up_sym = self.mem[up_branch as usize] as u32;
        let up_succ = up_branch + 1;
        let up_freq = if self.num_stats(pc) != 1 {
            if pc <= self.text {
                return 0;
            }
            let mut p = self.stats(pc);
            while self.sym(p) != up_sym {
                p += 6;
            }
            let cf = self.freq(p) - 1;
            let s0 = self.summ(pc) - self.num_stats(pc) - cf;
            1 + if 2 * cf <= s0 { (5 * cf > s0) as u32 } else { (2 * cf + 3 * s0 - 1) / (2 * s0) }
        } else {
            self.freq(Self::one_state(pc))
        };
        while n > 0 {
            n -= 1;
            let c = self.alloc_context();
            if c == 0 {
                return 0;
            }
            self.set_num_stats(c, 1);
            let os = Self::one_state(c);
            self.mem[os as usize] = up_sym as u8;
            self.mem[os as usize + 1] = up_freq as u8;
            self.set_succ(os, up_succ);
            self.set_suffix(c, pc);
            self.set_succ(ps[n], c);
            pc = c;
        }
        pc
    }

    fn update_model(&mut self) {
        let fs = self.found;
        let fs_sym = self.sym(fs);
        let fs_freq = self.freq(fs);
        let mut fs_succ = self.succ(fs);
        let mut p = 0u32;
        let suffix = self.suffix(self.min_ctx);
        if fs_freq < MAX_FREQ / 4 && suffix != 0 {
            let pc = suffix;
            if self.num_stats(pc) != 1 {
                p = self.stats(pc);
                if self.sym(p) != fs_sym {
                    loop {
                        p += 6;
                        if self.sym(p) == fs_sym {
                            break;
                        }
                    }
                    if self.freq(p) >= self.freq(p - 6) {
                        self.swap_states(p, p - 6);
                        p -= 6;
                    }
                }
                if self.freq(p) < MAX_FREQ - 9 {
                    self.set_freq(p, self.freq(p) + 2);
                    self.set_summ(pc, self.summ(pc) + 2);
                }
            } else {
                p = Self::one_state(pc);
                if self.freq(p) < 32 {
                    self.set_freq(p, self.freq(p) + 1);
                }
            }
        }
        if self.order_fall == 0 {
            let c = self.create_successors(true, p);
            self.min_ctx = c;
            self.max_ctx = c;
            self.set_succ(self.found, c);
            if c == 0 {
                self.restart_after_failure();
            }
            return;
        }
        self.mem[self.text as usize] = fs_sym as u8;
        self.text += 1;
        let mut successor = self.text;
        if self.text >= self.units_start {
            self.restart_after_failure();
            return;
        }
        if fs_succ != 0 {
            if fs_succ <= self.text {
                fs_succ = self.create_successors(false, p);
                if fs_succ == 0 {
                    self.restart_after_failure();
                    return;
                }
            }
            self.order_fall -= 1;
            if self.order_fall == 0 {
                successor = fs_succ;
                if self.max_ctx != self.min_ctx {
                    self.text -= 1;
                }
            }
        } else {
            self.set_succ(self.found, successor);
            fs_succ = self.min_ctx;
        }
        let ns = self.num_stats(self.min_ctx);
        let s0 = self.summ(self.min_ctx) - ns - (fs_freq - 1);
        let mut pc = self.max_ctx;
        while pc != self.min_ctx {
            let ns1 = self.num_stats(pc);
            if ns1 != 1 {
                if ns1 & 1 == 0 {
                    let s = self.expand_units(self.stats(pc), ns1 >> 1);
                    if s == 0 {
                        self.restart_after_failure();
                        return;
                    }
                    self.set_stats(pc, s);
                }
                let add = (2 * ns1 < ns) as u32 + 2 * ((4 * ns1 <= ns) as u32 & (self.summ(pc) <= 8 * ns1) as u32);
                self.set_summ(pc, self.summ(pc) + add);
            } else {
                let s = self.alloc_units(1);
                if s == 0 {
                    self.restart_after_failure();
                    return;
                }
                self.copy_state(s, Self::one_state(pc));
                self.set_stats(pc, s);
                let f = self.freq(s);
                self.set_freq(s, if f < MAX_FREQ / 4 - 1 { f * 2 } else { MAX_FREQ - 4 });
                self.set_summ(pc, self.freq(s) + self.init_esc + (ns > 3) as u32);
            }
            let mut cf = 2 * fs_freq * (self.summ(pc) + 6);
            let sf = s0 + self.summ(pc);
            if cf < 6 * sf {
                cf = 1 + (cf > sf) as u32 + (cf >= 4 * sf) as u32;
                self.set_summ(pc, self.summ(pc) + 3);
            } else {
                cf = 4 + (cf >= 9 * sf) as u32 + (cf >= 12 * sf) as u32 + (cf >= 15 * sf) as u32;
                self.set_summ(pc, self.summ(pc) + cf);
            }
            let s = self.stats(pc) + ns1 * 6;
            self.set_succ(s, successor);
            self.mem[s as usize] = fs_sym as u8;
            self.mem[s as usize + 1] = cf as u8;
            self.set_num_stats(pc, ns1 + 1);
            pc = self.suffix(pc);
        }
        self.max_ctx = fs_succ;
        self.min_ctx = fs_succ;
    }

    fn restart_after_failure(&mut self) {
        self.restart_model();
        self.esc_count = 0;
    }

    /// Decodes in a context with more than one symbol. Returns false on
    /// corrupt data.
    fn decode_symbol1(&mut self) -> bool {
        let c = self.min_ctx;
        let scale = self.summ(c);
        let mut p = self.stats(c);
        let count = self.coder.count(scale);
        if count >= scale {
            return false;
        }
        let mut hi = self.freq(p);
        if count < hi {
            self.prev_success = (2 * hi > scale) as u32;
            self.run_length += self.prev_success as i32;
            self.sub = (0, hi);
            self.found = p;
            hi += 4;
            self.set_freq(p, hi);
            self.set_summ(c, scale + 4);
            if hi > MAX_FREQ {
                self.rescale();
            }
            return true;
        }
        if self.found == 0 {
            return false;
        }
        self.prev_success = 0;
        let mut i = self.num_stats(c) - 1;
        loop {
            p += 6;
            hi += self.freq(p);
            if hi > count {
                break;
            }
            i -= 1;
            if i == 0 {
                // Escape: all symbols of this context are excluded.
                self.hi_bits_flag = self.hb2flag[self.sym(self.found) as usize] as u32;
                self.sub = (hi, scale);
                self.num_masked = self.num_stats(c);
                self.found = 0;
                let mut q = p;
                for _ in 0..self.num_masked {
                    self.char_mask[self.sym(q) as usize] = self.esc_count;
                    q = q.wrapping_sub(6);
                }
                return true;
            }
        }
        self.sub = (hi - self.freq(p), hi);
        // Symbol found after the first one.
        self.found = p;
        self.set_freq(p, self.freq(p) + 4);
        self.set_summ(c, self.summ(c) + 4);
        if self.freq(p) > self.freq(p - 6) {
            self.swap_states(p, p - 6);
            self.found = p - 6;
            if self.freq(p - 6) > MAX_FREQ {
                self.rescale();
            }
        }
        true
    }

    /// Decodes in a context with one symbol: a binary decision with an
    /// adaptive probability.
    fn decode_bin_symbol(&mut self) {
        let c = self.min_ctx;
        let rs = Self::one_state(c);
        self.hi_bits_flag = self.hb2flag[self.sym(self.found) as usize] as u32;
        let suffix_ns = self.num_stats(self.suffix(c));
        let i = self.freq(rs) as usize - 1;
        let j = (self.prev_success
            + self.ns2bsindx[suffix_ns as usize - 1] as u32
            + self.hi_bits_flag
            + 2 * self.hb2flag[self.sym(rs) as usize] as u32
            + ((self.run_length >> 26) & 0x20) as u32) as usize;
        let bs = self.bin_summ[i][j] as u32;
        if self.coder.count_shift(TOT_BITS) < bs {
            self.found = rs;
            let f = self.freq(rs);
            self.set_freq(rs, f + (f < 128) as u32);
            self.sub = (0, bs);
            self.bin_summ[i][j] = (bs + INTERVAL - ((bs + 32) >> 7)) as u16;
            self.prev_success = 1;
            self.run_length += 1;
        } else {
            self.sub = (bs, BIN_SCALE);
            let nb = (bs - ((bs + 32) >> 7)) as u16;
            self.bin_summ[i][j] = nb;
            self.init_esc = EXP_ESCAPE[(nb >> 10) as usize] as u32;
            self.num_masked = 1;
            self.char_mask[self.sym(rs) as usize] = self.esc_count;
            self.prev_success = 0;
            self.found = 0;
        }
    }

    fn make_esc_freq(&mut self, diff: u32) -> (SeeRef, u32) {
        let c = self.min_ctx;
        let ns = self.num_stats(c);
        if ns != 256 {
            let i = self.ns2indx[diff as usize - 1] as usize;
            let suffix_ns = self.num_stats(self.suffix(c)) as i32;
            let j = ((diff as i32) < suffix_ns - ns as i32) as usize
                + 2 * (self.summ(c) < 11 * ns) as usize
                + 4 * (self.num_masked > diff) as usize
                + self.hi_bits_flag as usize;
            let scale = self.see[i][j].mean();
            (SeeRef::At(i, j), scale)
        } else {
            (SeeRef::Dummy, 1)
        }
    }

    fn see_mut(&mut self, r: SeeRef) -> &mut See {
        match r {
            SeeRef::Dummy => &mut self.dummy_see,
            SeeRef::At(i, j) => &mut self.see[i][j],
        }
    }

    /// Decodes after an escape, excluding symbols seen in higher orders.
    fn decode_symbol2(&mut self) -> bool {
        let c = self.min_ctx;
        let ns = self.num_stats(c);
        let diff = ns - self.num_masked;
        let (see, esc) = self.make_esc_freq(diff);
        let mut ps = [0u32; 256];
        let mut p = self.stats(c).wrapping_sub(6);
        let mut hi = 0;
        for slot in ps.iter_mut().take(diff as usize) {
            loop {
                p = p.wrapping_add(6);
                if self.char_mask[self.sym(p) as usize] != self.esc_count {
                    break;
                }
            }
            hi += self.freq(p);
            *slot = p;
        }
        let scale = esc + hi;
        let count = self.coder.count(scale);
        if count >= scale {
            return false;
        }
        if count < hi {
            let mut k = 0;
            let mut h = self.freq(ps[0]);
            while h <= count {
                k += 1;
                h += self.freq(ps[k]);
            }
            let p = ps[k];
            self.sub = (h - self.freq(p), h);
            self.see_mut(see).update();
            self.found = p;
            self.set_freq(p, self.freq(p) + 4);
            self.set_summ(c, self.summ(c) + 4);
            if self.freq(p) > MAX_FREQ {
                self.rescale();
            }
            self.esc_count = self.esc_count.wrapping_add(1);
            self.run_length = self.init_rl;
        } else {
            self.sub = (hi, scale);
            for &q in &ps[..diff as usize] {
                self.char_mask[self.sym(q) as usize] = self.esc_count;
            }
            let s = self.see_mut(see);
            s.summ = s.summ.wrapping_add(scale as u16);
            self.num_masked = ns;
        }
        true
    }

    fn ctx_ok(&self, c: u32) -> bool {
        c > self.text && c <= self.heap_end
    }

    /// Reads PPMd block parameters and starts the range decoder. `esc` is
    /// the escape byte, updated if the block sets one.
    pub fn decode_init(&mut self, esc: &mut i32, rd: &mut impl ByteReader) -> bool {
        let flags = rd.byte() as i32;
        let reset = flags & 0x20 != 0;
        let mut max_mb = 0;
        if reset {
            max_mb = rd.byte() as u32;
        } else if self.size == 0 {
            return false;
        }
        if flags & 0x40 != 0 {
            *esc = rd.byte() as i32;
        }
        self.coder.init(rd);
        if reset {
            let mut order = (flags & 0x1f) + 1;
            if order > 16 {
                order = 16 + (order - 16) * 3;
            }
            if order == 1 {
                self.stop_alloc();
                return false;
            }
            self.start_alloc(max_mb + 1);
            self.start_model(order);
        }
        self.min_ctx != 0
    }

    /// Next decoded byte, or -1 on corrupt data.
    pub fn decode_char(&mut self, rd: &mut impl ByteReader) -> i32 {
        if self.mem.is_empty() || !self.ctx_ok(self.min_ctx) {
            return -1;
        }
        if self.num_stats(self.min_ctx) != 1 {
            let s = self.stats(self.min_ctx);
            if !self.ctx_ok(s) || !self.decode_symbol1() {
                return -1;
            }
        } else {
            self.decode_bin_symbol();
        }
        self.coder.decode(self.sub.0, self.sub.1);
        while self.found == 0 {
            self.coder.normalize(rd);
            loop {
                self.order_fall += 1;
                self.min_ctx = self.suffix(self.min_ctx);
                if !self.ctx_ok(self.min_ctx) {
                    return -1;
                }
                if self.num_stats(self.min_ctx) != self.num_masked {
                    break;
                }
            }
            if !self.decode_symbol2() {
                return -1;
            }
            self.coder.decode(self.sub.0, self.sub.1);
        }
        let symbol = self.sym(self.found) as i32;
        let succ = self.succ(self.found);
        if self.order_fall == 0 && succ > self.text {
            self.min_ctx = succ;
            self.max_ctx = succ;
        } else {
            self.update_model();
            if self.esc_count == 0 {
                self.clear_mask();
            }
        }
        self.coder.normalize(rd);
        symbol
    }

    /// Drops the model after an error, leaving a minimal one so a later
    /// block without reset fails cleanly.
    pub fn clean_up(&mut self) {
        self.stop_alloc();
        self.start_alloc(1);
        self.start_model(2);
    }
}
