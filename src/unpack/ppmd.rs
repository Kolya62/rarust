// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! PPMd variant H decoder used by RAR 3.x. The suballocator heap is a byte
//! array and model pointers are 32-bit offsets in it. Structures use a
//! 12 byte unit layout:
//!   context: NumStats u16, SummFreq u16 | OneState, Stats u32, Suffix u32
//!   state:   Symbol u8, Freq u8, Successor u32

const UNIT_SIZE: u32 = 12;
const FIXED_UNIT_SIZE: u32 = 12;
const N1: usize = 4;
const N2: usize = 4;
const N3: usize = 4;
const N4: usize = (128 + 3 - N1 - 2 * N2 - 3 * N3) / 4;
const N_INDEXES: usize = N1 + N2 + N3 + N4;
const STATE_SIZE: u32 = 6;

// Offset 0 is NULL, [12..24) is a sentinel list head used when gluing.
const S0: u32 = 12;
const HEAP_BASE: u32 = 24;

const INT_BITS: u32 = 7;
const PERIOD_BITS: u32 = 7;
const TOT_BITS: u32 = INT_BITS + PERIOD_BITS;
const INTERVAL: u32 = 1 << INT_BITS;
const BIN_SCALE: u32 = 1 << TOT_BITS;
const MAX_FREQ: u32 = 124;
const MAX_O: usize = 64;
const TOP: u32 = 1 << 24;
const BOT: u32 = 1 << 15;

struct SubAllocator {
    size: u32,
    indx2units: [u8; N_INDEXES],
    units2indx: [u8; 128],
    glue_count: u8,
    heap: Vec<u8>,
    heap_start: u32,
    lo_unit: u32,
    hi_unit: u32,
    free_list: [u32; N_INDEXES],
    p_text: u32,
    units_start: u32,
    heap_end: u32,
    fake_units_start: u32,
}

impl Default for SubAllocator {
    fn default() -> Self {
        SubAllocator {
            size: 0,
            indx2units: [0; N_INDEXES],
            units2indx: [0; 128],
            glue_count: 0,
            heap: Vec::new(),
            heap_start: 0,
            lo_unit: 0,
            hi_unit: 0,
            free_list: [0; N_INDEXES],
            p_text: 0,
            units_start: 0,
            heap_end: 0,
            fake_units_start: 0,
        }
    }
}

impl SubAllocator {
    #[inline(always)]
    fn u8_(&self, p: u32) -> u8 {
        self.heap.get(p as usize).copied().unwrap_or(0)
    }
    #[inline(always)]
    fn set_u8(&mut self, p: u32, v: u8) {
        if let Some(b) = self.heap.get_mut(p as usize) {
            *b = v;
        }
    }
    #[inline(always)]
    fn u16_(&self, p: u32) -> u16 {
        match self.heap.get(p as usize..p as usize + 2) {
            Some(s) => u16::from_le_bytes([s[0], s[1]]),
            None => 0,
        }
    }
    #[inline(always)]
    fn set_u16(&mut self, p: u32, v: u16) {
        if let Some(s) = self.heap.get_mut(p as usize..p as usize + 2) {
            s.copy_from_slice(&v.to_le_bytes());
        }
    }
    #[inline(always)]
    fn u32_(&self, p: u32) -> u32 {
        match self.heap.get(p as usize..p as usize + 4) {
            Some(s) => u32::from_le_bytes([s[0], s[1], s[2], s[3]]),
            None => 0,
        }
    }
    #[inline(always)]
    fn set_u32(&mut self, p: u32, v: u32) {
        if let Some(s) = self.heap.get_mut(p as usize..p as usize + 4) {
            s.copy_from_slice(&v.to_le_bytes());
        }
    }
    fn copy(&mut self, dst: u32, src: u32, n: u32) {
        let (d, s, n) = (dst as usize, src as usize, n as usize);
        if s + n <= self.heap.len() && d + n <= self.heap.len() {
            self.heap.copy_within(s..s + n, d);
        }
    }

    fn u2b(nu: u32) -> u32 {
        UNIT_SIZE * nu
    }

    fn insert_node(&mut self, p: u32, indx: usize) {
        let n = self.free_list[indx];
        self.set_u32(p, n);
        self.free_list[indx] = p;
    }

    fn remove_node(&mut self, indx: usize) -> u32 {
        let r = self.free_list[indx];
        self.free_list[indx] = self.u32_(r);
        r
    }

    fn split_block(&mut self, pv: u32, old_indx: usize, new_indx: usize) {
        let mut udiff = self.indx2units[old_indx] as u32 - self.indx2units[new_indx] as u32;
        let mut p = pv + Self::u2b(self.indx2units[new_indx] as u32);
        let mut i = self.units2indx[udiff as usize - 1] as usize;
        if self.indx2units[i] as u32 != udiff {
            i -= 1;
            self.insert_node(p, i);
            let u = self.indx2units[i] as u32;
            p += Self::u2b(u);
            udiff -= u;
        }
        let idx = self.units2indx[udiff as usize - 1] as usize;
        self.insert_node(p, idx);
    }

    fn stop(&mut self) {
        if self.size != 0 {
            self.size = 0;
            self.heap = Vec::new();
        }
    }

    fn start(&mut self, sa_size: u32) -> bool {
        let t = sa_size << 20;
        if self.size == t {
            return true;
        }
        self.stop();
        let alloc_size = t / FIXED_UNIT_SIZE * UNIT_SIZE + 2 * UNIT_SIZE;
        let total = (HEAP_BASE + alloc_size) as usize;
        let mut h: Vec<u8> = Vec::new();
        if h.try_reserve_exact(total).is_err() {
            crate::errhnd::memory_error();
        }
        h.resize(total, 0);
        self.heap = h;
        self.heap_start = HEAP_BASE;
        self.heap_end = self.heap_start + alloc_size - UNIT_SIZE;
        self.size = t;
        true
    }

    fn init(&mut self) {
        self.free_list = [0; N_INDEXES];
        self.p_text = self.heap_start;
        let size2 = FIXED_UNIT_SIZE * (self.size / 8 / FIXED_UNIT_SIZE * 7);
        let real_size2 = size2 / FIXED_UNIT_SIZE * UNIT_SIZE;
        let size1 = self.size - size2;
        let real_size1 = size1 / FIXED_UNIT_SIZE * UNIT_SIZE + UNIT_SIZE;
        self.lo_unit = self.heap_start + real_size1;
        self.units_start = self.lo_unit;
        self.fake_units_start = self.heap_start + size1;
        self.hi_unit = self.lo_unit + real_size2;
        let mut i = 0;
        let mut k = 1u32;
        while i < N1 {
            self.indx2units[i] = k as u8;
            i += 1;
            k += 1;
        }
        k += 1;
        while i < N1 + N2 {
            self.indx2units[i] = k as u8;
            i += 1;
            k += 2;
        }
        k += 1;
        while i < N1 + N2 + N3 {
            self.indx2units[i] = k as u8;
            i += 1;
            k += 3;
        }
        k += 1;
        while i < N_INDEXES {
            self.indx2units[i] = k as u8;
            i += 1;
            k += 4;
        }
        self.glue_count = 0;
        let mut i = 0usize;
        for k in 0..128usize {
            if (self.indx2units[i] as usize) < k + 1 {
                i += 1;
            }
            self.units2indx[k] = i as u8;
        }
    }

    // MEM_BLK accessors.
    fn stamp(&self, p: u32) -> u16 {
        self.u16_(p)
    }
    fn nu(&self, p: u32) -> u32 {
        self.u16_(p + 2) as u32
    }
    fn next(&self, p: u32) -> u32 {
        self.u32_(p + 4)
    }
    fn prev(&self, p: u32) -> u32 {
        self.u32_(p + 8)
    }
    fn set_next(&mut self, p: u32, v: u32) {
        self.set_u32(p + 4, v)
    }
    fn set_prev(&mut self, p: u32, v: u32) {
        self.set_u32(p + 8, v)
    }
    fn insert_at(&mut self, this: u32, p: u32) {
        self.set_prev(this, p);
        let n = self.next(p);
        self.set_next(this, n);
        self.set_prev(n, this);
        self.set_next(p, this);
    }
    fn remove_blk(&mut self, this: u32) {
        let (p, n) = (self.prev(this), self.next(this));
        self.set_next(p, n);
        self.set_prev(n, p);
    }

    fn glue_free_blocks(&mut self) {
        if self.lo_unit != self.hi_unit {
            let l = self.lo_unit;
            self.set_u8(l, 0);
        }
        self.set_next(S0, S0);
        self.set_prev(S0, S0);
        for i in 0..N_INDEXES {
            while self.free_list[i] != 0 {
                let p = self.remove_node(i);
                self.insert_at(p, S0);
                self.set_u16(p, 0xFFFF);
                let u = self.indx2units[i] as u16;
                self.set_u16(p + 2, u);
            }
        }
        let mut p = self.next(S0);
        let mut guard = 0u64;
        while p != S0 {
            loop {
                let p1 = p.wrapping_add(Self::u2b(self.nu(p)));
                if self.stamp(p1) == 0xFFFF && self.nu(p) + self.nu(p1) < 0x10000 {
                    self.remove_blk(p1);
                    let n = self.nu(p) + self.nu(p1);
                    self.set_u16(p + 2, n as u16);
                } else {
                    break;
                }
            }
            p = self.next(p);
            guard += 1;
            if guard > self.heap.len() as u64 {
                break;
            }
        }
        loop {
            let mut p = self.next(S0);
            if p == S0 || p == 0 {
                break;
            }
            self.remove_blk(p);
            let mut sz = self.nu(p);
            while sz > 128 {
                self.insert_node(p, N_INDEXES - 1);
                sz -= 128;
                p += Self::u2b(128);
            }
            if sz == 0 {
                continue;
            }
            let mut i = self.units2indx[sz as usize - 1] as usize;
            if self.indx2units[i] as u32 != sz {
                i -= 1;
                let k = sz - self.indx2units[i] as u32;
                self.insert_node(p + Self::u2b(sz - k), k as usize - 1);
            }
            self.insert_node(p, i);
        }
    }

    fn alloc_units_rare(&mut self, indx: usize) -> u32 {
        if self.glue_count == 0 {
            self.glue_count = 255;
            self.glue_free_blocks();
            if self.free_list[indx] != 0 {
                return self.remove_node(indx);
            }
        }
        let mut i = indx;
        loop {
            i += 1;
            if i == N_INDEXES {
                self.glue_count = self.glue_count.wrapping_sub(1);
                let bi = Self::u2b(self.indx2units[indx] as u32);
                let j = FIXED_UNIT_SIZE * self.indx2units[indx] as u32;
                if self.fake_units_start as i64 - self.p_text as i64 > j as i64 {
                    self.fake_units_start -= j;
                    self.units_start -= bi;
                    return self.units_start;
                }
                return 0;
            }
            if self.free_list[i] != 0 {
                break;
            }
        }
        let r = self.remove_node(i);
        self.split_block(r, i, indx);
        r
    }

    fn alloc_units(&mut self, nu: u32) -> u32 {
        let indx = self.units2indx[nu as usize - 1] as usize;
        if self.free_list[indx] != 0 {
            return self.remove_node(indx);
        }
        let r = self.lo_unit;
        self.lo_unit += Self::u2b(self.indx2units[indx] as u32);
        if self.lo_unit <= self.hi_unit {
            return r;
        }
        self.lo_unit -= Self::u2b(self.indx2units[indx] as u32);
        self.alloc_units_rare(indx)
    }

    fn alloc_context(&mut self) -> u32 {
        if self.hi_unit != self.lo_unit {
            self.hi_unit -= UNIT_SIZE;
            return self.hi_unit;
        }
        if self.free_list[0] != 0 {
            return self.remove_node(0);
        }
        self.alloc_units_rare(0)
    }

    fn expand_units(&mut self, old: u32, old_nu: u32) -> u32 {
        let i0 = self.units2indx[old_nu as usize - 1] as usize;
        let i1 = self.units2indx[old_nu as usize] as usize;
        if i0 == i1 {
            return old;
        }
        let p = self.alloc_units(old_nu + 1);
        if p != 0 {
            self.copy(p, old, Self::u2b(old_nu));
            self.insert_node(old, i0);
        }
        p
    }

    fn shrink_units(&mut self, old: u32, old_nu: u32, new_nu: u32) -> u32 {
        let i0 = self.units2indx[old_nu as usize - 1] as usize;
        let i1 = self.units2indx[new_nu as usize - 1] as usize;
        if i0 == i1 {
            return old;
        }
        if self.free_list[i1] != 0 {
            let p = self.remove_node(i1);
            self.copy(p, old, Self::u2b(new_nu));
            self.insert_node(old, i0);
            p
        } else {
            self.split_block(old, i0, i1);
            old
        }
    }

    fn free_units(&mut self, p: u32, old_nu: u32) {
        let i = self.units2indx[old_nu as usize - 1] as usize;
        self.insert_node(p, i);
    }
}

#[derive(Clone, Copy, Default)]
struct See2Context {
    summ: u16,
    shift: u8,
    count: u8,
}

impl See2Context {
    fn init(&mut self, init_val: u32) {
        self.shift = (PERIOD_BITS - 4) as u8;
        self.summ = (init_val << self.shift) as u16;
        self.count = 4;
    }
    fn get_mean(&mut self) -> u32 {
        let r = (self.summ as u32) >> self.shift;
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

#[derive(Clone, Copy, Default)]
struct State {
    symbol: u8,
    freq: u8,
    successor: u32,
}

#[derive(Default)]
struct RangeCoder {
    low: u32,
    code: u32,
    range: u32,
    low_count: u32,
    high_count: u32,
    scale: u32,
}

const DUMMY_SEE2: usize = 25 * 16;

pub struct ModelPPM {
    see2: Vec<See2Context>, // 25*16 + dummy
    min_context: u32,
    max_context: u32,
    found_state: u32,
    num_masked: i32,
    init_esc: i32,
    order_fall: i32,
    max_order: i32,
    run_length: i32,
    init_rl: i32,
    char_mask: [u8; 256],
    ns2indx: [u8; 256],
    ns2bsindx: [u8; 256],
    hb2flag: [u8; 256],
    esc_count: u8,
    prev_success: u8,
    hi_bits_flag: u8,
    bin_summ: Vec<[u16; 64]>,
    coder: RangeCoder,
    sa: SubAllocator,
    error: bool,
}

impl Default for ModelPPM {
    fn default() -> Self {
        ModelPPM {
            see2: vec![See2Context::default(); 25 * 16 + 1],
            min_context: 0,
            max_context: 0,
            found_state: 0,
            num_masked: 0,
            init_esc: 0,
            order_fall: 0,
            max_order: 0,
            run_length: 0,
            init_rl: 0,
            char_mask: [0; 256],
            ns2indx: [0; 256],
            ns2bsindx: [0; 256],
            hb2flag: [0; 256],
            esc_count: 0,
            prev_success: 0,
            hi_bits_flag: 0,
            bin_summ: vec![[0; 64]; 128],
            coder: RangeCoder::default(),
            sa: SubAllocator::default(),
            error: false,
        }
    }
}

type Reader<'a> = &'a mut dyn FnMut() -> u8;

impl ModelPPM {
    // Context accessors.
    fn ns(&self, c: u32) -> u32 {
        self.sa.u16_(c) as u32
    }
    fn set_ns(&mut self, c: u32, v: u32) {
        self.sa.set_u16(c, v as u16)
    }
    fn summ_freq(&self, c: u32) -> u32 {
        self.sa.u16_(c + 2) as u32
    }
    fn set_summ_freq(&mut self, c: u32, v: u32) {
        self.sa.set_u16(c + 2, v as u16)
    }
    fn stats(&self, c: u32) -> u32 {
        self.sa.u32_(c + 4)
    }
    fn set_stats(&mut self, c: u32, v: u32) {
        self.sa.set_u32(c + 4, v)
    }
    fn suffix(&self, c: u32) -> u32 {
        self.sa.u32_(c + 8)
    }
    fn set_suffix(&mut self, c: u32, v: u32) {
        self.sa.set_u32(c + 8, v)
    }
    fn one_state(c: u32) -> u32 {
        c + 2
    }
    // State accessors.
    fn sym(&self, s: u32) -> u32 {
        self.sa.u8_(s) as u32
    }
    fn freq(&self, s: u32) -> u32 {
        self.sa.u8_(s + 1) as u32
    }
    fn set_freq(&mut self, s: u32, v: u32) {
        self.sa.set_u8(s + 1, v as u8)
    }
    fn succ(&self, s: u32) -> u32 {
        self.sa.u32_(s + 2)
    }
    fn set_succ(&mut self, s: u32, v: u32) {
        self.sa.set_u32(s + 2, v)
    }
    fn get_state(&self, s: u32) -> State {
        State { symbol: self.sa.u8_(s), freq: self.sa.u8_(s + 1), successor: self.sa.u32_(s + 2) }
    }
    fn put_state(&mut self, s: u32, st: State) {
        self.sa.set_u8(s, st.symbol);
        self.sa.set_u8(s + 1, st.freq);
        self.sa.set_u32(s + 2, st.successor);
    }
    fn swap_states(&mut self, a: u32, b: u32) {
        let x = self.get_state(a);
        let y = self.get_state(b);
        self.put_state(a, y);
        self.put_state(b, x);
    }

    fn create_child(&mut self, ctx: u32, p_stats: u32, first: State) -> u32 {
        let pc = self.sa.alloc_context();
        if pc != 0 {
            self.set_ns(pc, 1);
            self.put_state(Self::one_state(pc), first);
            self.set_suffix(pc, ctx);
            self.set_succ(p_stats, pc);
        }
        pc
    }

    fn restart_model_rare(&mut self) {
        self.char_mask = [0; 256];
        self.sa.init();
        self.init_rl = -(if self.max_order < 12 { self.max_order } else { 12 }) - 1;
        let c = self.sa.alloc_context();
        self.min_context = c;
        self.max_context = c;
        if c == 0 {
            crate::errhnd::bad_alloc();
        }
        self.set_suffix(c, 0);
        self.order_fall = self.max_order;
        self.set_ns(c, 256);
        self.set_summ_freq(c, 257);
        let st = self.sa.alloc_units(256 / 2);
        self.found_state = st;
        self.set_stats(c, st);
        if st == 0 {
            crate::errhnd::bad_alloc();
        }
        self.run_length = self.init_rl;
        self.prev_success = 0;
        for i in 0..256u32 {
            let s = st + i * STATE_SIZE;
            self.put_state(s, State { symbol: i as u8, freq: 1, successor: 0 });
        }
        const INIT_BIN_ESC: [u32; 8] = [0x3CDD, 0x1F3F, 0x59BF, 0x48F3, 0x64A1, 0x5ABC, 0x6632, 0x6051];
        for i in 0..128usize {
            for k in 0..8usize {
                let mut m = 0;
                while m < 64 {
                    self.bin_summ[i][k + m] = (BIN_SCALE - INIT_BIN_ESC[k] / (i as u32 + 2)) as u16;
                    m += 8;
                }
            }
        }
        for i in 0..25 {
            for k in 0..16 {
                self.see2[i * 16 + k].init(5 * i as u32 + 10);
            }
        }
    }

    fn start_model_rare(&mut self, max_order: i32) {
        self.esc_count = 1;
        self.max_order = max_order;
        self.restart_model_rare();
        self.ns2bsindx[0] = 0;
        self.ns2bsindx[1] = 2;
        for x in &mut self.ns2bsindx[2..11] {
            *x = 4;
        }
        for x in &mut self.ns2bsindx[11..] {
            *x = 6;
        }
        for i in 0..3 {
            self.ns2indx[i] = i as u8;
        }
        let (mut m, mut k, mut step) = (3u32, 1u32, 1u32);
        for i in 3..256 {
            self.ns2indx[i] = m as u8;
            k -= 1;
            if k == 0 {
                step += 1;
                k = step;
                m += 1;
            }
        }
        for x in &mut self.hb2flag[..0x40] {
            *x = 0;
        }
        for x in &mut self.hb2flag[0x40..] {
            *x = 0x08;
        }
        self.see2[DUMMY_SEE2].shift = PERIOD_BITS as u8;
    }

    fn rescale(&mut self, ctx: u32) {
        let old_ns = self.ns(ctx);
        let mut i = old_ns as i32 - 1;
        let stats = self.stats(ctx);
        let mut p = self.found_state;
        while p != stats {
            if p < stats {
                break;
            }
            self.swap_states(p, p - STATE_SIZE);
            p -= STATE_SIZE;
        }
        let f = self.freq(stats) + 4;
        self.set_freq(stats, f);
        let sf = self.summ_freq(ctx) + 4;
        self.set_summ_freq(ctx, sf);
        let mut esc_freq = sf as i32 - self.freq(p) as i32;
        let adder = (self.order_fall != 0) as u32;
        let nf = (self.freq(p) + adder) >> 1;
        self.set_freq(p, nf);
        let mut summ = nf;
        loop {
            p += STATE_SIZE;
            esc_freq -= self.freq(p) as i32;
            let nf = (self.freq(p) + adder) >> 1;
            self.set_freq(p, nf);
            summ += nf;
            if self.freq(p) > self.freq(p - STATE_SIZE) {
                let tmp = self.get_state(p);
                let mut p1 = p;
                loop {
                    let prev = self.get_state(p1 - STATE_SIZE);
                    self.put_state(p1, prev);
                    p1 -= STATE_SIZE;
                    if p1 == stats || tmp.freq as u32 <= self.freq(p1 - STATE_SIZE) {
                        break;
                    }
                }
                self.put_state(p1, tmp);
            }
            i -= 1;
            if i <= 0 {
                break;
            }
        }
        self.set_summ_freq(ctx, summ);
        if self.freq(p) == 0 {
            let mut i = 0i32;
            loop {
                i += 1;
                p -= STATE_SIZE;
                if self.freq(p) != 0 || p <= stats {
                    break;
                }
            }
            esc_freq += i;
            let ns = self.ns(ctx) as i32 - i;
            self.set_ns(ctx, ns as u32);
            if ns == 1 {
                let mut tmp = self.get_state(stats);
                loop {
                    tmp.freq -= tmp.freq >> 1;
                    esc_freq >>= 1;
                    if esc_freq <= 1 {
                        break;
                    }
                }
                self.sa.free_units(stats, (old_ns + 1) >> 1);
                let os = Self::one_state(ctx);
                self.found_state = os;
                self.put_state(os, tmp);
                return;
            }
        }
        esc_freq -= esc_freq >> 1;
        let sf = self.summ_freq(ctx) as i32 + esc_freq;
        self.set_summ_freq(ctx, sf as u32);
        let n0 = (old_ns + 1) >> 1;
        let n1 = (self.ns(ctx) + 1) >> 1;
        if n0 != n1 {
            let ns = self.sa.shrink_units(stats, n0, n1);
            self.set_stats(ctx, ns);
        }
        self.found_state = self.stats(ctx);
    }

    fn create_successors(&mut self, skip: bool, p1: u32) -> u32 {
        let mut pc = self.min_context;
        let up_branch = self.succ(self.found_state);
        let mut ps: Vec<u32> = Vec::with_capacity(MAX_O);
        let mut p;
        let fs_sym = self.sym(self.found_state);
        let mut no_loop = false;
        if !skip {
            ps.push(self.found_state);
            if self.suffix(pc) == 0 {
                no_loop = true;
            }
        }
        if !no_loop {
            let mut entry = false;
            if p1 != 0 {
                p = p1;
                pc = self.suffix(pc);
                entry = true;
            } else {
                p = 0;
            }
            loop {
                if !entry {
                    pc = self.suffix(pc);
                    if pc == 0 {
                        return 0;
                    }
                    if self.ns(pc) != 1 {
                        p = self.stats(pc);
                        let mut guard = 0;
                        while self.sym(p) != fs_sym {
                            p += STATE_SIZE;
                            guard += 1;
                            if guard > 256 {
                                return 0;
                            }
                        }
                    } else {
                        p = Self::one_state(pc);
                    }
                }
                entry = false;
                if self.succ(p) != up_branch {
                    pc = self.succ(p);
                    break;
                }
                if ps.len() >= MAX_O {
                    return 0;
                }
                ps.push(p);
                if self.suffix(pc) == 0 {
                    break;
                }
            }
        }
        if ps.is_empty() {
            return pc;
        }
        let mut up = State { symbol: self.sa.u8_(up_branch), freq: 0, successor: up_branch.wrapping_add(1) };
        if self.ns(pc) != 1 {
            if pc <= self.sa.p_text {
                return 0;
            }
            let mut p = self.stats(pc);
            let mut guard = 0;
            while self.sym(p) != up.symbol as u32 {
                p += STATE_SIZE;
                guard += 1;
                if guard > 256 {
                    return 0;
                }
            }
            let cf = self.freq(p).wrapping_sub(1);
            let s0 = self.summ_freq(pc).wrapping_sub(self.ns(pc)).wrapping_sub(cf);
            up.freq = (1 + if 2 * cf <= s0 {
                (5 * cf > s0) as u32
            } else {
                (2 * cf + 3 * s0 - 1) / (2 * s0).max(1)
            }) as u8;
        } else {
            up.freq = self.freq(Self::one_state(pc)) as u8;
        }
        while let Some(s) = ps.pop() {
            pc = self.create_child(pc, s, up);
            if pc == 0 {
                return 0;
            }
        }
        pc
    }

    fn update_model(&mut self) {
        let fs = self.get_state(self.found_state);
        let mut p: u32 = 0;
        let mut pc = self.suffix(self.min_context);
        if (fs.freq as u32) < MAX_FREQ / 4 && pc != 0 {
            if self.ns(pc) != 1 {
                p = self.stats(pc);
                if self.sym(p) != fs.symbol as u32 {
                    let mut guard = 0;
                    loop {
                        p += STATE_SIZE;
                        guard += 1;
                        if self.sym(p) == fs.symbol as u32 || guard > 256 {
                            break;
                        }
                    }
                    if self.freq(p) >= self.freq(p - STATE_SIZE) {
                        self.swap_states(p, p - STATE_SIZE);
                        p -= STATE_SIZE;
                    }
                }
                if self.freq(p) < MAX_FREQ - 9 {
                    let f = self.freq(p) + 2;
                    self.set_freq(p, f);
                    let s = self.summ_freq(pc) + 2;
                    self.set_summ_freq(pc, s);
                }
            } else {
                p = Self::one_state(pc);
                let f = self.freq(p);
                self.set_freq(p, f + (f < 32) as u32);
            }
        }
        if self.order_fall == 0 {
            let s = self.create_successors(true, p);
            self.min_context = s;
            self.max_context = s;
            let fsp = self.found_state;
            self.set_succ(fsp, s);
            if s == 0 {
                self.restart();
            }
            return;
        }
        let pt = self.sa.p_text;
        self.sa.set_u8(pt, fs.symbol);
        self.sa.p_text += 1;
        let mut successor = self.sa.p_text;
        if self.sa.p_text >= self.sa.fake_units_start {
            self.restart();
            return;
        }
        let mut fs_succ = fs.successor;
        if fs_succ != 0 {
            if fs_succ <= self.sa.p_text {
                fs_succ = self.create_successors(false, p);
                if fs_succ == 0 {
                    self.restart();
                    return;
                }
            }
            self.order_fall -= 1;
            if self.order_fall == 0 {
                successor = fs_succ;
                if self.max_context != self.min_context {
                    self.sa.p_text -= 1;
                }
            }
        } else {
            let fsp = self.found_state;
            self.set_succ(fsp, successor);
            fs_succ = self.min_context;
        }
        let ns = self.ns(self.min_context);
        let s0 = self.summ_freq(self.min_context).wrapping_sub(ns).wrapping_sub(fs.freq as u32 - 1);
        pc = self.max_context;
        while pc != self.min_context {
            let mut ns1 = self.ns(pc);
            if ns1 != 1 {
                if ns1 & 1 == 0 {
                    let st = self.sa.expand_units(self.stats(pc), ns1 >> 1);
                    self.set_stats(pc, st);
                    if st == 0 {
                        self.restart();
                        return;
                    }
                }
                let sf = self.summ_freq(pc);
                let add = (2 * ns1 < ns) as u32 + 2 * ((4 * ns1 <= ns) as u32 & (sf <= 8 * ns1) as u32);
                self.set_summ_freq(pc, sf + add);
            } else {
                let p = self.sa.alloc_units(1);
                if p == 0 {
                    self.restart();
                    return;
                }
                let os = self.get_state(Self::one_state(pc));
                self.put_state(p, os);
                self.set_stats(pc, p);
                let f = self.freq(p);
                if f < MAX_FREQ / 4 - 1 {
                    self.set_freq(p, f + f);
                } else {
                    self.set_freq(p, MAX_FREQ - 4);
                }
                let sf = self.freq(p) as i32 + self.init_esc + (ns > 3) as i32;
                self.set_summ_freq(pc, sf as u32);
            }
            let mut cf = 2 * fs.freq as u32 * (self.summ_freq(pc) + 6);
            let sf = s0.wrapping_add(self.summ_freq(pc));
            if cf < 6 * sf {
                cf = 1 + (cf > sf) as u32 + (cf >= 4 * sf) as u32;
                let s = self.summ_freq(pc) + 3;
                self.set_summ_freq(pc, s);
            } else {
                cf = 4 + (cf >= 9 * sf) as u32 + (cf >= 12 * sf) as u32 + (cf >= 15 * sf) as u32;
                let s = self.summ_freq(pc) + cf;
                self.set_summ_freq(pc, s);
            }
            let p = self.stats(pc) + ns1 * STATE_SIZE;
            self.put_state(p, State { symbol: fs.symbol, freq: cf as u8, successor });
            ns1 += 1;
            self.set_ns(pc, ns1);
            pc = self.suffix(pc);
            if pc == 0 {
                break;
            }
        }
        self.max_context = fs_succ;
        self.min_context = fs_succ;
    }

    fn restart(&mut self) {
        self.restart_model_rare();
        self.esc_count = 0;
    }

    fn get_mean(summ: u32, shift: u32, round: u32) -> u32 {
        (summ + (1 << (shift - round))) >> shift
    }

    fn decode_bin_symbol(&mut self, ctx: u32) {
        let rs = Self::one_state(ctx);
        self.hi_bits_flag = self.hb2flag[self.sym(self.found_state) as usize & 0xff];
        let rs_freq = self.freq(rs);
        let suffix_ns = self.ns(self.suffix(ctx));
        let i1 = (rs_freq.wrapping_sub(1) & 127) as usize;
        let i2 = (self.prev_success as u32
            + self.ns2bsindx[(suffix_ns.wrapping_sub(1) & 0xff) as usize] as u32
            + self.hi_bits_flag as u32
            + 2 * self.hb2flag[self.sym(rs) as usize] as u32
            + ((self.run_length >> 26) & 0x20) as u32) as usize
            & 63;
        let bs = self.bin_summ[i1][i2] as u32;
        self.coder.range >>= TOT_BITS;
        let count = self.coder.code.wrapping_sub(self.coder.low).checked_div(self.coder.range).unwrap_or(u32::MAX);
        if count < bs {
            self.found_state = rs;
            self.set_freq(rs, rs_freq + (rs_freq < 128) as u32);
            self.coder.low_count = 0;
            self.coder.high_count = bs;
            self.bin_summ[i1][i2] = (bs + INTERVAL - Self::get_mean(bs, PERIOD_BITS, 2)) as u16;
            self.prev_success = 1;
            self.run_length += 1;
        } else {
            self.coder.low_count = bs;
            let nbs = (bs.wrapping_sub(Self::get_mean(bs, PERIOD_BITS, 2))) as u16;
            self.bin_summ[i1][i2] = nbs;
            self.coder.high_count = BIN_SCALE;
            const EXP_ESCAPE: [u8; 16] = [25, 14, 9, 7, 5, 5, 4, 4, 4, 3, 3, 3, 2, 2, 2, 2];
            self.init_esc = EXP_ESCAPE[(nbs >> 10) as usize & 15] as i32;
            self.num_masked = 1;
            self.char_mask[self.sym(rs) as usize] = self.esc_count;
            self.prev_success = 0;
            self.found_state = 0;
        }
    }

    fn update1(&mut self, ctx: u32, p: u32) {
        self.found_state = p;
        let f = self.freq(p) + 4;
        self.set_freq(p, f);
        let s = self.summ_freq(ctx) + 4;
        self.set_summ_freq(ctx, s);
        if self.freq(p) > self.freq(p - STATE_SIZE) {
            self.swap_states(p, p - STATE_SIZE);
            self.found_state = p - STATE_SIZE;
            if self.freq(p - STATE_SIZE) > MAX_FREQ {
                self.rescale(ctx);
            }
        }
    }

    fn current_count(&mut self) -> i32 {
        if self.coder.scale == 0 {
            self.error = true;
            return i32::MAX;
        }
        self.coder.range /= self.coder.scale;
        if self.coder.range == 0 {
            self.error = true;
            return i32::MAX;
        }
        (self.coder.code.wrapping_sub(self.coder.low) / self.coder.range) as i32
    }

    fn decode_symbol1(&mut self, ctx: u32) -> bool {
        self.coder.scale = self.summ_freq(ctx);
        let mut p = self.stats(ctx);
        let count = self.current_count();
        if count >= self.coder.scale as i32 {
            return false;
        }
        let mut hi_cnt = self.freq(p) as i32;
        if count < hi_cnt {
            self.coder.high_count = hi_cnt as u32;
            self.prev_success = (2 * hi_cnt as u32 > self.coder.scale) as u8;
            self.run_length += self.prev_success as i32;
            self.found_state = p;
            hi_cnt += 4;
            self.set_freq(p, hi_cnt as u32);
            let s = self.summ_freq(ctx) + 4;
            self.set_summ_freq(ctx, s);
            if hi_cnt as u32 > MAX_FREQ {
                self.rescale(ctx);
            }
            self.coder.low_count = 0;
            return true;
        } else if self.found_state == 0 {
            return false;
        }
        self.prev_success = 0;
        let mut i = self.ns(ctx) as i32 - 1;
        loop {
            p += STATE_SIZE;
            hi_cnt += self.freq(p) as i32;
            if hi_cnt > count {
                break;
            }
            i -= 1;
            if i <= 0 {
                self.hi_bits_flag = self.hb2flag[self.sym(self.found_state) as usize];
                self.coder.low_count = hi_cnt as u32;
                self.char_mask[self.sym(p) as usize] = self.esc_count;
                self.num_masked = self.ns(ctx) as i32;
                let mut i = self.num_masked - 1;
                self.found_state = 0;
                while i > 0 {
                    p -= STATE_SIZE;
                    self.char_mask[self.sym(p) as usize] = self.esc_count;
                    i -= 1;
                }
                self.coder.high_count = self.coder.scale;
                return true;
            }
        }
        self.coder.high_count = hi_cnt as u32;
        self.coder.low_count = (hi_cnt - self.freq(p) as i32) as u32;
        self.update1(ctx, p);
        true
    }

    fn update2(&mut self, ctx: u32, p: u32) {
        self.found_state = p;
        let f = self.freq(p) + 4;
        self.set_freq(p, f);
        let s = self.summ_freq(ctx) + 4;
        self.set_summ_freq(ctx, s);
        if f > MAX_FREQ {
            self.rescale(ctx);
        }
        self.esc_count = self.esc_count.wrapping_add(1);
        self.run_length = self.init_rl;
    }

    fn make_esc_freq2(&mut self, ctx: u32, diff: i32) -> usize {
        let ns = self.ns(ctx);
        if ns != 256 {
            let idx = self.ns2indx[(diff - 1).clamp(0, 255) as usize] as usize * 16
                + (diff < self.ns(self.suffix(ctx)) as i32 - ns as i32) as usize
                + 2 * (self.summ_freq(ctx) < 11 * ns) as usize
                + 4 * (self.num_masked > diff) as usize
                + self.hi_bits_flag as usize;
            let idx = idx.min(DUMMY_SEE2 - 1);
            self.coder.scale = self.see2[idx].get_mean();
            idx
        } else {
            self.coder.scale = 1;
            DUMMY_SEE2
        }
    }

    fn decode_symbol2(&mut self, ctx: u32) -> bool {
        let ns = self.ns(ctx) as i32;
        if self.num_masked > ns {
            return false;
        }
        let mut i = ns - self.num_masked;
        let psee2c = self.make_esc_freq2(ctx, i);
        let mut ps: Vec<u32> = Vec::with_capacity(256);
        let stats = self.stats(ctx);
        let end = stats + ns as u32 * STATE_SIZE;
        let mut p = stats.wrapping_sub(STATE_SIZE);
        let mut hi_cnt: i32 = 0;
        loop {
            loop {
                p = p.wrapping_add(STATE_SIZE);
                if p >= end {
                    return false;
                }
                if self.char_mask[self.sym(p) as usize] != self.esc_count {
                    break;
                }
            }
            hi_cnt += self.freq(p) as i32;
            if ps.len() >= 256 {
                return false;
            }
            ps.push(p);
            i -= 1;
            if i <= 0 {
                break;
            }
        }
        self.coder.scale = self.coder.scale.wrapping_add(hi_cnt as u32);
        let count = self.current_count();
        if count >= self.coder.scale as i32 {
            return false;
        }
        let mut k = 0;
        p = ps[0];
        if count < hi_cnt {
            hi_cnt = 0;
            loop {
                hi_cnt += self.freq(p) as i32;
                if hi_cnt > count {
                    break;
                }
                k += 1;
                if k >= ps.len() {
                    return false;
                }
                p = ps[k];
            }
            self.coder.high_count = hi_cnt as u32;
            self.coder.low_count = (hi_cnt - self.freq(p) as i32) as u32;
            self.see2[psee2c].update();
            self.update2(ctx, p);
        } else {
            self.coder.low_count = hi_cnt as u32;
            self.coder.high_count = self.coder.scale;
            let n = (ns - self.num_masked) as usize;
            for &q in ps.iter().take(n) {
                self.char_mask[self.sym(q) as usize] = self.esc_count;
            }
            let sc = self.coder.scale as u16;
            self.see2[psee2c].summ = self.see2[psee2c].summ.wrapping_add(sc);
            self.num_masked = ns;
        }
        true
    }

    fn clear_mask(&mut self) {
        self.esc_count = 1;
        self.char_mask = [0; 256];
    }

    /// Reset PPM variables after data error.
    pub fn clean_up(&mut self) {
        self.sa.stop();
        self.sa.start(1);
        self.start_model_rare(2);
    }

    fn init_decoder(&mut self, rd: Reader) {
        self.coder.low = 0;
        self.coder.code = 0;
        self.coder.range = 0xffffffff;
        for _ in 0..4 {
            self.coder.code = (self.coder.code << 8) | rd() as u32;
        }
    }

    pub fn decode_init(&mut self, esc_char: &mut i32, rd: Reader) -> bool {
        let mut max_order = rd() as i32;
        let reset = max_order & 0x20 != 0;
        let mut max_mb = 0;
        if reset {
            max_mb = rd() as u32;
        } else if self.sa.size == 0 {
            return false;
        }
        if max_order & 0x40 != 0 {
            *esc_char = rd() as i32;
        }
        self.init_decoder(rd);
        if reset {
            max_order = (max_order & 0x1f) + 1;
            if max_order > 16 {
                max_order = 16 + (max_order - 16) * 3;
            }
            if max_order == 1 {
                self.sa.stop();
                return false;
            }
            self.sa.start(max_mb + 1);
            self.start_model_rare(max_order);
        }
        self.min_context != 0
    }

    fn normalize(&mut self, rd: Reader) {
        let mut guard = 0;
        loop {
            let c = &mut self.coder;
            if (c.low ^ c.low.wrapping_add(c.range)) >= TOP {
                if c.range < BOT {
                    c.range = c.low.wrapping_neg() & (BOT - 1);
                } else {
                    break;
                }
            }
            c.code = (c.code << 8) | rd() as u32;
            c.range <<= 8;
            c.low <<= 8;
            guard += 1;
            if guard > 8 {
                self.error = true;
                break;
            }
        }
    }

    fn decode(&mut self) {
        let c = &mut self.coder;
        c.low = c.low.wrapping_add(c.range.wrapping_mul(c.low_count));
        c.range = c.range.wrapping_mul(c.high_count.wrapping_sub(c.low_count));
    }

    fn ctx_valid(&self, c: u32) -> bool {
        !(c <= self.sa.p_text || c > self.sa.heap_end)
    }

    /// Decode a character. Returns -1 on error.
    pub fn decode_char(&mut self, rd: Reader) -> i32 {
        self.error = false;
        if !self.ctx_valid(self.min_context) {
            return -1;
        }
        let mc = self.min_context;
        if self.ns(mc) != 1 {
            let st = self.stats(mc);
            if st <= self.sa.p_text || st > self.sa.heap_end {
                return -1;
            }
            if !self.decode_symbol1(mc) {
                return -1;
            }
        } else {
            self.decode_bin_symbol(mc);
        }
        self.decode();
        while self.found_state == 0 {
            self.normalize(rd);
            loop {
                self.order_fall += 1;
                self.min_context = self.suffix(self.min_context);
                if !self.ctx_valid(self.min_context) {
                    return -1;
                }
                if self.ns(self.min_context) as i32 != self.num_masked {
                    break;
                }
            }
            let mc = self.min_context;
            if !self.decode_symbol2(mc) {
                return -1;
            }
            self.decode();
            if self.error {
                return -1;
            }
        }
        let symbol = self.sym(self.found_state) as i32;
        let succ = self.succ(self.found_state);
        if self.order_fall == 0 && succ > self.sa.p_text {
            self.min_context = succ;
            self.max_context = succ;
        } else {
            self.update_model();
            if self.esc_count == 0 {
                self.clear_mask();
            }
        }
        self.normalize(rd);
        if self.error {
            return -1;
        }
        symbol
    }
}
