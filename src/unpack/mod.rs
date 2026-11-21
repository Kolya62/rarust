// SPDX-License-Identifier: GPL-3.0-or-later

//! Decompression of all RAR formats. `Unpack` owns the dictionary and
//! dispatches to the decoder of each format:
//!
//! - `rar15`: RAR 1.5 (method 15, also used for RAR 1.4 data)
//! - `rar2`: RAR 2.x (methods 20 and 26)
//! - `rar3`: RAR 3.x (method 29), with `ppm` for PPMd blocks
//! - `rar5`: RAR 5.0 and 7.0 (methods 50 and 70)
//!
//! The decoders of the older formats share one LZ window, so a solid
//! stream can continue across files of different methods.

mod bitstream;
mod huffman;
mod ppm;
mod rar15;
mod rar2;
mod rar3;
mod rar5;

/// Source of packed data and destination of unpacked data.
pub trait UnpackIo {
    /// Read packed data. Returns number of bytes read, 0 at end or -1 on error.
    fn unp_read(&mut self, buf: &mut [u8]) -> i32;
    /// Write unpacked data.
    fn unp_write(&mut self, data: &[u8]);
}

/// Largest dictionary accepted (RAR 7 allows up to 1 TB; 64 GB here).
const MAX_DICT: u64 = 0x10_0000_0000;
const MIN_DICT: u64 = 0x40000;

#[derive(Debug)]
pub struct AllocError;

/// Allocates a zero filled buffer, reporting failure instead of aborting.
/// Pages are mapped by the system only when they are first written.
pub(crate) fn alloc_zeroed(size: usize) -> Result<Vec<u8>, AllocError> {
    let mut probe: Vec<u8> = Vec::new();
    probe.try_reserve_exact(size).map_err(|_| AllocError)?;
    drop(probe);
    Ok(vec![0u8; size])
}

pub struct Unpack {
    window: Vec<u8>,
    alloc_win_size: u64,
    max_win_size: usize,
    max_win_mask: usize,
    /// Shared LZ window state of the RAR 1.5-3.x decoders: decode and
    /// write positions, the previous decode position (to notice wrapping)
    /// and whether the window has wrapped at least once.
    unp_ptr: usize,
    wr_ptr: usize,
    prev_ptr: usize,
    first_win_done: bool,
    dest_unp_size: i64,
    written_file_size: i64,
    file_extracted: bool,
    max_user_threads: u32,
    stream: bitstream::StreamBits,
    rar15: Box<rar15::Rar15>,
    rar2: Box<rar2::Rar2>,
    rar3: Box<rar3::Rar3>,
    rar5: rar5::Rar5,
}

impl Default for Unpack {
    fn default() -> Self {
        Self::new()
    }
}

impl Unpack {
    pub fn new() -> Self {
        Unpack {
            window: Vec::new(),
            alloc_win_size: 0,
            max_win_size: 0,
            max_win_mask: 0,
            unp_ptr: 0,
            wr_ptr: 0,
            prev_ptr: 0,
            first_win_done: false,
            dest_unp_size: 0,
            written_file_size: 0,
            file_extracted: false,
            max_user_threads: 1,
            stream: bitstream::StreamBits::default(),
            rar15: Box::default(),
            rar2: Box::default(),
            rar3: Box::default(),
            rar5: rar5::Rar5::default(),
        }
    }

    /// Prepares the dictionary. A solid stream keeps the existing one, so
    /// it cannot grow.
    pub fn init(&mut self, win_size: u64, solid: bool) -> Result<(), AllocError> {
        let win_size = win_size.max(MIN_DICT);
        if win_size > MAX_DICT || win_size > usize::MAX as u64 / 2 {
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
        self.window = alloc_zeroed(win_size as usize)?;
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

    pub fn set_threads(&mut self, threads: u32) {
        self.max_user_threads = threads.clamp(1, 8);
    }

    pub fn do_unpack(&mut self, method: u32, solid: bool, io: &mut dyn UnpackIo) {
        if self.window.is_empty() {
            return;
        }
        match method {
            15 => self.unpack_rar15(solid, io),
            20 | 26 => self.unpack_rar2(solid, io),
            29 => self.unpack_rar3(solid, io),
            50 | 70 => {
                let mut win = std::mem::take(&mut self.window);
                let n = self.max_win_size.min(win.len());
                let threads = self.max_user_threads as usize;
                self.rar5.unpack(&mut win[..n], solid, method == 70, threads, self.dest_unp_size, io);
                self.window = win;
            }
            _ => return,
        }
        self.file_extracted = true;
    }

    /// Starts a file in the shared LZ window of the RAR 1.5-3.x decoders.
    fn lz_start(&mut self, solid: bool) {
        if !solid {
            self.unp_ptr = 0;
            self.wr_ptr = 0;
            self.prev_ptr = 0;
            self.first_win_done = false;
        }
        self.written_file_size = 0;
    }

    fn lz_track_wrap(&mut self) {
        self.first_win_done |= self.prev_ptr > self.unp_ptr;
        self.prev_ptr = self.unp_ptr;
    }

    #[inline(always)]
    fn lz_put(&mut self, b: u8) {
        self.window[self.unp_ptr] = b;
        self.unp_ptr = (self.unp_ptr + 1) & self.max_win_mask;
    }

    /// Copies a match. A distance reaching before the start of the data
    /// (or beyond the window) produces zeros.
    #[inline(always)]
    fn lz_copy(&mut self, len: u32, dist: usize) {
        let len = len as usize;
        let mask = self.max_win_mask;
        let dst = self.unp_ptr;
        if dist > dst && (dist > self.max_win_size || !self.first_win_done) {
            for i in 0..len {
                self.window[(dst + i) & mask] = 0;
            }
        } else {
            let src = dst.wrapping_sub(dist) & mask;
            if dist >= len && src + len <= self.max_win_size && dst + len <= self.max_win_size {
                self.window.copy_within(src..src + len, dst);
            } else {
                for i in 0..len {
                    self.window[(dst + i) & mask] = self.window[(src + i) & mask];
                }
            }
        }
        self.unp_ptr = (dst + len) & mask;
    }

    /// Writes the decoded part of the window when it is nearly full, so the
    /// next match cannot overwrite unwritten data.
    #[inline(always)]
    fn lz_flush_if_full(&mut self, io: &mut dyn UnpackIo) {
        if (self.unp_ptr.wrapping_sub(self.wr_ptr) & self.max_win_mask) + 0x1000 >= self.max_win_size {
            self.lz_flush(io);
        }
    }

    fn lz_flush(&mut self, io: &mut dyn UnpackIo) {
        if self.unp_ptr < self.wr_ptr {
            io.unp_write(&self.window[self.wr_ptr..self.max_win_size]);
            io.unp_write(&self.window[..self.unp_ptr]);
        } else {
            io.unp_write(&self.window[self.wr_ptr..self.unp_ptr]);
        }
        self.wr_ptr = self.unp_ptr;
    }

}
