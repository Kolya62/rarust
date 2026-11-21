// SPDX-License-Identifier: GPL-3.0-or-later

//! Development tool: decodes raw packed streams from stdin.
//!
//! `unpack_stream METHOD [DICT]` reads frames of
//! `packed_size: u64 LE, unpacked_size: i64 LE, packed bytes` and decodes
//! them as consecutive files of a solid stream (the first frame starts
//! non-solid). For every frame it writes `output_size: u64 LE, output`.
//! THREADS sets the decoder thread count.

use rarust::unpack::{Unpack, UnpackIo};
use std::io::{Read, Write};

struct Io<'a> {
    src: &'a [u8],
    out: Vec<u8>,
}

impl UnpackIo for Io<'_> {
    fn unp_read(&mut self, buf: &mut [u8]) -> i32 {
        let n = buf.len().min(self.src.len());
        buf[..n].copy_from_slice(&self.src[..n]);
        self.src = &self.src[n..];
        n as i32
    }
    fn unp_write(&mut self, data: &[u8]) {
        self.out.extend_from_slice(data);
    }
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let method: u32 = a[1].parse().unwrap();
    let dict: u64 = a.get(2).map_or(0x400000, |s| s.parse().unwrap());
    let mut input = Vec::new();
    std::io::stdin().read_to_end(&mut input).unwrap();
    let mut u = Unpack::new();
    u.set_threads(std::env::var("THREADS").map_or(1, |t| t.parse().unwrap()));
    let mut stdout = std::io::stdout();
    let mut rest = &input[..];
    let mut first = true;
    while rest.len() >= 16 {
        let packed = u64::from_le_bytes(rest[..8].try_into().unwrap()) as usize;
        let size = i64::from_le_bytes(rest[8..16].try_into().unwrap());
        let data = &rest[16..(16 + packed).min(rest.len())];
        rest = &rest[(16 + packed).min(rest.len())..];
        let solid = !first;
        first = false;
        u.init(dict, solid).unwrap();
        u.set_dest_size(size);
        let mut io = Io { src: data, out: Vec::new() };
        u.do_unpack(method, solid, &mut io);
        stdout.write_all(&(io.out.len() as u64).to_le_bytes()).unwrap();
        stdout.write_all(&io.out).unwrap();
    }
}
