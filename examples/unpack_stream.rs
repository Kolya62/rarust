// SPDX-License-Identifier: GPL-3.0-or-later

//! Development tool: decodes a raw packed stream from stdin.
//!
//! `unpack_stream METHOD SIZE [DICT] [FILES]` writes the unpacked data to
//! stdout. With FILES > 1 the input is split into that many equal parts
//! that are decoded as consecutive files of a solid archive.

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
    let size: i64 = a[2].parse().unwrap();
    let dict: u64 = a.get(3).map_or(0x400000, |s| s.parse().unwrap());
    let files: usize = a.get(4).map_or(1, |s| s.parse().unwrap());
    let mut input = Vec::new();
    std::io::stdin().read_to_end(&mut input).unwrap();
    let mut u = Unpack::new();
    u.set_threads(std::env::var("THREADS").map_or(1, |t| t.parse().unwrap()));
    let part = input.len() / files;
    let mut stdout = std::io::stdout();
    for i in 0..files {
        let solid = i > 0;
        u.init(dict, solid).unwrap();
        u.set_dest_size(size);
        let mut io = Io { src: &input[i * part..(i + 1) * part], out: Vec::new() };
        u.do_unpack(method, solid, &mut io);
        stdout.write_all(&(io.out.len() as u64).to_le_bytes()).unwrap();
        stdout.write_all(&io.out).unwrap();
    }
}
