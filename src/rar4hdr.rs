// SPDX-License-Identifier: GPL-3.0-or-later

//! Parsers for RAR 1.4 and RAR 1.5-4.x archive headers.
//!
//! A RAR 1.5-4.x header starts with
//!
//! ```text
//! crc   u16  low 16 bits of the CRC32 of the header after this field
//! type  u8   0x73 main, 0x74 file, 0x75 comment, 0x76 authenticity,
//!            0x77 old service, 0x78 recovery, 0x79 signature,
//!            0x7a service, 0x7b end of archive
//! flags u16  0x8000: a u32 data size follows the fixed part
//! size  u16  header size
//! ```
//!
//! All numbers are little endian. Missing bytes of a truncated header read
//! as zero, as damaged archives have always been handled.

/// Byte cursor that remembers how far it was read.
pub struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    pub fn new(buf: &'a [u8], pos: usize) -> Self {
        Cursor { buf, pos }
    }
    pub fn pos(&self) -> usize {
        self.pos
    }
    pub fn u8(&mut self) -> u8 {
        let b = self.buf.get(self.pos).copied().unwrap_or(0);
        self.pos += 1;
        b
    }
    pub fn u16(&mut self) -> u16 {
        u16::from_le_bytes([self.u8(), self.u8()])
    }
    pub fn u32(&mut self) -> u32 {
        u32::from_le_bytes([self.u8(), self.u8(), self.u8(), self.u8()])
    }
    pub fn bytes(&mut self, n: usize) -> Vec<u8> {
        let start = self.pos.min(self.buf.len());
        let end = self.pos.saturating_add(n).min(self.buf.len());
        self.pos = self.pos.saturating_add(n);
        self.buf[start..end].to_vec()
    }
}

/// CRC32 of `buf[2..end]`, low 16 bits.
pub fn crc16_of(buf: &[u8], end: usize) -> u32 {
    let end = end.min(buf.len());
    let data = buf.get(2..end).unwrap_or(&[]);
    (crate::hash::crc32::crc32(!0, data) ^ !0) & 0xffff
}

/// File flags.
pub const F_SPLIT_BEFORE: u32 = 0x0001;
pub const F_SPLIT_AFTER: u32 = 0x0002;
pub const F_PASSWORD: u32 = 0x0004;
pub const F_COMMENT: u32 = 0x0008;
pub const F_SOLID: u32 = 0x0010;
pub const F_DICT_MASK: u32 = 0x00e0;
pub const F_DIRECTORY: u32 = 0x00e0;
pub const F_LARGE: u32 = 0x0100;
pub const F_UNICODE: u32 = 0x0200;
pub const F_SALT: u32 = 0x0400;
pub const F_VERSION: u32 = 0x0800;
pub const F_EXTTIME: u32 = 0x1000;

/// One of the extended times of a file header. Times are DOS times with
/// optional extra precision: one more second and a fraction in 100 ns
/// units.
#[derive(Clone, Copy, Debug, Default)]
pub struct ExtTime {
    /// DOS time for creation and access time (modification time uses the
    /// main DOS time of the header).
    pub dos: Option<u32>,
    pub add_second: bool,
    /// Fraction of a second in 100 ns units.
    pub fraction: u32,
}

#[derive(Clone, Debug, Default)]
pub struct FileBlock {
    pub pack_low: u32,
    pub unp_low: u32,
    pub host_os: u8,
    pub crc32: u32,
    pub dos_time: u32,
    pub unp_ver: u8,
    pub method: u8,
    pub name_size: usize,
    pub attr: u32,
    pub pack_high: u32,
    pub unp_high: u32,
    pub name: Vec<u8>,
    /// Service data following the name of service headers.
    pub sub_data: Vec<u8>,
    pub salt: Option<[u8; 8]>,
    /// Modification, creation, access times when extended times are present.
    pub ext_times: Option<[Option<ExtTime>; 3]>,
    /// Bytes of the header consumed by the known fields.
    pub parsed_end: usize,
}

/// Parses the fields of a file or service header after the 7-byte base.
pub fn parse_file(buf: &[u8], flags: u32, head_size: usize, service: bool) -> FileBlock {
    let mut c = Cursor::new(buf, 7);
    let mut f = FileBlock {
        pack_low: c.u32(),
        unp_low: c.u32(),
        host_os: c.u8(),
        crc32: c.u32(),
        dos_time: c.u32(),
        unp_ver: c.u8(),
        method: c.u8(),
        name_size: c.u16() as usize,
        attr: c.u32(),
        ..Default::default()
    };
    if flags & F_LARGE != 0 {
        f.pack_high = c.u32();
        f.unp_high = c.u32();
    }
    const NAME_LIMIT: usize = 0x10000;
    f.name = c.bytes(f.name_size.min(NAME_LIMIT));
    if service {
        // Size of the fixed part of a file header.
        const FIXED: i64 = 32;
        let mut n = head_size as i64 - f.name_size as i64 - FIXED;
        if flags & F_SALT != 0 {
            n -= 8;
        }
        if n > 0 {
            f.sub_data = c.bytes(n as usize);
        }
    }
    if flags & F_SALT != 0 {
        let s = c.bytes(8);
        let mut salt = [0u8; 8];
        salt[..s.len()].copy_from_slice(&s);
        f.salt = Some(salt);
    }
    if flags & F_EXTTIME != 0 {
        // 4 bits per time (mtime, ctime, atime, unused): bit 3 present,
        // bit 2 one more second, bits 0-1 number of fraction bytes.
        let modes = c.u16() as u32;
        let mut times = [None; 3];
        for (i, t) in times.iter_mut().enumerate() {
            let mode = modes >> ((3 - i) * 4);
            if mode & 8 == 0 {
                continue;
            }
            let dos = if i != 0 { Some(c.u32()) } else { None };
            let count = mode & 3;
            let mut fraction = 0u32;
            for j in 0..count {
                fraction |= (c.u8() as u32) << ((j + 3 - count) * 8);
            }
            *t = Some(ExtTime { dos, add_second: mode & 4 != 0, fraction });
        }
        f.ext_times = Some(times);
    }
    f.parsed_end = c.pos();
    f
}

#[derive(Clone, Copy, Debug, Default)]
pub struct EndBlock {
    pub data_crc: Option<u32>,
    pub vol_number: Option<u16>,
}

pub const END_NEXT_VOLUME: u32 = 0x0001;
pub const END_DATA_CRC: u32 = 0x0002;
pub const END_REV_SPACE: u32 = 0x0004;
pub const END_VOL_NUMBER: u32 = 0x0008;

pub fn parse_end(buf: &[u8], flags: u32) -> EndBlock {
    let mut c = Cursor::new(buf, 7);
    let data_crc = (flags & END_DATA_CRC != 0).then(|| c.u32());
    let vol_number = (flags & END_VOL_NUMBER != 0).then(|| c.u16());
    EndBlock { data_crc, vol_number }
}

/// RAR 1.4 main header (after the 4-byte signature): size u16, flags u8.
pub struct Main14 {
    pub head_size: u16,
    pub flags: u8,
}

pub fn parse_main14(buf: &[u8]) -> Main14 {
    let mut c = Cursor::new(buf, 4);
    Main14 { head_size: c.u16(), flags: c.u8() }
}

/// RAR 1.4 file header (21 bytes, then the name).
#[derive(Default)]
pub struct File14 {
    pub pack_size: u32,
    pub unp_size: u32,
    pub checksum: u16,
    pub head_size: u16,
    pub dos_time: u32,
    pub attr: u8,
    pub flags: u8,
    /// 2 for RAR 1.3 encryption.
    pub version: u8,
    pub name_size: u8,
    pub method: u8,
}

pub fn parse_file14(buf: &[u8]) -> File14 {
    let mut c = Cursor::new(buf, 0);
    File14 {
        pack_size: c.u32(),
        unp_size: c.u32(),
        checksum: c.u16(),
        head_size: c.u16(),
        dos_time: c.u32(),
        attr: c.u8(),
        flags: c.u8(),
        version: c.u8(),
        name_size: c.u8(),
        method: c.u8(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ext_time_fraction() {
        // mtime: present, +1 s, 2 fraction bytes; ctime: present, DOS time, no fraction.
        let mut h2 = vec![0u8; 32];
        h2[26] = 1; // name size
        h2.extend_from_slice(b"a");
        h2.extend_from_slice(&[0x00u8, 0xe8]);
        h2.extend_from_slice(&[0x34, 0x12]);
        h2.extend_from_slice(&0x1111_2222u32.to_le_bytes());
        let f = parse_file(&h2, F_EXTTIME, h2.len(), false);
        let t = f.ext_times.unwrap();
        let m = t[0].unwrap();
        assert!(m.add_second);
        assert_eq!(m.fraction, 0x12 << 16 | 0x34 << 8);
        assert_eq!(t[1].unwrap().dos, Some(0x1111_2222));
        assert!(t[2].is_none());
    }
}
