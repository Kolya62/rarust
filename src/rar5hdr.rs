// SPDX-License-Identifier: GPL-3.0-or-later

//! Parser for RAR 5.0 archive headers, following the published RAR 5.0
//! archive format description.
//!
//! Every header is
//!
//! ```text
//! crc32       u32    CRC32 of everything after this field
//! size        vint   bytes after this field
//! type        vint   1 main, 2 file, 3 service, 4 encryption, 5 end
//! flags       vint   common header flags
//! extra_size  vint   if flags & 0x01
//! data_size   vint   if flags & 0x02
//! ...         type specific fields
//! extra area  extra_size bytes at the end of the header: records of
//!             (size vint, type vint, data)
//! ```
//!
//! A vint stores 7 bits per byte, least significant group first; the high
//! bit marks that another byte follows.
//!
//! The parser works on a complete, already decrypted header and never
//! fails on truncated fields: missing bytes read as zero, matching how
//! damaged archives have always been handled.

pub const BLOCK_MAIN: u64 = 1;
pub const BLOCK_FILE: u64 = 2;
pub const BLOCK_SERVICE: u64 = 3;
pub const BLOCK_CRYPT: u64 = 4;
pub const BLOCK_END: u64 = 5;

/// Common header flags.
pub const HF_EXTRA: u64 = 0x01;
pub const HF_DATA: u64 = 0x02;
pub const HF_SKIP_IF_UNKNOWN: u64 = 0x04;
pub const HF_SPLIT_BEFORE: u64 = 0x08;
pub const HF_SPLIT_AFTER: u64 = 0x10;
pub const HF_CHILD: u64 = 0x20;
pub const HF_INHERITED: u64 = 0x40;

/// Longest name accepted from a header.
pub const NAME_LIMIT: usize = 0x10000;

/// Byte cursor over a header.
pub struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
    end: usize,
}

impl<'a> Cursor<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Cursor { buf, pos: 0, end: buf.len() }
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    pub fn left(&self) -> usize {
        self.end.saturating_sub(self.pos)
    }

    pub fn byte(&mut self) -> u8 {
        let b = if self.pos < self.end { self.buf[self.pos] } else { 0 };
        self.pos += 1;
        b
    }

    pub fn u32(&mut self) -> u32 {
        u32::from_le_bytes([self.byte(), self.byte(), self.byte(), self.byte()])
    }

    pub fn u64(&mut self) -> u64 {
        self.u32() as u64 | (self.u32() as u64) << 32
    }

    pub fn vint(&mut self) -> u64 {
        let mut v = 0u64;
        for shift in (0..70).step_by(7) {
            if self.pos >= self.end {
                return 0;
            }
            let b = self.byte();
            if shift < 64 {
                v |= ((b & 0x7f) as u64) << shift;
            }
            if b & 0x80 == 0 {
                return v;
            }
        }
        0
    }

    /// Up to `n` bytes; fewer if the header ends.
    pub fn bytes(&mut self, n: usize) -> Vec<u8> {
        let start = self.pos.min(self.end);
        let stop = start.saturating_add(n).min(self.end);
        self.pos = self.pos.saturating_add(n);
        self.buf[start..stop].to_vec()
    }

    /// Exactly `N` bytes, zero padded.
    pub fn array<const N: usize>(&mut self) -> [u8; N] {
        let mut a = [0u8; N];
        let v = self.bytes(N);
        a[..v.len()].copy_from_slice(&v);
        a
    }

    /// Bytes from the current position to the end of the cursor.
    pub fn rest(&mut self) -> Vec<u8> {
        let n = self.left();
        self.bytes(n)
    }

    /// Cursor limited to the next `n` bytes; `self` moves past them.
    fn sub(&mut self, n: usize) -> Cursor<'a> {
        let start = self.pos.min(self.end);
        let end = start.saturating_add(n).min(self.end);
        self.pos = end;
        Cursor { buf: self.buf, pos: start, end }
    }
}

/// Number of bytes of the vint at the start of `buf`, if it is complete.
pub fn vint_len(buf: &[u8]) -> Option<usize> {
    buf.iter().take(10).position(|b| b & 0x80 == 0).map(|p| p + 1)
}

/// Fields every header has.
#[derive(Clone, Debug, Default)]
pub struct Common {
    pub stored_crc: u32,
    pub crc_ok: bool,
    pub kind: u64,
    pub flags: u64,
    pub extra_size: u64,
    pub data_size: u64,
    /// Size of the whole header including the CRC and size fields.
    pub header_size: u64,
}

#[derive(Clone, Debug, Default)]
pub struct CryptBlock {
    pub version: u64,
    pub kdf_lg2: u8,
    pub salt: [u8; 16],
    /// Password check value, present only when its checksum is valid.
    pub check: Option<[u8; 8]>,
}

#[derive(Clone, Debug, Default)]
pub struct MainBlock {
    pub volume: bool,
    pub solid: bool,
    pub recovery: bool,
    pub locked: bool,
    pub volume_number: Option<u64>,
    /// Offsets relative to the start of this header.
    pub locator: Option<Locator>,
    pub orig_name: Option<Vec<u8>>,
    pub orig_time: Option<Time>,
}

#[derive(Clone, Debug, Default)]
pub struct Locator {
    pub quick_open: Option<u64>,
    pub recovery: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Time {
    Unix(u32),
    UnixNs(u64),
    /// Windows FILETIME: 100 ns intervals since 1601.
    Windows(u64),
}

#[derive(Clone, Debug, Default)]
pub struct FileCrypt {
    pub version: u64,
    pub kdf_lg2: u8,
    pub salt: [u8; 16],
    pub iv: [u8; 16],
    /// Checksums are replaced by keyed MACs.
    pub mac: bool,
    /// Password check value, present only when its checksum is valid.
    pub check: Option<[u8; 8]>,
}

#[derive(Clone, Debug, Default)]
pub struct FileTimes {
    pub mtime: Option<Time>,
    pub ctime: Option<Time>,
    pub atime: Option<Time>,
    /// Nanoseconds to add to Unix times, valid values only.
    pub mtime_ns: Option<u32>,
    pub ctime_ns: Option<u32>,
    pub atime_ns: Option<u32>,
}

#[derive(Clone, Debug, Default)]
pub struct Redirect {
    /// 1 Unix symlink, 2 Windows symlink, 3 junction, 4 hard link, 5 file copy.
    pub kind: u64,
    pub target_is_dir: bool,
    pub target: Vec<u8>,
}

#[derive(Clone, Debug, Default)]
pub struct Owner {
    pub user: Option<Vec<u8>>,
    pub group: Option<Vec<u8>>,
    pub uid: Option<u64>,
    pub gid: Option<u64>,
}

/// File and service headers share one layout.
#[derive(Clone, Debug, Default)]
pub struct FileBlock {
    pub dir: bool,
    /// `None` if the archiver did not know the size.
    pub unp_size: Option<u64>,
    pub attr: u64,
    pub mtime: Option<u32>,
    pub crc32: Option<u32>,
    /// Compression information, see [`Compression`].
    pub comp: u64,
    pub host_os: u64,
    pub name: Vec<u8>,
    pub crypt: Option<FileCrypt>,
    pub blake2: Option<[u8; 32]>,
    pub times: Option<FileTimes>,
    pub version: Option<u64>,
    pub redirect: Option<Redirect>,
    pub owner: Option<Owner>,
    pub service_data: Option<Vec<u8>>,
    /// Encryption record with an unsupported version or KDF count.
    pub bad_crypt: Option<String>,
}

/// Decoded compression information field.
#[derive(Clone, Copy, Debug)]
pub struct Compression {
    /// 0 RAR 5.0, 1 RAR 7.0, other values unknown.
    pub algorithm: u64,
    pub solid: bool,
    pub method: u64,
    /// Dictionary size in bytes, 0 for unknown algorithms.
    pub dict: u64,
    /// RAR 7.0 data that a RAR 5.0 decoder can unpack.
    pub v5_compatible: bool,
}

impl Compression {
    pub fn decode(info: u64) -> Self {
        let algorithm = info & 0x3f;
        let solid = info & 0x40 != 0;
        let method = (info >> 7) & 7;
        let v5_compatible = algorithm == 1 && info & 0x10_0000 != 0;
        let dict = match algorithm {
            // 128 KB shifted by 4 bits of exponent.
            0 => 0x20000u64 << ((info >> 10) & 0x0f),
            // 5 bits of exponent and a fraction in 1/32 steps.
            1 => {
                let base = 0x20000u64 << ((info >> 10) & 0x1f);
                base + base / 32 * ((info >> 15) & 0x1f)
            }
            _ => 0,
        };
        Compression { algorithm, solid, method, dict, v5_compatible }
    }
}

#[derive(Clone, Debug)]
pub enum Block {
    Main(MainBlock),
    File(FileBlock),
    Service(FileBlock),
    Crypt(CryptBlock),
    End { more_volumes: bool },
    Unknown,
}

/// Valid check value: 8 bytes followed by the first 4 bytes of their SHA-256.
fn check_value(c: &mut Cursor) -> Option<[u8; 8]> {
    let v: [u8; 8] = c.array();
    let sum: [u8; 4] = c.array();
    (crate::hash::sha256::Sha256::digest(&v)[..4] == sum).then_some(v)
}

fn time(c: &mut Cursor, unix: bool) -> Time {
    if unix {
        Time::Unix(c.u32())
    } else {
        Time::Windows(c.u64())
    }
}

/// Reads the size field after the CRC. Returns (header size after the
/// size field, length of the size field) if the bytes are complete.
pub fn header_size(after_crc: &[u8]) -> Option<(u64, usize)> {
    let n = vint_len(after_crc)?;
    Some((Cursor::new(after_crc).vint(), n))
}

/// Parses a complete header starting at its CRC field.
pub fn parse(buf: &[u8]) -> (Common, Block) {
    let mut c = Cursor::new(buf);
    let mut h = Common { stored_crc: c.u32(), ..Default::default() };
    h.crc_ok = crate::hash::crc32::crc32(!0, buf.get(4..).unwrap_or(&[])) ^ !0 == h.stored_crc;
    let size = c.vint();
    h.header_size = c.pos() as u64 + size;
    h.kind = c.vint();
    h.flags = c.vint();
    if h.flags & HF_EXTRA != 0 {
        h.extra_size = c.vint();
    }
    if h.flags & HF_DATA != 0 {
        h.data_size = c.vint();
    }
    let end = (h.header_size as usize).min(buf.len());
    let extra_at = end.checked_sub(h.extra_size as usize).filter(|&p| p >= c.pos());
    let body_end = extra_at.unwrap_or(end);
    let mut body = Cursor { buf, pos: c.pos(), end: body_end };
    let mut extra = Cursor { buf, pos: extra_at.unwrap_or(end), end: if extra_at.is_some() { end } else { 0 } };
    let block = match h.kind {
        BLOCK_MAIN => Block::Main(parse_main(&mut body, &mut extra)),
        BLOCK_FILE => Block::File(parse_file(&mut body, &mut extra, false)),
        BLOCK_SERVICE => Block::Service(parse_file(&mut body, &mut extra, true)),
        BLOCK_CRYPT => {
            let version = body.vint();
            let flags = body.vint();
            let kdf_lg2 = body.byte();
            let salt = body.array();
            let check = if flags & 1 != 0 { check_value(&mut body) } else { None };
            Block::Crypt(CryptBlock { version, kdf_lg2, salt, check })
        }
        BLOCK_END => Block::End { more_volumes: body.vint() & 1 != 0 },
        _ => Block::Unknown,
    };
    (h, block)
}

/// Visits extra area records as (type, record cursor). `next_is_last_byte`
/// tells whether exactly one byte of the area follows the record.
fn records(extra: &mut Cursor, mut f: impl FnMut(u64, &mut Cursor, bool)) {
    while extra.left() >= 2 {
        let size = extra.vint() as usize;
        if size == 0 || size > extra.left() {
            break;
        }
        let mut rec = extra.sub(size);
        let one_left = extra.left() == 1;
        let kind = rec.vint();
        f(kind, &mut rec, one_left);
    }
}

fn parse_main(body: &mut Cursor, extra: &mut Cursor) -> MainBlock {
    let flags = body.vint();
    let mut m = MainBlock {
        volume: flags & 0x01 != 0,
        solid: flags & 0x04 != 0,
        recovery: flags & 0x08 != 0,
        locked: flags & 0x10 != 0,
        volume_number: (flags & 0x02 != 0).then(|| body.vint()),
        ..Default::default()
    };
    records(extra, |kind, r, _| match kind {
        1 => {
            let f = r.vint();
            let quick_open = if f & 1 != 0 { Some(r.vint()).filter(|&o| o != 0) } else { None };
            let recovery = if f & 2 != 0 { Some(r.vint()).filter(|&o| o != 0) } else { None };
            m.locator = Some(Locator { quick_open, recovery });
        }
        2 => {
            // Original archive name and creation time (RAR 7).
            let f = r.vint();
            if f & 1 != 0 {
                let n = r.vint() as usize;
                if n > 0 && n < NAME_LIMIT {
                    let name = r.bytes(n);
                    if name.first().is_some_and(|&b| b != 0) {
                        m.orig_name = Some(name);
                    }
                }
            }
            if f & 2 != 0 {
                m.orig_time = Some(match (f & 4 != 0, f & 8 != 0) {
                    (true, true) => Time::UnixNs(r.u64()),
                    (true, false) => Time::Unix(r.u32()),
                    _ => Time::Windows(r.u64()),
                });
            }
        }
        _ => {}
    });
    m
}

fn parse_file(body: &mut Cursor, extra: &mut Cursor, service: bool) -> FileBlock {
    let flags = body.vint();
    let unp = body.vint();
    let mut f = FileBlock {
        dir: flags & 0x01 != 0,
        unp_size: (flags & 0x08 == 0).then_some(unp),
        attr: body.vint(),
        ..Default::default()
    };
    if flags & 0x02 != 0 {
        f.mtime = Some(body.u32());
    }
    if flags & 0x04 != 0 {
        f.crc32 = Some(body.u32());
    }
    f.comp = body.vint();
    f.host_os = body.vint();
    let name_len = body.vint() as usize;
    f.name = body.bytes(name_len.min(NAME_LIMIT));
    let area_last_byte = extra.byte_at_end();

    records(extra, |kind, r, one_left| match kind {
        1 => {
            let version = r.vint();
            if version > crate::crypt::CRYPT_VERSION {
                f.bad_crypt = Some(format!("x{version}"));
                return;
            }
            let fl = r.vint();
            let kdf_lg2 = r.byte();
            if kdf_lg2 as u32 > crate::crypt::CRYPT5_KDF_LG2_COUNT_MAX {
                f.bad_crypt = Some(format!("xc{kdf_lg2}"));
                return;
            }
            let salt = r.array();
            let iv = r.array();
            let mut check = if fl & 1 != 0 { check_value(r) } else { None };
            // Service headers may carry an all-zero placeholder.
            if service && check == Some([0; 8]) {
                check = None;
            }
            f.crypt = Some(FileCrypt { version, kdf_lg2, salt, iv, mac: fl & 2 != 0, check });
        }
        2 => {
            if r.vint() == 0 {
                f.blake2 = Some(r.array());
            }
        }
        3 => {
            if r.left() >= 4 {
                let fl = r.vint();
                let unix = fl & 1 != 0;
                let mut t = FileTimes::default();
                if fl & 2 != 0 {
                    t.mtime = Some(time(r, unix));
                }
                if fl & 4 != 0 {
                    t.ctime = Some(time(r, unix));
                }
                if fl & 8 != 0 {
                    t.atime = Some(time(r, unix));
                }
                if unix && fl & 0x10 != 0 {
                    let mut ns = || Some(r.u32() & 0x3fff_ffff).filter(|&n| n < 1_000_000_000);
                    if fl & 2 != 0 {
                        t.mtime_ns = ns();
                    }
                    if fl & 4 != 0 {
                        t.ctime_ns = ns();
                    }
                    if fl & 8 != 0 {
                        t.atime_ns = ns();
                    }
                }
                f.times = Some(t);
            }
        }
        4 => {
            if r.left() >= 1 {
                let _flags = r.vint();
                f.version = Some(r.vint()).filter(|&v| v != 0);
            }
        }
        5 => {
            let kind = r.vint();
            let fl = r.vint();
            let n = r.vint() as usize;
            if n > 0 && n < NAME_LIMIT {
                f.redirect = Some(Redirect { kind, target_is_dir: fl & 1 != 0, target: r.bytes(n) });
            }
        }
        6 => {
            let fl = r.vint();
            let name = |r: &mut Cursor| {
                let n = (r.vint() as usize).min(255);
                let mut v = r.bytes(n);
                if let Some(z) = v.iter().position(|&b| b == 0) {
                    v.truncate(z);
                }
                v
            };
            let mut o = Owner::default();
            if fl & 1 != 0 {
                o.user = Some(name(r));
            }
            if fl & 2 != 0 {
                o.group = Some(name(r));
            }
            if fl & 4 != 0 {
                o.uid = Some(r.vint());
            }
            if fl & 8 != 0 {
                o.gid = Some(r.vint());
            }
            f.owner = Some(o);
        }
        7 => {
            let mut data = r.rest();
            // Some RAR versions stored this record one byte too short in
            // service headers; the missing byte is the last of the area.
            if service && one_left {
                data.push(area_last_byte);
            }
            f.service_data = Some(data);
        }
        _ => {}
    });
    f
}

impl Cursor<'_> {
    fn byte_at_end(&self) -> u8 {
        if self.end > 0 { self.buf[self.end - 1] } else { 0 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vint() {
        let mut c = Cursor::new(&[0x7f, 0x80, 0x01, 0xff, 0xff, 0x03]);
        assert_eq!(c.vint(), 0x7f);
        assert_eq!(c.vint(), 0x80);
        assert_eq!(c.vint(), 0xffff);
        assert_eq!(c.vint(), 0); // past the end
        assert_eq!(vint_len(&[0x80, 0x80]), None);
        assert_eq!(vint_len(&[0x80, 0x01]), Some(2));
    }

    #[test]
    fn compression_info() {
        let c = Compression::decode(0x40 | 3 << 7 | 5 << 10);
        assert_eq!((c.algorithm, c.solid, c.method, c.dict), (0, true, 3, 0x20000 << 5));
        let c = Compression::decode(1 | 2 << 10 | 16 << 15);
        assert_eq!(c.dict, 0x80000 + 0x80000 / 2);
    }

    #[test]
    fn end_block() {
        // type 5, flags 0, end flags 1
        let body = [5u8, 0, 1];
        let mut h = vec![0, 0, 0, 0, body.len() as u8];
        h.extend_from_slice(&body);
        let crc = crate::hash::crc32::crc32(!0, &h[4..]) ^ !0;
        h[..4].copy_from_slice(&crc.to_le_bytes());
        let (c, b) = parse(&h);
        assert!(c.crc_ok);
        assert_eq!(c.header_size, h.len() as u64);
        assert!(matches!(b, Block::End { more_volumes: true }));
    }
}
