// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Checksums and hash functions.

pub mod blake2sp;
pub mod crc32;
pub mod sha1;
pub mod sha256;

use blake2sp::Blake2sp;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum HashType {
    #[default]
    None,
    Rar14,
    Crc32,
    Blake2,
}

/// Stored or computed checksum.
#[derive(Clone, Copy, Debug, Default)]
pub struct HashValue {
    pub kind: HashType,
    pub crc32: u32,
    pub digest: [u8; 32],
}

pub const BLAKE2_EMPTY: [u8; 32] = [
    0xdd, 0x0e, 0x89, 0x17, 0x76, 0x93, 0x3f, 0x43, 0xc7, 0xd0, 0x32, 0xb0, 0x8a, 0x91, 0x7e, 0x25, 0x74,
    0x1f, 0x8a, 0xa9, 0xa1, 0x2c, 0x12, 0xe1, 0xca, 0xc8, 0x80, 0x15, 0x00, 0xf2, 0xca, 0x4f,
];

impl HashValue {
    pub fn init(kind: HashType) -> Self {
        let mut v = HashValue { kind, ..Default::default() };
        if kind == HashType::Blake2 {
            v.digest = BLAKE2_EMPTY;
        }
        v
    }
}

impl PartialEq for HashValue {
    fn eq(&self, o: &Self) -> bool {
        use HashType::*;
        match (self.kind, o.kind) {
            (None, _) | (_, None) => true,
            (Rar14, Rar14) | (Crc32, Crc32) => self.crc32 == o.crc32,
            (Blake2, Blake2) => self.digest == o.digest,
            _ => false,
        }
    }
}

/// Incremental hasher for unpacked data.
#[derive(Clone)]
pub struct DataHash {
    kind: HashType,
    crc: u32,
    blake: Option<Box<Blake2sp>>,
}

impl Default for DataHash {
    fn default() -> Self {
        DataHash { kind: HashType::None, crc: 0, blake: None }
    }
}

impl DataHash {
    pub fn new(kind: HashType) -> Self {
        let mut h = DataHash::default();
        h.init(kind);
        h
    }

    pub fn init(&mut self, kind: HashType) {
        self.kind = kind;
        match kind {
            HashType::Rar14 => self.crc = 0,
            HashType::Crc32 => self.crc = 0xffffffff,
            HashType::Blake2 => self.blake = Some(Box::new(Blake2sp::new())),
            HashType::None => {}
        }
    }

    pub fn kind(&self) -> HashType {
        self.kind
    }

    pub fn update(&mut self, data: &[u8]) {
        match self.kind {
            HashType::Rar14 => self.crc = crc32::checksum14(self.crc as u16, data) as u32,
            HashType::Crc32 => self.crc = crc32::crc32(self.crc, data),
            HashType::Blake2 => self.blake.as_mut().unwrap().update(data),
            HashType::None => {}
        }
    }

    pub fn result(&self) -> HashValue {
        let mut v = HashValue { kind: self.kind, ..Default::default() };
        match self.kind {
            HashType::Rar14 => v.crc32 = self.crc,
            HashType::Crc32 => v.crc32 = self.crc ^ 0xffffffff,
            HashType::Blake2 => v.digest = self.blake.as_ref().unwrap().finalize(),
            HashType::None => {}
        }
        v
    }

    pub fn crc32(&self) -> u32 {
        if self.kind == HashType::Crc32 {
            self.crc ^ 0xffffffff
        } else {
            0
        }
    }

    /// Compare with stored value, converting to MAC first if `key` is set.
    pub fn cmp(&self, stored: &HashValue, key: Option<&[u8; 32]>) -> bool {
        let mut f = self.result();
        if let Some(k) = key {
            crate::crypt::convert_hash_to_mac(&mut f, k);
        }
        f == *stored
    }
}
