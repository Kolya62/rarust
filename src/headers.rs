// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Archive header structures and constants for RAR 1.4 - 7.x formats.

use crate::crypt::{CryptMethod, SIZE_INITV, SIZE_PSWCHECK, SIZE_SALT50};
use crate::hash::HashValue;
use crate::timefn::RarTime;

pub const SIZEOF_MARKHEAD3: usize = 7;
pub const SIZEOF_MAINHEAD14: usize = 7;
pub const SIZEOF_MAINHEAD3: usize = 13;
pub const SIZEOF_FILEHEAD14: usize = 21;
pub const SIZEOF_FILEHEAD3: usize = 32;
pub const SIZEOF_SHORTBLOCKHEAD: usize = 7;
pub const SIZEOF_COMMHEAD: usize = 13;
pub const SIZEOF_MARKHEAD5: usize = 8;
pub const SIZEOF_SHORTBLOCKHEAD5: usize = 7;

pub const VER_PACK: u32 = 29;
pub const VER_PACK5: u32 = 50;
pub const VER_PACK7: u32 = 70;
pub const VER_UNPACK: u32 = 29;
pub const VER_UNPACK5: u32 = 50;
pub const VER_UNPACK7: u32 = 70;
pub const VER_UNKNOWN: u32 = 9999;

pub const MHD_VOLUME: u32 = 0x0001;
pub const MHD_COMMENT: u32 = 0x0002;
pub const MHD_LOCK: u32 = 0x0004;
pub const MHD_SOLID: u32 = 0x0008;
pub const MHD_PACK_COMMENT: u32 = 0x0010;
pub const MHD_NEWNUMBERING: u32 = 0x0010;
pub const MHD_AV: u32 = 0x0020;
pub const MHD_PROTECT: u32 = 0x0040;
pub const MHD_PASSWORD: u32 = 0x0080;
pub const MHD_FIRSTVOLUME: u32 = 0x0100;

pub const LHD_SPLIT_BEFORE: u32 = 0x0001;
pub const LHD_SPLIT_AFTER: u32 = 0x0002;
pub const LHD_PASSWORD: u32 = 0x0004;
pub const LHD_COMMENT: u32 = 0x0008;
pub const LHD_SOLID: u32 = 0x0010;
pub const LHD_WINDOWMASK: u32 = 0x00e0;
pub const LHD_DIRECTORY: u32 = 0x00e0;
pub const LHD_LARGE: u32 = 0x0100;
pub const LHD_UNICODE: u32 = 0x0200;
pub const LHD_SALT: u32 = 0x0400;
pub const LHD_VERSION: u32 = 0x0800;
pub const LHD_EXTTIME: u32 = 0x1000;

pub const SKIP_IF_UNKNOWN: u32 = 0x4000;
pub const LONG_BLOCK: u32 = 0x8000;

pub const EARC_NEXT_VOLUME: u32 = 0x0001;
pub const EARC_DATACRC: u32 = 0x0002;
pub const EARC_REVSPACE: u32 = 0x0004;
pub const EARC_VOLNUMBER: u32 = 0x0008;

// RAR 5.0 header types.
pub const HEAD_MARK: u32 = 0x00;
pub const HEAD_MAIN: u32 = 0x01;
pub const HEAD_FILE: u32 = 0x02;
pub const HEAD_SERVICE: u32 = 0x03;
pub const HEAD_CRYPT: u32 = 0x04;
pub const HEAD_ENDARC: u32 = 0x05;
pub const HEAD_UNKNOWN: u32 = 0xff;
// RAR 1.5 - 4.x header types.
pub const HEAD3_MARK: u32 = 0x72;
pub const HEAD3_MAIN: u32 = 0x73;
pub const HEAD3_FILE: u32 = 0x74;
pub const HEAD3_CMT: u32 = 0x75;
pub const HEAD3_AV: u32 = 0x76;
pub const HEAD3_OLDSERVICE: u32 = 0x77;
pub const HEAD3_PROTECT: u32 = 0x78;
pub const HEAD3_SIGN: u32 = 0x79;
pub const HEAD3_SERVICE: u32 = 0x7a;
pub const HEAD3_ENDARC: u32 = 0x7b;

pub const EA_HEAD: u16 = 0x100;
pub const UO_HEAD: u16 = 0x101;
pub const MAC_HEAD: u16 = 0x102;
pub const BEEA_HEAD: u16 = 0x103;
pub const NTACL_HEAD: u16 = 0x104;
pub const STREAM_HEAD: u16 = 0x105;

pub const HOST5_WINDOWS: u8 = 0;
pub const HOST5_UNIX: u8 = 1;
pub const HOST_MSDOS: u8 = 0;
pub const HOST_OS2: u8 = 1;
pub const HOST_WIN32: u8 = 2;
pub const HOST_UNIX: u8 = 3;
pub const HOST_MACOS: u8 = 4;
pub const HOST_BEOS: u8 = 5;
pub const HOST_MAX: u8 = 6;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum HostSystemType {
    Windows,
    Unix,
    #[default]
    Unknown,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum FsRedir {
    #[default]
    None = 0,
    UnixSymlink,
    WinSymlink,
    Junction,
    Hardlink,
    FileCopy,
    Unknown,
}

pub const SUBHEAD_TYPE_CMT: &str = "CMT";
pub const SUBHEAD_TYPE_QOPEN: &str = "QO";
pub const SUBHEAD_TYPE_ACL: &str = "ACL";
pub const SUBHEAD_TYPE_STREAM: &str = "STM";
pub const SUBHEAD_TYPE_UOWNER: &str = "UOW";
pub const SUBHEAD_TYPE_AV: &str = "AV";
pub const SUBHEAD_TYPE_RR: &str = "RR";
pub const SUBHEAD_TYPE_OS2EA: &str = "EA2";

pub const SUBHEAD_FLAGS_INHERITED: u32 = 0x80000000;
pub const SUBHEAD_FLAGS_CMT_UNICODE: u32 = 0x00000001;

// RAR 5.0 flags.
pub const HFL_EXTRA: u32 = 0x0001;
pub const HFL_DATA: u32 = 0x0002;
pub const HFL_SKIPIFUNKNOWN: u32 = 0x0004;
pub const HFL_SPLITBEFORE: u32 = 0x0008;
pub const HFL_SPLITAFTER: u32 = 0x0010;
pub const HFL_CHILD: u32 = 0x0020;
pub const HFL_INHERITED: u32 = 0x0040;

pub const MHFL_VOLUME: u32 = 0x0001;
pub const MHFL_VOLNUMBER: u32 = 0x0002;
pub const MHFL_SOLID: u32 = 0x0004;
pub const MHFL_PROTECT: u32 = 0x0008;
pub const MHFL_LOCK: u32 = 0x0010;

pub const FHFL_DIRECTORY: u32 = 0x0001;
pub const FHFL_UTIME: u32 = 0x0002;
pub const FHFL_CRC32: u32 = 0x0004;
pub const FHFL_UNPUNKNOWN: u32 = 0x0008;

pub const EHFL_NEXTVOLUME: u32 = 0x0001;
pub const CHFL_CRYPT_PSWCHECK: u32 = 0x0001;

pub const FCI_SOLID: u32 = 0x00000040;
pub const FCI_DICT_BIT0: u32 = 0x00000400;
pub const FCI_DICT_FRACT0: u32 = 0x00008000;
pub const FCI_RAR5_COMPAT: u32 = 0x00100000;

pub const MHEXTRA_LOCATOR: u64 = 0x01;
pub const MHEXTRA_METADATA: u64 = 0x02;
pub const MHEXTRA_LOCATOR_QLIST: u32 = 0x01;
pub const MHEXTRA_LOCATOR_RR: u32 = 0x02;
pub const MHEXTRA_METADATA_NAME: u32 = 0x01;
pub const MHEXTRA_METADATA_CTIME: u32 = 0x02;
pub const MHEXTRA_METADATA_UNIXTIME: u32 = 0x04;
pub const MHEXTRA_METADATA_UNIX_NS: u32 = 0x08;

pub const FHEXTRA_CRYPT: u64 = 0x01;
pub const FHEXTRA_HASH: u64 = 0x02;
pub const FHEXTRA_HTIME: u64 = 0x03;
pub const FHEXTRA_VERSION: u64 = 0x04;
pub const FHEXTRA_REDIR: u64 = 0x05;
pub const FHEXTRA_UOWNER: u64 = 0x06;
pub const FHEXTRA_SUBDATA: u64 = 0x07;

pub const FHEXTRA_HASH_BLAKE2: u32 = 0x00;
pub const FHEXTRA_HTIME_UNIXTIME: u8 = 0x01;
pub const FHEXTRA_HTIME_MTIME: u8 = 0x02;
pub const FHEXTRA_HTIME_CTIME: u8 = 0x04;
pub const FHEXTRA_HTIME_ATIME: u8 = 0x08;
pub const FHEXTRA_HTIME_UNIX_NS: u8 = 0x10;
pub const FHEXTRA_CRYPT_PSWCHECK: u32 = 0x01;
pub const FHEXTRA_CRYPT_HASHMAC: u32 = 0x02;
pub const FHEXTRA_REDIR_DIR: u32 = 0x01;
pub const FHEXTRA_UOWNER_UNAME: u32 = 0x01;
pub const FHEXTRA_UOWNER_GNAME: u32 = 0x02;
pub const FHEXTRA_UOWNER_NUMUID: u32 = 0x04;
pub const FHEXTRA_UOWNER_NUMGID: u32 = 0x08;

/// Undefined 64-bit value marker.
pub const INT64NDF: i64 = (0x7fffffffi64 << 32) | 0x7fffffff;

#[derive(Clone, Debug, Default)]
pub struct BaseBlock {
    pub head_crc: u32,
    pub header_type: u32,
    pub flags: u32,
    pub head_size: u32,
    pub skip_if_unknown: bool,
}

#[derive(Clone, Debug, Default)]
pub struct MainHeader {
    pub base: BaseBlock,
    pub high_pos_av: u16,
    pub pos_av: u32,
    pub comment_in_header: bool,
    pub pack_comment: bool,
    pub locator: bool,
    pub qopen_offset: u64,
    pub qopen_max_size: u64,
    pub rr_offset: u64,
    pub rr_max_size: u64,
    pub orig_name: String,
    pub orig_time: RarTime,
}

#[derive(Clone, Debug, Default)]
pub struct FileHeader {
    pub base: BaseBlock,
    pub data_size: u32,
    pub host_os: u8,
    pub unp_ver: u32,
    pub method: u32,
    pub file_attr: u32, // Also SubFlags for service headers.
    pub file_name: String,
    pub sub_data: Vec<u8>,
    pub mtime: RarTime,
    pub ctime: RarTime,
    pub atime: RarTime,
    pub pack_size: i64,
    pub unp_size: i64,
    pub max_size: i64,
    pub file_hash: HashValue,
    pub file_flags: u32,
    pub split_before: bool,
    pub split_after: bool,
    pub unknown_unp_size: bool,
    pub encrypted: bool,
    pub crypt_method: CryptMethod,
    pub salt_set: bool,
    pub salt: [u8; SIZE_SALT50],
    pub init_v: [u8; SIZE_INITV],
    pub use_psw_check: bool,
    pub psw_check: [u8; SIZE_PSWCHECK],
    pub use_hash_key: bool,
    pub hash_key: [u8; 32],
    pub lg2_count: u32,
    pub solid: bool,
    pub dir: bool,
    pub comment_in_header: bool,
    pub version: bool,
    pub win_size: u64,
    pub inherited: bool,
    pub large_file: bool,
    pub sub_block: bool,
    pub hs_type: HostSystemType,
    pub redir_type: FsRedir,
    pub redir_name: String,
    pub dir_target: bool,
    pub unix_owner_set: bool,
    pub unix_owner_numeric: bool,
    pub unix_group_numeric: bool,
    pub unix_owner_name: Vec<u8>,
    pub unix_group_name: Vec<u8>,
    pub unix_owner_id: u32,
    pub unix_group_id: u32,
}

impl FileHeader {
    pub fn reset(&mut self) {
        *self = self.reset_copy(BaseBlock::default());
    }

    /// New header keeping fields which must survive between headers
    /// (encryption keys, link and owner data).
    pub fn reset_copy(&self, base: BaseBlock) -> FileHeader {
        FileHeader {
            base,
            host_os: self.host_os,
            hash_key: self.hash_key,
            salt: self.salt,
            init_v: self.init_v,
            psw_check: self.psw_check,
            redir_name: self.redir_name.clone(),
            unix_owner_numeric: self.unix_owner_numeric,
            unix_group_numeric: self.unix_group_numeric,
            unix_owner_name: self.unix_owner_name.clone(),
            unix_group_name: self.unix_group_name.clone(),
            unix_owner_id: self.unix_owner_id,
            unix_group_id: self.unix_group_id,
            ..Default::default()
        }
    }
    pub fn cmp_name(&self, name: &str) -> bool {
        self.file_name == name
    }
    pub fn sub_flags(&self) -> u32 {
        self.file_attr
    }
}

#[derive(Clone, Debug, Default)]
pub struct EndArcHeader {
    pub base: BaseBlock,
    pub arc_data_crc: u32,
    pub vol_number: u32,
    pub next_volume: bool,
    pub data_crc: bool,
    pub rev_space: bool,
    pub store_vol_number: bool,
}

#[derive(Clone, Debug, Default)]
pub struct CryptHeader {
    pub base: BaseBlock,
    pub use_psw_check: bool,
    pub lg2_count: u32,
    pub salt: [u8; SIZE_SALT50],
    pub psw_check: [u8; SIZE_PSWCHECK],
}

#[derive(Clone, Debug, Default)]
pub struct SubBlockHeader {
    pub base: BaseBlock,
    pub data_size: u32,
    pub sub_type: u16,
    pub level: u8,
}

#[derive(Clone, Debug, Default)]
pub struct CommentHeader {
    pub base: BaseBlock,
    pub unp_size: u16,
    pub unp_ver: u8,
    pub method: u8,
    pub comm_crc: u16,
}

#[derive(Clone, Debug, Default)]
pub struct ProtectHeader {
    pub base: BaseBlock,
    pub data_size: u32,
    pub version: u8,
    pub rec_sectors: u16,
    pub total_blocks: u32,
    pub mark: [u8; 8],
}

#[derive(Clone, Debug, Default)]
pub struct EaHeader {
    pub sub: SubBlockHeader,
    pub unp_size: u32,
    pub unp_ver: u8,
    pub method: u8,
    pub ea_crc: u32,
}

#[derive(Clone, Debug, Default)]
pub struct StreamHeader {
    pub sub: SubBlockHeader,
    pub unp_size: u32,
    pub unp_ver: u8,
    pub method: u8,
    pub stream_crc: u32,
    pub stream_name_size: u16,
    pub stream_name: Vec<u8>,
}
