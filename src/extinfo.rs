// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Extra file information: links and Unix owners.

use crate::archive::{Archive, RarFormat};
use crate::cmddata::{CommandData, ExtTimeMode};
use crate::errhnd::*;
use crate::filefn::*;
use crate::find::{fast_find, FindData};
use crate::headers::*;
use crate::pathfn::*;
use crate::rdwrfn::ComprDataIO;
use crate::ui::{ui_msg, UiMsg};
use crate::unicode::{char_to_wide, to_path, wide_to_char};

/// Current process umask. Read from /proc in Linux, 022 otherwise.
pub fn get_umask() -> u32 {
    use std::sync::OnceLock;
    static M: OnceLock<u32> = OnceLock::new();
    *M.get_or_init(|| {
        if let Ok(s) = std::fs::read_to_string("/proc/self/status") {
            for l in s.lines() {
                if let Some(v) = l.strip_prefix("Umask:") {
                    if let Ok(m) = u32::from_str_radix(v.trim(), 8) {
                        return m;
                    }
                }
            }
        }
        0o022
    })
}

/// Effective user ID without libc: owner of /proc/self.
pub fn geteuid() -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if let Ok(m) = std::fs::metadata("/proc/self") {
            return m.uid();
        }
        // Fallback: owner of a newly created temporary file.
        let p = std::env::temp_dir().join(format!(".rarust-uid-{}", std::process::id()));
        if std::fs::write(&p, b"").is_ok() {
            let uid = std::fs::metadata(&p).map(|m| m.uid()).unwrap_or(1);
            let _ = std::fs::remove_file(&p);
            return uid;
        }
        1
    }
    #[cfg(not(unix))]
    {
        1
    }
}

/// RAR3 and RAR5 service header extra records.
pub fn set_extra_info(cmd: &CommandData, arc: &mut Archive, name: &str) {
    if cfg!(windows) && !cmd.test && cmd.process_owners && arc.sub_head.cmp_name(SUBHEAD_TYPE_ACL) {
        extract_acl(arc, name);
    }
    if cfg!(windows) && arc.sub_head.cmp_name(SUBHEAD_TYPE_STREAM) {
        extract_streams(cmd, arc, name);
    }
    if cfg!(unix) && !cmd.test && cmd.process_owners && arc.format == RarFormat::Rar15 && arc.sub_head.cmp_name(SUBHEAD_TYPE_UOWNER) {
        extract_unix_owner30(arc, name);
    }
}

/// RAR 2.x NTFS security and stream subblocks.
pub fn set_extra_info20(cmd: &CommandData, arc: &mut Archive, name: &str) {
    if !cfg!(windows) || cmd.test {
        return;
    }
    match arc.sub_block_head.sub_type {
        NTACL_HEAD => {
            if cmd.process_owners {
                extract_acl20(arc, name);
            }
        }
        STREAM_HEAD => extract_streams20(arc, name),
        _ => {}
    }
}

fn extract_acl(arc: &mut Archive, file_name: &str) {
    let (ok, data) = arc.read_sub_data(true, None, false);
    if !ok {
        return;
    }
    let an = arc.file_name().to_string();
    crate::winsys::set_acl(&an, file_name, &data);
}

/// Check if the current user is administrator. Always false outside of
/// Windows, where it is used only for error hints.
pub fn is_user_admin() -> bool {
    #[cfg(windows)]
    return crate::win32::is_user_admin();
    #[cfg(not(windows))]
    false
}

fn extract_acl20(arc: &mut Archive, file_name: &str) {
    const MAX_ACL_SIZE: u32 = 0x100000;
    let an = arc.file_name().to_string();
    let h = arc.ea_head.clone();
    if arc.broken_header || h.unp_size > MAX_ACL_SIZE {
        ui_msg(UiMsg::AclBroken(an, file_name.to_string()));
        set_error_code(RARX_CRC);
        return;
    }
    if h.method < 0x31 || h.method > 0x35 || h.unp_ver as u32 > VER_PACK {
        ui_msg(UiMsg::AclUnknown(an, file_name.to_string()));
        set_error_code(RARX_WARNING);
        return;
    }
    let (data, crc) = arc.unpack_old_sub(h.sub.data_size, h.unp_size, h.unp_ver, None);
    if crc != h.ea_crc {
        ui_msg(UiMsg::AclBroken(an, file_name.to_string()));
        set_error_code(RARX_CRC);
        return;
    }
    crate::winsys::set_acl(&an, file_name, &data);
}

fn extract_streams20(arc: &mut Archive, file_name: &str) {
    let an = arc.file_name().to_string();
    if arc.broken_header {
        ui_msg(UiMsg::StreamBroken(an, file_name.to_string()));
        set_error_code(RARX_CRC);
        return;
    }
    let h = arc.stream_head.clone();
    if h.method < 0x31 || h.method > 0x35 || h.unp_ver as u32 > VER_PACK {
        ui_msg(UiMsg::StreamUnknown(an, file_name.to_string()));
        set_error_code(RARX_WARNING);
        return;
    }
    let stream_name = char_to_wide(&h.stream_name);
    if !stream_name.starts_with(':') || stream_name.contains(['\\', '/']) {
        ui_msg(UiMsg::StreamBroken(an, file_name.to_string()));
        set_error_code(RARX_CRC);
        return;
    }
    // Convert single character names like f:stream to .\f:stream to
    // resolve the ambiguity with drive letters.
    let full = if file_name.chars().count() == 1 { format!(".\\{}", file_name) } else { file_name.to_string() } + &stream_name;
    // Can't easily read RAR 2.0 stream data here, so if we already propagated
    // the archive Mark of the Web to extracted file, do not overwrite it.
    if arc.motw.is_name_conflicting(&stream_name) || is_ntfs_prohibited_stream(&stream_name) {
        return;
    }
    let mut fd = FindData::default();
    let host_found = fast_find(file_name, &mut fd, false);
    if fd.file_attr & 1 != 0 {
        set_file_attr(file_name, fd.file_attr & !1);
    }
    let mut f = crate::file::File::new();
    if f.w_create(&full, crate::file::FMF_WRITE) {
        let (_, crc) = arc.unpack_old_sub(h.sub.data_size, h.unp_size, h.unp_ver, Some(&mut f));
        if crc != h.stream_crc {
            ui_msg(UiMsg::StreamBroken(an, stream_name));
            set_error_code(RARX_CRC);
        } else {
            f.close();
        }
    }
    if host_found {
        crate::file::set_file_times_by_name(file_name, Some(&fd.mtime), Some(&fd.ctime), Some(&fd.atime));
    }
    if fd.file_attr & 1 != 0 {
        set_file_attr(file_name, fd.file_attr);
    }
}

/// More than one colon could be used to set the stream type and abused to
/// hide the actual file data in file::$DATA or MOTW data in
/// Zone.Identifier:$DATA. Stream name must include the leading ':'.
fn is_ntfs_prohibited_stream(stream_name: &str) -> bool {
    stream_name.chars().filter(|&c| c == ':').count() > 1
}

/// Extra data stored directly in file header.
pub fn set_file_header_extra(cmd: &CommandData, arc: &mut Archive, name: &str) {
    if cfg!(unix) && cmd.process_owners && arc.format == RarFormat::Rar50 && arc.file_head.unix_owner_set {
        set_unix_owner(arc, name);
    }
}

fn lookup_id(file: &str, name: &[u8]) -> Option<u32> {
    let data = std::fs::read(file).ok()?;
    for line in data.split(|&b| b == b'\n') {
        let mut parts = line.split(|&b| b == b':');
        if parts.next()? == name {
            parts.next();
            let id = parts.next()?;
            return std::str::from_utf8(id).ok()?.parse().ok();
        }
    }
    None
}

fn getpwnam(name: &[u8]) -> Option<u32> {
    lookup_id("/etc/passwd", name)
}

fn getgrnam(name: &[u8]) -> Option<u32> {
    lookup_id("/etc/group", name)
}

#[cfg(unix)]
fn lchown(name: &str, uid: u32, gid: u32) -> bool {
    std::os::unix::fs::lchown(to_path(name), Some(uid), Some(gid)).is_ok()
}

#[cfg(not(unix))]
fn lchown(_name: &str, _uid: u32, _gid: u32) -> bool {
    true
}

pub fn extract_unix_owner30(arc: &mut Archive, file_name: &str) {
    let data = arc.sub_head.sub_data.clone();
    let z = match data.iter().position(|&b| b == 0) {
        Some(z) => z,
        None => return,
    };
    let owner = &data[..z];
    let mut group = data[z + 1..].to_vec();
    if let Some(p) = group.iter().position(|&b| b == 0) {
        group.truncate(p);
    }
    let arc_name = arc.file_name().to_string();
    let uid = match getpwnam(owner) {
        Some(u) => u,
        None => {
            ui_msg(UiMsg::UOwnerGetOwnerId(arc_name, char_to_wide(owner)));
            set_error_code(RARX_WARNING);
            return;
        }
    };
    let gid = match getgrnam(&group) {
        Some(g) => g,
        None => {
            ui_msg(UiMsg::UOwnerGetGroupId(arc_name, char_to_wide(&group)));
            set_error_code(RARX_WARNING);
            return;
        }
    };
    let attr = get_file_attr(file_name);
    if !lchown(file_name, uid, gid) {
        ui_msg(UiMsg::UOwnerSet(arc_name, file_name.to_string()));
        set_error_code(RARX_CREATE);
    }
    set_file_attr(file_name, attr);
}

pub fn set_unix_owner(arc: &mut Archive, file_name: &str) {
    let arc_name = arc.file_name().to_string();
    let hd = &mut arc.file_head;
    if !hd.unix_owner_name.is_empty() {
        match getpwnam(&hd.unix_owner_name) {
            None => {
                if !hd.unix_owner_numeric {
                    ui_msg(UiMsg::UOwnerGetOwnerId(arc_name, char_to_wide(&hd.unix_owner_name)));
                    set_error_code(RARX_WARNING);
                    return;
                }
            }
            Some(u) => hd.unix_owner_id = u,
        }
    }
    if !hd.unix_group_name.is_empty() {
        match getgrnam(&hd.unix_group_name) {
            None => {
                if !hd.unix_group_numeric {
                    ui_msg(UiMsg::UOwnerGetGroupId(arc_name, char_to_wide(&hd.unix_group_name)));
                    set_error_code(RARX_WARNING);
                    return;
                }
            }
            Some(g) => hd.unix_group_id = g,
        }
    }
    if !lchown(file_name, hd.unix_owner_id, hd.unix_group_id) {
        ui_msg(UiMsg::UOwnerSet(arc_name, file_name.to_string()));
        set_error_code(RARX_CREATE);
    }
}

fn calc_allowed_depth(name: &str) -> i32 {
    let v = chars(name);
    let mut depth = 0;
    for i in 0..v.len() {
        if is_path_div(v[i]) {
            if is_path_div(at(&v, i + 1)) {
                return 0;
            }
            let dot = at(&v, i + 1) == '.' && (is_path_div(at(&v, i + 2)) || at(&v, i + 2) == '\0');
            let dot2 = at(&v, i + 1) == '.' && at(&v, i + 2) == '.' && (is_path_div(at(&v, i + 3)) || at(&v, i + 3) == '\0');
            if !dot && !dot2 {
                depth += 1;
            } else if dot2 {
                depth -= 1;
            }
        }
    }
    depth.max(0)
}

fn link_in_path(path: &str) -> bool {
    let v = chars(path);
    if v.is_empty() {
        return false;
    }
    let mut i = v.len() - 1;
    while i > 0 {
        if is_path_div(v[i]) {
            let p: String = v[..i].iter().collect();
            let mut fd = FindData::default();
            if fast_find(&p, &mut fd, true) && (fd.is_link || !fd.is_dir) {
                return true;
            }
        }
        i -= 1;
    }
    false
}

pub fn is_relative_symlink_safe(cmd: &CommandData, src_name: &str, prep_src_name: &str, target: &str) -> bool {
    if is_full_root_path(src_name) || is_full_root_path(target) || is_drive_letter(target) {
        return false;
    }
    let t = chars(target);
    let mut up_levels = 0;
    for pos in 0..t.len() {
        let dot2 = t[pos] == '.'
            && at(&t, pos + 1) == '.'
            && (is_path_div(at(&t, pos + 2)) || at(&t, pos + 2) == '\0')
            && (pos == 0 || is_path_div(t[pos - 1]));
        if dot2 {
            up_levels += 1;
        }
    }
    if up_levels > 0 && link_in_path(prep_src_name) {
        return false;
    }
    let allowed = calc_allowed_depth(src_name);
    let mut prep: Vec<char> = chars(prep_src_name);
    let ep = chars(&cmd.extr_path);
    if !ep.is_empty() && prep.len() >= ep.len() && prep[..ep.len()] == ep[..] {
        let mut l = ep.len();
        while is_path_div(at(&prep, l)) {
            l += 1;
        }
        prep.drain(..l.min(prep.len()));
    }
    let prep_allowed = calc_allowed_depth(&prep.iter().collect::<String>());
    allowed >= up_levels && prep_allowed >= up_levels
}

fn unix_symlink(cmd: &CommandData, target: &[u8], link_name: &str) -> bool {
    create_path(link_name, true, cmd.disable_names);
    del_file(link_name);
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let t = std::ffi::OsStr::from_bytes(target);
        match std::os::unix::fs::symlink(t, to_path(link_name)) {
            Ok(()) => true,
            Err(e) => {
                set_os_error(&e);
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    ui_msg(UiMsg::ULinkExist(link_name.to_string()));
                } else {
                    ui_msg(UiMsg::SLinkCreate(String::new(), link_name.to_string()));
                    set_error_code(RARX_WARNING);
                }
                false
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = target;
        ui_msg(UiMsg::SLinkCreate(String::new(), link_name.to_string()));
        false
    }
}

fn safe_char_to_wide(src: &[u8]) -> Option<String> {
    let d = char_to_wide(src);
    if d.is_empty() {
        return None;
    }
    let sc = src.iter().take_while(|&&b| b != 0).filter(|&&b| b == b'/' || b == b'.').count();
    let dc = d.chars().filter(|&c| c == '/' || c == '.').count();
    if sc == dc {
        Some(d)
    } else {
        None
    }
}

fn extract_unix_link30(cmd: &CommandData, io: &mut ComprDataIO, arc: &mut Archive, link_name: &str, up_link: &mut bool) -> bool {
    if !is_link(arc.file_head.file_attr) {
        return false;
    }
    let data_size = arc.file_head.pack_size as usize;
    if data_size > 0x10000 {
        return false;
    }
    let mut target = vec![0u8; data_size];
    if io.unp_read(&mut target, arc) as usize != data_size {
        return false;
    }
    let tlen = target.iter().position(|&b| b == 0).unwrap_or(target.len());
    io.unp_hash.init(arc.file_head.file_hash.kind);
    io.unp_hash.update(&target[..tlen]);
    let key = if arc.file_head.use_hash_key { Some(&arc.file_head.hash_key) } else { None };
    if !io.unp_hash.cmp(&arc.file_head.file_hash, key) {
        return true;
    }
    let target = &target[..tlen];
    let target_w = match safe_char_to_wide(target) {
        Some(t) => t,
        None => return false,
    };
    if !cmd.absolute_links
        && (target_w.starts_with(CPATHDIVIDER) || !is_relative_symlink_safe(cmd, &arc.file_head.file_name, link_name, &target_w))
    {
        ui_msg(UiMsg::SkipUnsafeLink(arc.file_head.file_name.clone(), target_w));
        set_error_code(RARX_WARNING);
        return false;
    }
    *up_link = target.windows(2).any(|w| w == b"..");
    unix_symlink(cmd, target, link_name)
}

fn extract_unix_link50(cmd: &CommandData, name: &str, hd: &FileHeader) -> bool {
    let mut target = wide_to_char(&hd.redir_name);
    if hd.redir_type == FsRedir::WinSymlink || hd.redir_type == FsRedir::Junction {
        if target.starts_with(b"\\??\\") || target.starts_with(b"/??/") {
            target.drain(..4);
        }
        for b in target.iter_mut() {
            if *b == b'\\' {
                *b = b'/';
            }
        }
    }
    let target_w = match safe_char_to_wide(&target) {
        Some(t) => t,
        None => return false,
    };
    if !cmd.absolute_links && (target_w.starts_with(CPATHDIVIDER) || !is_relative_symlink_safe(cmd, &hd.file_name, name, &target_w)) {
        ui_msg(UiMsg::SkipUnsafeLink(hd.file_name.clone(), target_w));
        set_error_code(RARX_WARNING);
        return false;
    }
    unix_symlink(cmd, &target, name)
}

pub fn extract_symlink(cmd: &CommandData, io: &mut ComprDataIO, arc: &mut Archive, link_name: &str, up_link: &mut bool) -> bool {
    *up_link = true;
    if arc.format == RarFormat::Rar50 {
        *up_link = arc.file_head.redir_name.contains("..");
    }
    if cfg!(unix) {
        if arc.format == RarFormat::Rar15 {
            return extract_unix_link30(cmd, io, arc, link_name, up_link);
        }
        if arc.format == RarFormat::Rar50 {
            let hd = arc.file_head.clone();
            return extract_unix_link50(cmd, link_name, &hd);
        }
    }
    if cfg!(windows) && arc.format == RarFormat::Rar50 {
        let hd = arc.file_head.clone();
        return create_windows_link(cmd, link_name, &hd);
    }
    false
}

/// Create a symbolic link or junction in Windows.
fn create_windows_link(cmd: &CommandData, name: &str, hd: &FileHeader) -> bool {
    let subst = &hd.redir_name;
    let win_prefix = subst.starts_with("\\??\\");
    let mut target = if win_prefix { subst[4..].to_string() } else { subst.clone() };
    if win_prefix && target.starts_with("UNC\\") {
        target = format!("\\{}", &target[3..]);
    }
    if !cmd.absolute_links
        && (win_prefix || is_full_path(subst) || hd.redir_type == FsRedir::Junction || !is_relative_symlink_safe(cmd, &hd.file_name, name, subst))
    {
        ui_msg(UiMsg::SkipUnsafeLink(hd.file_name.clone(), hd.redir_name.clone()));
        set_error_code(RARX_WARNING);
        return false;
    }
    create_path(name, true, cmd.disable_names);
    if file_exist(name) {
        if is_dir(get_file_attr(name)) {
            del_dir(name);
        } else {
            del_file(name);
        }
    }
    let is_dir_link = hd.dir || hd.dir_target;
    let link_done = |name: &str| {
        let mtime = if cmd.xmtime == ExtTimeMode::None { None } else { Some(&hd.mtime) };
        let ctime = if cmd.xctime == ExtTimeMode::None { None } else { Some(&hd.ctime) };
        let atime = if cmd.xatime == ExtTimeMode::None { None } else { Some(&hd.atime) };
        crate::file::set_file_times_by_name(name, mtime, ctime, atime);
        if !cmd.ignore_general_attr {
            set_file_attr(name, hd.file_attr);
        }
    };
    if hd.redir_type == FsRedir::Junction {
        // Junctions have no creation API, so write the reparse point data
        // to an empty directory.
        if let Err(e) = std::fs::create_dir(to_path(name)) {
            set_os_error(&e);
            ui_msg(UiMsg::DirCreate(String::new(), name.to_string()));
            set_error_code(RARX_CREATE);
            return false;
        }
        if !crate::winsys::create_reparse_point(name, true, subst, &target, win_prefix, true) {
            return false;
        }
        link_done(name);
        return true;
    }
    #[cfg(windows)]
    let r = if is_dir_link {
        std::os::windows::fs::symlink_dir(to_path(&target), to_path(name))
    } else {
        std::os::windows::fs::symlink_file(to_path(&target), to_path(name))
    };
    #[cfg(not(windows))]
    let r: std::io::Result<()> = {
        let _ = (is_dir_link, &target);
        Err(std::io::Error::other("not supported"))
    };
    match r {
        Ok(()) => {
            link_done(name);
            true
        }
        Err(e) => {
            set_os_error(&e);
            ui_msg(UiMsg::SLinkCreate(String::new(), name.to_string()));
            if matches!(e.raw_os_error(), Some(5) | Some(1314)) && !crate::extinfo::is_user_admin() {
                // ERROR_ACCESS_DENIED or ERROR_PRIVILEGE_NOT_HELD.
                ui_msg(UiMsg::NeedAdmin);
            }
            sys_err_msg();
            set_error_code(RARX_CREATE);
            false
        }
    }
}

/// Extract NTFS alternate data stream stored in service header.
fn extract_streams(cmd: &CommandData, arc: &mut Archive, file_name: &str) {
    let stream_name = get_stream_name_ntfs(arc);
    if !stream_name.starts_with(':') || stream_name.contains(['\\', '/']) {
        ui_msg(UiMsg::StreamBroken(arc.file_name().to_string(), file_name.to_string()));
        set_error_code(RARX_CRC);
        return;
    }
    let full = format!("{}{}", file_name, stream_name);
    if cmd.test {
        if !cmd.disable_names {
            crate::consio::mprintf(&crate::wfmt!(crate::loclang::MExtrTestFile, full.as_str()));
        }
        let mut f = crate::file::File::new();
        if arc.read_sub_data(false, Some(&mut f), true).0 && !cmd.disable_names && !cmd.disable_percentage {
            crate::consio::mprintf(&crate::wfmt!(" %s", crate::loclang::MOk));
        }
        return;
    }
    let full = if file_name.chars().count() == 1 { format!(".\\{}", full) } else { full };
    // If we already propagated the archive Mark of the Web to extracted file,
    // overwrite it only if file zone is stricter.
    let mut parsed_motw = Vec::new();
    if arc.motw.is_name_conflicting(&stream_name) {
        let (ok, mut file_motw) = arc.read_sub_data(true, None, false);
        if !ok || !arc.motw.is_file_stream_more_secure(&mut file_motw) {
            return;
        }
        parsed_motw = file_motw;
    }
    if is_ntfs_prohibited_stream(&stream_name) {
        return;
    }
    let mut fd = FindData::default();
    let host_found = fast_find(file_name, &mut fd, false);
    if fd.file_attr & 1 != 0 {
        set_file_attr(file_name, fd.file_attr & !1);
    }
    let mut f = crate::file::File::new();
    if f.w_create(&full, crate::file::FMF_UPDATE | crate::file::FMF_SHAREREAD) {
        f.set_allow_delete(!cmd.keep_broken);
        if !cmd.disable_names {
            crate::consio::mprintf(&crate::wfmt!(crate::loclang::MExtrFile, full.as_str()));
        }
        if !parsed_motw.is_empty() {
            // The archive zone is either missing or less strict than file one.
            f.write(&parsed_motw);
            f.keep();
            f.close();
        } else if arc.read_sub_data(false, Some(&mut f), false).0 {
            f.keep();
            f.close();
            if !cmd.disable_names && !cmd.disable_percentage {
                crate::consio::mprintf(&crate::wfmt!(" %s", crate::loclang::MOk));
            }
        }
    }
    if host_found {
        crate::file::set_file_times_by_name(file_name, Some(&fd.mtime), Some(&fd.ctime), Some(&fd.atime));
    }
    if fd.file_attr & 1 != 0 {
        set_file_attr(file_name, fd.file_attr);
    }
}

pub fn extract_hardlink(cmd: &CommandData, name_new: &str, name_existing: &str) -> bool {
    if !file_exist(name_existing) {
        ui_msg(UiMsg::HLinkCreate(name_new.to_string()));
        ui_msg(UiMsg::NoLinkTarget);
        set_error_code(RARX_CREATE);
        return false;
    }
    create_path(name_new, true, cmd.disable_names);
    match std::fs::hard_link(to_path(name_existing), to_path(name_new)) {
        Ok(()) => true,
        Err(e) => {
            set_os_error(&e);
            ui_msg(UiMsg::HLinkCreate(name_new.to_string()));
            sys_err_msg();
            set_error_code(RARX_CREATE);
            false
        }
    }
}

pub fn get_stream_name_ntfs(arc: &Archive) -> String {
    if arc.format == RarFormat::Rar15 {
        crate::unicode::raw_to_wide(&arc.sub_head.sub_data)
    } else {
        crate::unicode::utf_to_wide(&arc.sub_head.sub_data)
    }
}
