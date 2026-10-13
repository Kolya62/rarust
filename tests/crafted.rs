// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Tests with archives built at test time: hostile names and links, which
//! RAR itself does not create.

use rarust::hash::crc32::crc32;
use std::path::{Path, PathBuf};

fn run(args: &[&str]) -> i32 {
    let mut a: Vec<String> = vec!["-cfg-".into(), "-idq".into()];
    a.extend(args.iter().map(|s| s.to_string()));
    std::thread::spawn(move || rarust::run(a)).join().unwrap()
}

fn tmp_dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("rarust-crafted-{}-{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn vint(mut n: u64) -> Vec<u8> {
    let mut v = Vec::new();
    loop {
        let b = (n & 0x7f) as u8;
        n >>= 7;
        if n == 0 {
            v.push(b);
            return v;
        }
        v.push(b | 0x80);
    }
}

/// RAR 5.0 header block with optional extra area and data.
fn block(htype: u64, body: &[u8], extra: &[u8], data: Option<&[u8]>) -> Vec<u8> {
    let mut flags = 0;
    if !extra.is_empty() {
        flags |= 1;
    }
    if data.is_some() {
        flags |= 2;
    }
    let mut fields = vint(htype);
    fields.extend(vint(flags));
    if !extra.is_empty() {
        fields.extend(vint(extra.len() as u64));
    }
    if let Some(d) = data {
        fields.extend(vint(d.len() as u64));
    }
    fields.extend_from_slice(body);
    fields.extend_from_slice(extra);
    let mut hdr = vint(fields.len() as u64);
    hdr.extend(fields);
    let mut out = (crc32(0xffffffff, &hdr) ^ 0xffffffff).to_le_bytes().to_vec();
    out.extend(hdr);
    if let Some(d) = data {
        out.extend_from_slice(d);
    }
    out
}

/// Stored file, directory or link.
struct Entry {
    name: &'static str,
    data: Vec<u8>,
    dir: bool,
    attr: u64,
    /// Redirection type and target.
    redir: Option<(u64, &'static str)>,
}

fn file(name: &'static str, data: &[u8]) -> Entry {
    Entry { name, data: data.to_vec(), dir: false, attr: 0o100644, redir: None }
}

fn dir(name: &'static str, attr: u64) -> Entry {
    Entry { name, data: Vec::new(), dir: true, attr, redir: None }
}

fn link(name: &'static str, rtype: u64, target: &'static str) -> Entry {
    Entry { name, data: Vec::new(), dir: false, attr: 0o120777, redir: Some((rtype, target)) }
}

fn archive(entries: &[Entry]) -> Vec<u8> {
    let mut out = b"Rar!\x1a\x07\x01\x00".to_vec();
    out.extend(block(1, &vint(0), &[], None));
    for e in entries {
        // Directory flag, mtime and CRC32 present.
        let mut fflags = 2;
        if e.dir {
            fflags |= 1;
        } else {
            fflags |= 4;
        }
        let mut body = vint(fflags);
        body.extend(vint(e.data.len() as u64));
        body.extend(vint(e.attr));
        body.extend_from_slice(&1_000_000_000u32.to_le_bytes());
        if !e.dir {
            body.extend_from_slice(&(crc32(0xffffffff, &e.data) ^ 0xffffffff).to_le_bytes());
        }
        // Store method, Unix host.
        body.extend(vint(0));
        body.extend(vint(1));
        body.extend(vint(e.name.len() as u64));
        body.extend_from_slice(e.name.as_bytes());
        let mut extra = Vec::new();
        if let Some((rtype, target)) = e.redir {
            let mut rec = vint(5);
            rec.extend(vint(rtype));
            rec.extend(vint(0));
            rec.extend(vint(target.len() as u64));
            rec.extend_from_slice(target.as_bytes());
            extra.extend(vint(rec.len() as u64));
            extra.extend(rec);
        }
        out.extend(block(2, &body, &extra, if e.dir { None } else { Some(&e.data) }));
    }
    out.extend(block(5, &vint(0), &[], None));
    out
}

fn write_arc(d: &Path, entries: &[Entry]) -> String {
    let p = d.join("arc.rar");
    std::fs::write(&p, archive(entries)).unwrap();
    p.to_string_lossy().into_owned()
}

fn dest(d: &Path) -> (PathBuf, String) {
    let dst = d.join("parent").join("dest");
    std::fs::create_dir_all(&dst).unwrap();
    let s = format!("{}/", dst.display());
    (dst, s)
}

#[test]
fn crafted_archive_is_valid() {
    let d = tmp_dir("valid");
    let a = write_arc(&d, &[dir("sub", 0o40755), file("sub/a.txt", b"hello")]);
    assert_eq!(run(&["t", &a]), 0);
    let (dst, ds) = dest(&d);
    assert_eq!(run(&["x", "-y", &a, &ds]), 0);
    assert_eq!(std::fs::read(dst.join("sub/a.txt")).unwrap(), b"hello");
    let _ = std::fs::remove_dir_all(&d);
}

/// Directory named ".." must not change attributes or times of the parent
/// of destination folder.
#[cfg(unix)]
#[test]
fn dot_dot_dir_entry() {
    use std::os::unix::fs::PermissionsExt;
    let d = tmp_dir("dotdot");
    let a = write_arc(&d, &[dir("..", 0o40777), dir("x/..", 0o40777), file("ok.txt", b"ok")]);
    let (dst, ds) = dest(&d);
    let parent = dst.parent().unwrap().to_path_buf();
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o755)).unwrap();
    let before = std::fs::metadata(&parent).unwrap();
    run(&["x", "-y", &a, &ds]);
    let after = std::fs::metadata(&parent).unwrap();
    assert_eq!(after.permissions().mode() & 0o7777, 0o755);
    assert_eq!(after.modified().unwrap(), before.modified().unwrap());
    assert_eq!(std::fs::read(dst.join("ok.txt")).unwrap(), b"ok");
    let _ = std::fs::remove_dir_all(&d);
}

/// Files with different archived names but the same destination must be
/// extracted in archive order even if parallel extraction is enabled.
#[test]
fn same_destination_in_order() {
    let d = tmp_dir("samedest");
    let mut entries = Vec::new();
    // Enough files large enough to enable parallel extraction.
    const NAMES: [&str; 8] = ["f0", "f1", "f2", "f3", "f4", "f5", "f6", "f7"];
    for n in NAMES {
        entries.push(file(n, &n.as_bytes().repeat(40000)));
    }
    let big_first = vec![b'1'; 300000];
    let small_last = vec![b'2'; 40000];
    entries.push(Entry { name: "x/../same", ..file("", &big_first) });
    entries.push(Entry { name: "./same", ..file("", &small_last) });
    let a = write_arc(&d, &entries);
    for _ in 0..5 {
        let (dst, ds) = dest(&d);
        assert_eq!(run(&["x", "-y", "-mt4", &a, &ds]), 0);
        assert_eq!(std::fs::read(dst.join("same")).unwrap(), small_last);
        let _ = std::fs::remove_dir_all(&dst);
    }
    let _ = std::fs::remove_dir_all(&d);
}

/// Absolute Windows links cannot be created in Unix, even with -ola.
#[cfg(unix)]
#[test]
fn windows_absolute_link() {
    let d = tmp_dir("winlink");
    let a = write_arc(&d, &[link("lnk", 2, "\\??\\C:\\Windows"), file("ok.txt", b"ok")]);
    let (dst, ds) = dest(&d);
    run(&["x", "-y", "-ola", &a, &ds]);
    assert!(std::fs::symlink_metadata(dst.join("lnk")).is_err());
    let _ = std::fs::remove_dir_all(&d);
}

/// Links pointing outside of destination are skipped unless -ola is used.
#[cfg(unix)]
#[test]
fn unsafe_symlinks() {
    let d = tmp_dir("unsafe");
    let a = write_arc(
        &d,
        &[
            link("abs", 1, "/etc"),
            link("up", 1, "../x"),
            link("sub/up2", 1, "../../x"),
            link("sub/ok", 1, "../ok.txt"),
            link("lnk1", 1, "."),
            link("lnk1/lnk2", 1, ".."),
            file("ok.txt", b"ok"),
        ],
    );
    let (dst, ds) = dest(&d);
    run(&["x", "-y", &a, &ds]);
    for n in ["abs", "up", "sub/up2"] {
        assert!(std::fs::symlink_metadata(dst.join(n)).is_err(), "{}", n);
    }
    assert_eq!(std::fs::read(dst.join("sub/ok")).unwrap(), b"ok");
    // "lnk1" symlink is replaced by a folder before creating "lnk1/lnk2",
    // so the second link must point inside of destination.
    let root = dst.canonicalize().unwrap();
    if let Ok(p) = dst.join("lnk1/lnk2").canonicalize() {
        assert!(p.starts_with(&root), "{:?}", p);
    }
    let _ = std::fs::remove_dir_all(&d);
}
