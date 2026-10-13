// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Integration tests: run the rarust command on fixture archives.
//! Fixtures g4_* and g5_* were created by RAR 6.24 and 7.23 from the
//! files in tests/data/src. ppmd_restart.rar was made by a PPMd encoder
//! written for testing and verified with unrar 7.00.

use std::path::{Path, PathBuf};

fn data() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data")
}

fn run(args: &[&str]) -> i32 {
    let mut a: Vec<String> = vec!["-cfg-".into(), "-idq".into()];
    a.extend(args.iter().map(|s| s.to_string()));
    // Each test runs in its own thread, so global UI and error state is separate.
    std::thread::spawn(move || rarust::run(a)).join().unwrap()
}

fn arc(name: &str) -> String {
    data().join(name).to_string_lossy().into_owned()
}

fn tmp_dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("rarust-test-{}-{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

const GEN: &[&str] = &[
    "g5_m0.rar", "g5_m3.rar", "g5_m5_solid.rar", "g5_enc.rar", "g5_hp.rar", "g5_blake.rar", "g5_vol.part01.rar",
    "g5_links.rar", "g5_cmt.rar", "g5_qo_rr.rar", "g4_m0.rar", "g4_m3.rar", "g4_ppm.rar", "g4_enc.rar", "g4_hp.rar",
    "g4_vol.part01.rar", "g4_volold.rar", "g4_links.rar", "g4_cmt.rar",
];

#[test]
fn test_generated_archives() {
    for a in GEN {
        assert_eq!(run(&["t", "-ppass", &arc(a)]), 0, "{}", a);
    }
}

#[test]
fn test_legacy_fixtures() {
    for a in ["comment.rar", "solid.rar", "unicode.rar", "utf8.rar", "version.rar", "locked.rar", "recovery-record.rar"] {
        assert_eq!(run(&["t", &arc(a)]), 0, "{}", a);
    }
    assert_eq!(run(&["t", "-punrar", &arc("crypted.rar")]), 0);
    assert_eq!(run(&["t", "-ppassword", &arc("comment-hpw-password.rar")]), 0);
}

fn compare_tree(src: &Path, dst: &Path) {
    for e in std::fs::read_dir(src).unwrap() {
        let e = e.unwrap();
        let p = e.path();
        let q = dst.join(e.file_name());
        let m = std::fs::symlink_metadata(&p).unwrap();
        if m.file_type().is_symlink() {
            continue;
        } else if m.is_dir() {
            compare_tree(&p, &q);
        } else {
            assert_eq!(std::fs::read(&p).unwrap(), std::fs::read(&q).unwrap(), "{:?}", q);
        }
    }
}

#[test]
fn extract_matches_source() {
    for a in ["g5_m5_solid.rar", "g4_ppm.rar", "g5_vol.part01.rar", "g4_volold.rar", "g4_enc.rar"] {
        let d = tmp_dir(a);
        let dest = format!("{}/", d.display());
        assert_eq!(run(&["x", "-ppass", "-y", &arc(a), &dest]), 0, "{}", a);
        compare_tree(&data().join("src"), &d);
        let _ = std::fs::remove_dir_all(&d);
    }
}

#[test]
fn wrong_password() {
    assert_eq!(run(&["t", "-pwrong", &arc("g5_enc.rar")]), 11);
    assert_eq!(run(&["t", "-pwrong", &arc("g5_hp.rar")]), 11);
    assert_eq!(run(&["t", "-pwrong", &arc("g4_enc.rar")]), 3);
}

#[test]
fn damaged_archive() {
    let d = tmp_dir("damaged");
    let mut b = std::fs::read(data().join("g5_m3.rar")).unwrap();
    let n = b.len();
    b[n / 2] ^= 0x55;
    let p = d.join("bad.rar");
    std::fs::write(&p, b).unwrap();
    assert_eq!(run(&["t", &p.to_string_lossy()]), 3);
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn recovery_volume_restore() {
    let d = tmp_dir("rev");
    for e in std::fs::read_dir(data()).unwrap() {
        let e = e.unwrap();
        let n = e.file_name().to_string_lossy().into_owned();
        if n.starts_with("g5_vol.") {
            std::fs::copy(e.path(), d.join(&n)).unwrap();
        }
    }
    std::fs::remove_file(d.join("g5_vol.part02.rar")).unwrap();
    let first = d.join("g5_vol.part01.rar").to_string_lossy().into_owned();
    assert_eq!(run(&["t", &first]), 0);
    assert!(d.join("g5_vol.part02.rar").exists());
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn listing() {
    for a in GEN {
        assert_eq!(run(&["lt", "-ppass", &arc(a)]), 0, "{}", a);
    }
}

/// Data of ppmd_restart.rar, made by xorshift32 generator: pseudo words and
/// biased random bytes.
fn xorshift(x: &mut u32) -> u32 {
    *x ^= *x << 13;
    *x ^= *x >> 17;
    *x ^= *x << 5;
    *x
}

fn ppmd_text(n: usize) -> Vec<u8> {
    const SYL: [&str; 32] = [
        "ka", "lo", "mi", "nu", "re", "sa", "to", "vi", "ber", "dan", "fol", "gim", "hur", "jes", "kol", "lum", "mar", "nos",
        "pil", "quo", "ras", "sel", "tun", "ulm", "vor", "wex", "yal", "zen", "ab", "ef", "ix", "ou",
    ];
    let mut x = 0x12345678;
    let mut out = Vec::new();
    while out.len() < n {
        for _ in 0..1 + xorshift(&mut x) % 3 {
            out.extend_from_slice(SYL[(xorshift(&mut x) % 32) as usize].as_bytes());
        }
        out.push(if xorshift(&mut x).is_multiple_of(16) { b'\n' } else { b' ' });
    }
    out.truncate(n);
    out
}

fn ppmd_binary(n: usize) -> Vec<u8> {
    let mut x = 0x9e3779b9;
    (0..n)
        .map(|_| {
            let v = xorshift(&mut x);
            (v & 0x3f) as u8 | if v & 0x300 == 0 { 0x80 } else { 0 }
        })
        .collect()
}

/// PPMd order 64 with 1 MB of memory: the model memory is exhausted, so
/// free blocks are glued and the model is restarted several times.
#[test]
fn ppmd_model_restart() {
    let d = tmp_dir("ppmd");
    let dest = format!("{}/", d.display());
    assert_eq!(run(&["x", "-y", &arc("ppmd_restart.rar"), &dest]), 0);
    assert!(std::fs::read(d.join("ppm_text.txt")).unwrap() == ppmd_text(200000));
    assert!(std::fs::read(d.join("ppm_bin.dat")).unwrap() == ppmd_binary(30000));
    let _ = std::fs::remove_dir_all(&d);
}
