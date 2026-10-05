<div align="center">

# rarust

**Fast, dependency-free RAR extractor written in Rust**

[![Rust](https://img.shields.io/badge/Rust-orange?logo=rust)](https://www.rust-lang.org)
[![License: MPL 2.0](https://img.shields.io/badge/License-MPL_2.0-brightgreen.svg)](LICENSE)
[![Platforms](https://img.shields.io/badge/platforms-Linux%20%7C%20Windows-lightgrey)](#building)

**English** · [Русский](README.ru.md)

</div>

---

`rarust` lists, tests and extracts RAR archives of every version, from RAR 1.4
to RAR 7. It is written in Rust using only the standard library: no external
crates, no C code, no bundled binaries.

```text
$ rarust x photos.rar ~/Pictures/

Extracting from photos.rar

Creating    /home/user/Pictures/2024                                 OK
Extracting  /home/user/Pictures/2024/beach.jpg                       100%  OK
Extracting  /home/user/Pictures/2024/sunset.jpg                      100%  OK
All OK
```

## Contents

- [Features](#features)
- [Quick start](#quick-start)
- [Usage](#usage)
- [Building](#building)
- [Platform notes](#platform-notes)
- [Project layout](#project-layout)
- [Testing](#testing)
- [License](#license)

## Features

| Area | Supported |
|---|---|
| **Archive formats** | RAR 1.4, RAR 1.5–4.x, RAR 5.0 / 7.0, self-extracting (SFX) archives |
| **Compression** | RAR 1.5, 2.x (incl. audio), 3.x (LZ, PPMd, VM filters), 5.0/7.0 (E8, E8E9, ARM, Delta filters) |
| **Dictionaries** | Up to 1 TB (RAR 7), multithreaded RAR 5 decoding |
| **Encryption** | RAR 1.3, 1.5, 2.0, AES-128 (RAR 3.x), AES-256 (RAR 5.0), encrypted headers, password check values |
| **Integrity** | CRC32, BLAKE2sp, checksum MACs for encrypted files |
| **Volumes** | Multivolume archives with new (`.partN.rar`) and old (`.rNN`) naming |
| **Recovery** | Recovery volumes for RAR 3.x and 5.0: test and rebuild missing volumes |
| **Extras** | Solid archives, archive and file comments, quick open records, file versions |
| **Links** | Symbolic links, hard links, file references, junctions |
| **Metadata** | Modification, creation and access times, attributes, Unix owners |
| **Windows** | NTFS streams, security descriptors (ACL), Mark of the Web, NTFS compression, OEM/ANSI code pages |
| **Safety** | Path traversal and unsafe link protection, archive data never trusted |

Highlights:

- **Zero dependencies.** Hashes (CRC32, BLAKE2sp, SHA-1, SHA-256), AES, PBKDF2
  and all decompressors are implemented in the crate itself.
- **Tested.** Verified on hundreds of archives created by different RAR
  versions: listings, test results, exit codes and extracted files.
- **Robust.** Fuzzed with corrupted archives: no panics and no hangs.
- **Minimal unsafe code.** Only operating system calls in two small modules,
  `src/win32.rs` and `src/unixsig.rs`. Everything else is safe Rust.

## Quick start

```bash
git clone https://github.com/Kolya62/rarust.git
cd rarust
cargo build --release
./target/release/rarust x archive.rar
```

## Usage

```text
rarust <command> -<switch 1> -<switch N> <archive> <files...> <path_to_extract/>
```

### Commands

| Command | Description |
|---|---|
| `x` | Extract files with full paths |
| `e` | Extract files without archived paths |
| `t` | Test archive files |
| `l[t[a],b]` | List archive contents (technical, all, bare) |
| `v[t,a,b]` | Verbosely list archive contents |
| `p` | Print file to stdout |

### Examples

```bash
# Extract everything into a folder
rarust x archive.rar out/

# Test an encrypted archive
rarust t -pSecret archive.rar

# Extract only text files, overwrite without asking
rarust x -o+ archive.rar '*.txt' out/

# Technical listing with times, hashes and attributes
rarust lt archive.rar

# Extract a multivolume archive (start from any volume)
rarust x backup.part01.rar

# Print a file to stdout
rarust p -inul archive.rar readme.txt | less
```

Frequently used switches:

| Switch | Meaning |
|---|---|
| `-p<pwd>` | Set password (`-p` alone asks for it) |
| `-o+` / `-o-` | Overwrite / skip existing files |
| `-or` | Rename extracted files automatically |
| `-y` | Assume Yes on all queries |
| `-x<mask>` | Exclude files |
| `-r` | Recurse subdirectories |
| `-ola` | Allow links with absolute paths (trusted archives only) |
| `-ts` | Restore modification, creation and access times |
| `-ow` | Restore owners (Unix) or security descriptors (Windows) |
| `-idq` | Quiet mode |

Run `rarust` without parameters for the full list of switches.

### Exit codes

| Code | Meaning | Code | Meaning |
|---|---|---|---|
| 0 | Success | 7 | Wrong command line |
| 1 | Non-fatal warning | 8 | Not enough memory |
| 2 | Fatal error | 9 | File create error |
| 3 | CRC error | 10 | No files to extract |
| 4 | Locked archive | 11 | Wrong password |
| 5 | Write error | 12 | Read error |
| 6 | Open error | 255 | User break (Ctrl+C) |

## Building

Requires Rust 1.87 or newer.

```bash
cargo build --release            # Linux and other Unix systems
cargo test --release             # unit and integration tests
```

### Windows

Native build with the MSVC or GNU toolchain:

```bash
cargo build --release
```

Cross-compilation from Linux with [llvm-mingw](https://github.com/mstorsjo/llvm-mingw):

```bash
rustup target add x86_64-pc-windows-gnullvm
export CARGO_TARGET_X86_64_PC_WINDOWS_GNULLVM_LINKER=/path/to/llvm-mingw/bin/x86_64-w64-mingw32-clang
cargo build --release --target x86_64-pc-windows-gnullvm
```

The C runtime is linked statically (see `.cargo/config.toml`), so
`rarust.exe` runs on Windows 10 and later without extra DLLs.

## Platform notes

**Linux / Unix**

- Unix permissions, owners and groups (`-ow`), symbolic links.
- Local time zone from `/etc/localtime` or the `TZ` variable.
- Ctrl+C deletes the incompletely extracted file and exits with code 255.

**Windows**

- File and directory attributes, creation time, NTFS alternate data streams.
- Junctions and symbolic links. Symbolic links require administrator rights
  or Developer Mode.
- NTFS security descriptors (`-ow`). Security descriptors from the archive
  are validated before they are passed to the system. Owners and audit data
  require administrator rights.
- Mark of the Web propagation (`-om[1][=masks]`) and NTFS compression (`-oc`).
- OEM and ANSI code pages for legacy archive names, comments and passwords.
- Reserved and invalid file names are corrected (`-oni` to keep them).
- Process priority and pauses (`-ri`), power off after completion (`-ioff`).
- Both `-switch` and `/switch` syntax.

## Project layout

```text
src/
├── main.rs, lib.rs      Command line entry point
├── cmddata.rs           Command line and switch parsing
├── archive.rs           Archive headers (RAR 1.4, 1.5–4.x, 5.0)
├── extract.rs, list.rs  Extract, test and list commands
├── unpack/              Decompressors: v15, v20, v30 (+ RarVM, PPMd), v50, v50mt
├── crypt/               RAR 1.3–3.x ciphers, AES
├── hash/                CRC32, BLAKE2sp, SHA-1, SHA-256, HMAC, PBKDF2
├── recvol.rs            Recovery volumes (Reed-Solomon 8 and 16 bit)
├── volume.rs            Multivolume archives
├── extinfo.rs, motw.rs  Links, owners, ACLs, streams, Mark of the Web
├── tz.rs, timefn.rs     Time zones (TZif, POSIX TZ rules) and time formats
├── win32.rs, winsys.rs  Windows API calls and services
└── unixsig.rs           Unix signal handling
```

## Testing

```bash
cargo test --release
```

- Unit tests: hash, AES and PBKDF2 test vectors, time zone rules, security
  descriptor validation, reparse point data.
- Integration tests in `tests/` on archives created by RAR 6 and RAR 7:
  compression methods, solid and encrypted archives, volumes, recovery
  volumes, comments, links and Unicode names.

## License

Distributed under the [Mozilla Public License 2.0](LICENSE).
