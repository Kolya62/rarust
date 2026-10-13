// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Parallel extraction of independent files in non-solid archives.
//!
//! Every file in a non-solid archive is compressed separately, so files of
//! any RAR version can be decompressed concurrently. Worker threads open
//! the archive themselves and process whole files taken from a shared
//! queue. Their console output and error codes are recorded and replayed
//! by the main thread in archive order, so the output and exit code are
//! the same as with sequential extraction. Directories are processed by
//! the main thread after all preceding files, so their times are not
//! changed by files extracted later. Small files are also extracted by the
//! main thread, because file system operations dominate for them.

use crate::archive::Archive;
use crate::cmddata::{CommandData, OverwriteMode};
use crate::consio::{self, CapturedEvent};
use crate::errhnd::{self, RarExit, RARX_FATAL};
use crate::headers::*;
use crate::pathfn::{convert_path, is_path_div, is_wildcard, point_to_name};
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc;

/// Memory budget for dictionaries of all workers together.
const WINDOW_MEMORY_BUDGET: u64 = 2 << 30;

/// Files smaller than this are extracted by the main thread. Creating many
/// small files in parallel is slower, because file system operations
/// dominate and do not scale.
const MIN_PARALLEL_FILE_SIZE: i64 = 32 * 1024;

/// Header positions belonging to one archived file: the file header and
/// following service headers, such as NTFS streams or security data.
pub struct Group {
    pub headers: Vec<i64>,
    /// Processed by the main thread: directories, small files and leading
    /// headers.
    pub main_thread: bool,
}

pub struct Plan {
    pub groups: Vec<Group>,
    /// Position of the end of archive header, or of the place where
    /// headers end if the archive is truncated.
    pub end_pos: i64,
    pub workers: usize,
}

/// Result of processing one group by a worker.
pub struct GroupResult {
    pub events: Vec<CapturedEvent>,
    /// false if extraction of the archive must stop after this group.
    pub proceed: bool,
    /// Exit code if a fatal error aborted processing.
    pub fatal: Option<i32>,
}

/// Counters collected from workers.
#[derive(Default)]
pub struct Counters {
    pub total_file_count: u64,
    pub file_count: u64,
    pub matched_args: u64,
    pub suppress_no_files_message: bool,
}

/// Decide if the archive can be extracted in parallel. Reads all headers
/// starting from the current position and restores it afterwards.
pub fn plan(cmd: &CommandData, arc: &mut Archive, command: char) -> Option<Plan> {
    if !matches!(command, 'X' | 'E' | 'T') || cmd.threads < 2 || !cmd.use_stdin.is_empty() {
        return None;
    }
    if arc.solid || arc.volume || arc.encrypted && !cmd.password_set() {
        return None;
    }
    // Interactive overwrite prompts and automatic renaming depend on the
    // order of extraction.
    let overwrite_ok = cmd.test
        || matches!(cmd.overwrite, OverwriteMode::All | OverwriteMode::None)
        || cmd.overwrite == OverwriteMode::Default && cmd.all_yes;
    if !overwrite_ok {
        return None;
    }
    // Exact file names stop extraction when all of them are found.
    if cmd.file_args.items().iter().any(|a| !is_wildcard(a)) {
        return None;
    }
    // Read headers silently. Any message or error means a damaged archive,
    // which is extracted sequentially to report problems in usual order.
    let start = arc.tell();
    let errors = errhnd::error_state();
    consio::capture_start();
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| scan(cmd, arc, command)));
    let events = consio::capture_take();
    errhnd::restore_error_state(errors);
    arc.seek(start, crate::file::SEEK_SET);
    match r {
        Ok(plan) if events.is_empty() && !arc.broken_header => plan,
        _ => None,
    }
}

/// Destination path of archived name split to lowercase components,
/// without "." components and dangerous prefixes, so names like "a/./b",
/// "x/../a/b" and "A/B" give the same key.
fn dest_key(name: &str, flat: bool) -> Vec<String> {
    let (_, conv) = convert_path(name);
    let conv = if flat { point_to_name(&conv) } else { conv.as_str() };
    conv.split(is_path_div)
        .filter(|c| !c.is_empty() && *c != ".")
        .map(|c| {
            let c = c.to_lowercase();
            // Windows ignores trailing dots and spaces in names.
            if cfg!(windows) {
                c.trim_end_matches(['.', ' ']).to_string()
            } else {
                c
            }
        })
        .collect()
}

/// Destination paths seen in the archive. Files must be extracted in archive
/// order if they have the same destination or if one of them is a folder
/// containing another.
#[derive(Default)]
struct DestNames {
    files: HashSet<Vec<String>>,
    dirs: HashSet<Vec<String>>,
}

impl DestNames {
    /// Add a name. Returns false on conflict with already added names.
    fn add(&mut self, key: Vec<String>, dir: bool) -> bool {
        for i in 1..key.len() {
            let parent = &key[..i];
            if self.files.contains(parent) {
                return false;
            }
            self.dirs.insert(parent.to_vec());
        }
        if dir {
            !self.files.contains(&key) && {
                self.dirs.insert(key);
                true
            }
        } else {
            !self.dirs.contains(&key) && self.files.insert(key)
        }
    }
}

fn scan(cmd: &CommandData, arc: &mut Archive, command: char) -> Option<Plan> {
    let mut groups: Vec<Group> = Vec::new();
    let mut names = DestNames::default();
    let mut max_window = 0u64;
    let mut end_pos;
    // Name transformations other than path removal are not tracked, so
    // compare only names without path for them.
    let flat_names = command == 'E'
        || cmd.excl_path != crate::cmddata::PathExclMode::Unchanged
        || !cmd.arc_path.is_empty()
        || !cmd.excl_arc_path.is_empty();
    loop {
        // Where sequential processing continues after parallel extraction:
        // the end of archive header or the place where headers end.
        end_pos = arc.tell();
        if arc.read_header() == 0 {
            break;
        }
        if arc.broken_header {
            return None;
        }
        let pos = arc.cur_block_pos;
        let ht = arc.get_header_type();
        if ht == HEAD_ENDARC {
            if arc.end_arc_head.next_volume {
                return None;
            }
            end_pos = pos;
            break;
        }
        if ht == HEAD_FILE {
            let h = &arc.file_head;
            if h.split_before || h.split_after || h.solid || h.redir_type != FsRedir::None {
                return None;
            }
            if h.encrypted && !cmd.password_set() {
                return None;
            }
            // Files with the same destination name must be processed in
            // archive order.
            if !names.add(dest_key(&h.file_name, flat_names), h.dir) {
                return None;
            }
            if !h.dir {
                max_window = max_window.max(h.win_size);
            }
            // Key derivation for encrypted files takes long regardless of
            // the file size.
            let small = h.unp_size < MIN_PARALLEL_FILE_SIZE && !h.encrypted;
            groups.push(Group { headers: vec![pos], main_thread: h.dir || small });
        } else {
            match groups.last_mut() {
                Some(g) => g.headers.push(pos),
                None => groups.push(Group { headers: vec![pos], main_thread: true }),
            }
        }
        arc.seek_to_next();
    }
    let worker_groups = groups.iter().filter(|g| !g.main_thread).count();
    let mut workers = (cmd.threads as usize).min(worker_groups).min(16);
    if let Some(n) = WINDOW_MEMORY_BUDGET.checked_div(max_window) {
        workers = workers.min(n.max(1) as usize);
    }
    if workers < 2 {
        return None;
    }
    Some(Plan { groups, end_pos, workers })
}

/// Settings stored per thread, which workers must inherit.
#[derive(Clone, Copy)]
pub struct ThreadSettings {
    msg_stream: consio::MessageType,
    prohibit_input: bool,
    silent: bool,
    sound: bool,
}

impl ThreadSettings {
    pub fn current() -> Self {
        ThreadSettings {
            msg_stream: consio::get_console_msg_stream(),
            prohibit_input: consio::is_input_prohibited(),
            silent: errhnd::is_silent(),
            sound: crate::ui::sound_on(),
        }
    }

    pub fn apply(&self) {
        consio::set_console_msg_stream(self.msg_stream);
        if self.prohibit_input {
            consio::prohibit_console_input();
        }
        errhnd::set_silent(self.silent);
        crate::ui::ui_init(self.sound);
    }
}

/// Fatal error code from a worker panic payload.
pub fn fatal_code(e: &(dyn std::any::Any + Send)) -> i32 {
    match e.downcast_ref::<RarExit>() {
        Some(RarExit(code)) => *code,
        None => RARX_FATAL,
    }
}

/// Shared state of workers.
pub struct Shared<'a> {
    pub plan: &'a Plan,
    pub next: AtomicUsize,
    pub abort: AtomicBool,
    /// Number of running workers.
    pub live: AtomicUsize,
    pub results: mpsc::Sender<(usize, GroupResult)>,
}

/// Decrements the number of running workers when a worker exits.
pub struct LiveGuard<'a>(pub &'a AtomicUsize);

impl Drop for LiveGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

impl Shared<'_> {
    /// Next group index for a worker, skipping groups of the main thread.
    pub fn take(&self) -> Option<usize> {
        loop {
            if self.abort.load(Ordering::SeqCst) {
                return None;
            }
            let i = self.next.fetch_add(1, Ordering::SeqCst);
            let g = self.plan.groups.get(i)?;
            if !g.main_thread {
                return Some(i);
            }
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dest_names() {
        assert_eq!(dest_key("a/./b", false), dest_key("x/../a/b", false));
        assert_eq!(dest_key("A/B", false), dest_key("a/b", false));
        assert_eq!(dest_key("a//b", false), dest_key("a/b", false));
        assert_eq!(dest_key("dir/b", true), dest_key("b", true));
        let mut n = DestNames::default();
        assert!(n.add(dest_key("a/b", false), false));
        assert!(n.add(dest_key("a/c", false), false));
        assert!(n.add(dest_key("a", false), true));
        assert!(!n.add(dest_key("./a/b", false), false));
        assert!(!n.add(dest_key("a", false), false));
        assert!(!n.add(dest_key("a/b/c", false), false));
        assert!(!n.add(dest_key("a/b", false), true));
    }
}
