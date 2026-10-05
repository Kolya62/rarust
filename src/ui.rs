// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Console user interface: messages, prompts and progress.

use crate::consio::{ask, eprintf, getwstr, mprintf};
use crate::loclang::*;
use crate::wfmt;
use std::cell::Cell;

/// UI messages.
#[derive(Clone, Debug)]
pub enum UiMsg {
    SysErrMsg(String),
    GeneralErrMsg(String),
    IncErrCount,
    Checksum(String, String),
    ChecksumEnc(String, String),
    ChecksumPacked(String, String),
    BadPsw(String, String),
    WaitBadPsw(String, String),
    Memory,
    FileOpen(String, String),
    FileCreate(String, String),
    FileClose(String),
    FileSeek(String),
    FileRead(String, String),
    FileWrite(String, String),
    FileDelete(String, String),
    FileRename(String, String, String),
    FileAttr(String, String),
    FileCopy(String, String, String),
    FileCopyHint(String),
    DirCreate(String, String),
    SLinkCreate(String, String),
    HLinkCreate(String),
    NoLinkTarget,
    NeedAdmin,
    StreamBroken(String, String),
    StreamUnknown(String, String),
    AclSet(String, String),
    AclBroken(String, String),
    AclUnknown(String, String),
    ArcBroken(String),
    HeaderBroken(String),
    MainHeaderBroken(String),
    FHeaderBroken(String, String),
    SubHeaderBroken(String),
    SubHeaderUnknown(String),
    SubHeaderDataBroken(String, String),
    RRDamaged(String),
    UnknownMethod(String, String),
    UnknownEncMethod(String, String, String),
    Renaming(String, String, String),
    NewerRar(String),
    RecVolDiffSets(String, String),
    RecVolAllExist,
    Reconstructing,
    RecVolCannotFix,
    ExtrDictOutMem(String, u32),
    UnexpEof(String),
    TruncService(String, String),
    BadArchive(String),
    CmtBroken(String),
    InvalidName(String, String),
    NewRarFormat(String),
    NoFilesToExtract(String),
    MissingVol(String),
    NeedPrevVol(String, String),
    UnknownExtra(String, String),
    CorruptExtra(String, String, String),
    IncompatSwitch(String, u32),
    PathTooLong(String, String, String),
    DirScan(String),
    UOwnerBroken(String, String),
    UOwnerGetOwnerId(String, String),
    UOwnerGetGroupId(String, String),
    UOwnerSet(String, String),
    ULinkRead(String),
    ULinkExist(String),
    DirNameExists,
    TruncPsw(u32),
    AdjustValue(String, String),
    SkipUnsafeLink(String, String),
    MsgString(String),
    CorrectingName(String),
    MsgBadArchive(String),
    Creating(String),
    MsgRenaming(String, String),
    RecVolCalcChecksum,
    RecVolFound(u32),
    RecVolMissing(u32),
    MsgMissingVol(String),
    MsgReconstructing,
    MsgChecksum(String),
    SkipEncArc(String),
    RRTestingStart,
    DelAddedFile(String, bool),
}

thread_local! {
    static ANY_MESSAGE_DISPLAYED: Cell<bool> = const { Cell::new(false) };
    static SOUND_ON: Cell<bool> = const { Cell::new(false) };
}

/// Log an error message to stderr.
fn log(s: &str) {
    eprintf(s);
}

pub fn ui_init(sound: bool) {
    SOUND_ON.with(|s| s.set(sound));
}

pub fn ui_msg(m: UiMsg) {
    use UiMsg::*;
    ANY_MESSAGE_DISPLAYED.with(|a| a.set(true));
    match m {
        SysErrMsg(s) | GeneralErrMsg(s) => log(&wfmt!("\n%s", s)),
        IncErrCount => {}
        Checksum(_, n) => log(&wfmt!(MCRCFailed, n)),
        ChecksumEnc(_, n) => log(&wfmt!(MEncrBadCRC, n)),
        ChecksumPacked(a, n) => log(&wfmt!(MDataBadCRC, n, a)),
        BadPsw(_, n) => log(&wfmt!(MWrongFilePassword, n)),
        WaitBadPsw(_, _) => log(MWrongPassword),
        Memory => {
            mprintf("\n");
            log(MErrOutMem);
        }
        FileOpen(_, n) => log(&wfmt!(MCannotOpen, n)),
        FileCreate(_, n) => log(&wfmt!(MCannotCreate, n)),
        FileClose(n) => log(&wfmt!(MErrFClose, n)),
        FileSeek(n) => log(&wfmt!(MErrSeek, n)),
        FileRead(_, n) => {
            mprintf("\n");
            log(&wfmt!(MErrRead, n));
        }
        FileWrite(_, n) => log(&wfmt!(MErrWrite, n)),
        FileDelete(_, n) => log(&wfmt!(MCannotDelete, n)),
        FileRename(_, a, b) => log(&wfmt!(MErrRename, a, b)),
        FileAttr(_, n) => {
            if cfg!(unix) {
                log(&wfmt!(MErrChangePerm, n))
            } else {
                log(&wfmt!(MErrChangeAttr, n))
            }
        }
        FileCopy(_, a, b) => log(&wfmt!(MCopyError, a, b)),
        FileCopyHint(_) => {
            log(MCopyErrorHint);
            mprintf("     ");
        }
        DirCreate(_, n) => log(&wfmt!(MExtrErrMkDir, n)),
        SLinkCreate(_, n) => log(&wfmt!(MErrCreateLnkS, n)),
        HLinkCreate(n) => log(&wfmt!(MErrCreateLnkH, n)),
        NeedAdmin => log(MNeedAdmin),
        StreamBroken(_, n) => log(&wfmt!(MStreamBroken, n)),
        StreamUnknown(_, n) => log(&wfmt!(MStreamUnknown, n)),
        AclSet(_, n) => log(&wfmt!(MACLSetError, n)),
        AclBroken(_, n) => log(&wfmt!(MACLBroken, n)),
        AclUnknown(_, n) => log(&wfmt!(MACLUnknown, n)),
        NoLinkTarget => {
            log(MErrLnkTarget);
            mprintf("     ");
        }
        ArcBroken(_) => {
            mprintf("\n");
            log(MErrBrokenArc);
        }
        HeaderBroken(_) => log(MHeaderBroken),
        MainHeaderBroken(_) => log(MMainHeaderBroken),
        FHeaderBroken(_, n) => log(&wfmt!(MLogFileHead, n)),
        SubHeaderBroken(_) => log(MSubHeadCorrupt),
        SubHeaderUnknown(_) => log(MSubHeadUnknown),
        SubHeaderDataBroken(_, n) => log(&wfmt!(MSubHeadDataCRC, n)),
        RRDamaged(_) => log(MRRDamaged),
        UnknownMethod(_, n) => log(&wfmt!(MUnknownMeth, n)),
        UnknownEncMethod(_, n, info) => {
            let msg = wfmt!(MUnkEncMethod, n);
            log(&wfmt!("%s: %s", msg, info));
        }
        Renaming(_, a, b) => log(&wfmt!(MRenaming, a, b)),
        NewerRar(_) => log(MNewerRAR),
        RecVolDiffSets(a, b) => log(&wfmt!(MRecVolDiffSets, a, b)),
        RecVolAllExist => mprintf(MRecVolAllExist),
        Reconstructing => mprintf(MReconstructing),
        RecVolCannotFix => mprintf(MRecVolCannotFix),
        ExtrDictOutMem(_, n) => log(&wfmt!(MExtrDictOutMem, n)),
        UnexpEof(_) => log(MLogUnexpEOF),
        TruncService(_, t) => {
            let ty = if t == "QO" {
                Some(MHeaderQO)
            } else if t == "RR" {
                Some(MHeaderRR)
            } else {
                None
            };
            if let Some(ty) = ty {
                log(&wfmt!(MTruncService, ty));
            }
        }
        BadArchive(a) => log(&wfmt!(MBadArc, a)),
        CmtBroken(_) => log(MLogCommBrk),
        InvalidName(_, n) => {
            log(&wfmt!(MInvalidName, n));
            mprintf("\n");
        }
        NewRarFormat(_) => log(MNewRarFormat),
        NoFilesToExtract(_) => mprintf(MExtrNoFiles),
        MissingVol(n) => {
            log(&wfmt!(MAbsNextVol, n));
            mprintf("     ");
        }
        NeedPrevVol(_, n) => log(&wfmt!(MUnpCannotMerge, n)),
        UnknownExtra(_, n) => log(&wfmt!(MUnknownExtra, n)),
        CorruptExtra(_, a, b) => log(&wfmt!(MCorruptExtra, a, b)),
        IncompatSwitch(s, n) => mprintf(&wfmt!(MIncompatSwitch, s, n)),
        PathTooLong(a, b, c) => {
            log(&wfmt!("\n%s%s%s", a, b, c));
            log(MPathTooLong);
        }
        DirScan(n) => log(&wfmt!(MScanError, n)),
        UOwnerBroken(_, n) => log(&wfmt!(MOwnersBroken, n)),
        UOwnerGetOwnerId(_, n) => log(&wfmt!(MErrGetOwnerID, n)),
        UOwnerGetGroupId(_, n) => log(&wfmt!(MErrGetGroupID, n)),
        UOwnerSet(_, n) => log(&wfmt!(MSetOwnersError, n)),
        ULinkRead(n) => log(&wfmt!(MErrLnkRead, n)),
        ULinkExist(n) => log(&wfmt!(MSymLinkExists, n)),
        DirNameExists => log(MDirNameExists),
        TruncPsw(n) => {
            eprintf(&wfmt!(MTruncPsw, n));
            eprintf("\n");
        }
        AdjustValue(a, b) => log(&wfmt!(MAdjustValue, a, b)),
        SkipUnsafeLink(a, b) => log(&wfmt!(MSkipUnsafeLink, a, b)),
        MsgString(s) => mprintf(&wfmt!("\n%s", s)),
        CorrectingName(_) => log(MCorrectingName),
        MsgBadArchive(a) => mprintf(&wfmt!(MBadArc, a)),
        Creating(n) => mprintf(&wfmt!(MCreating, n)),
        MsgRenaming(a, b) => mprintf(&wfmt!(MRenaming, a, b)),
        RecVolCalcChecksum => mprintf(MCalcCRCAllVol),
        RecVolFound(n) => mprintf(&wfmt!(MRecVolFound, n)),
        RecVolMissing(n) => mprintf(&wfmt!(MRecVolMissing, n)),
        MsgMissingVol(n) => mprintf(&wfmt!(MAbsNextVol, n)),
        MsgReconstructing => mprintf(MReconstructing),
        MsgChecksum(n) => mprintf(&wfmt!(MCRCFailed, n)),
        SkipEncArc(n) => log(&wfmt!(MSkipEncArc, n)),
        RRTestingStart => mprintf(&wfmt!("%s      ", MTestingRR)),
        DelAddedFile(_, _) => {}
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum UiAlarm {
    Error,
    Info,
    Question,
}

pub fn ui_alarm(_t: UiAlarm) {
    if SOUND_ON.with(|s| s.get()) {
        eprintf("\x07");
    }
}

pub fn ui_eol_after_msg() {
    if ANY_MESSAGE_DISPLAYED.with(|a| a.get()) {
        ANY_MESSAGE_DISPLAYED.with(|a| a.set(false));
        mprintf("\n");
    }
}

pub fn ui_start_archive_extract(extract: bool, arc_name: &str) {
    mprintf(&wfmt!(if extract { MExtracting } else { MExtrTest }, arc_name));
}

pub fn to_percent(n1: i64, n2: i64) -> i32 {
    if n2 < n1 {
        return 100;
    }
    to_percent_unlim(n1, n2)
}

pub fn to_percent_unlim(n1: i64, n2: i64) -> i32 {
    if n2 == 0 {
        return 0;
    }
    (n1 as i128 * 100 / n2 as i128) as i32
}

pub fn ui_extract_progress(cur_file: i64, total_file: i64, cur: i64, total: i64) {
    let p = if total != 0 { to_percent(cur, total) } else { to_percent(cur_file, total_file) };
    mprintf(&wfmt!("\x08\x08\x08\x08%3d%%", p));
}

pub fn ui_ask_next_volume(vol_name: &str) -> bool {
    eprintf(&wfmt!(MAskNextVol, vol_name));
    ask(MContinueQuit) != 2
}

/// Returns (ignore, all, retry, quit).
pub fn ui_ask_repeat_read(_name: &str) -> (bool, bool, bool, bool) {
    eprintf(MErrReadInfo);
    let code = ask(MIgnoreAllRetryQuit);
    let ignore = code == 1;
    let all = code == 2;
    let quit = code == 4;
    let retry = !ignore && !all && !quit;
    (ignore || all, all, retry, quit)
}

pub fn ui_ask_repeat_write(name: &str, disk_full: bool) -> bool {
    mprintf("\n");
    log(&wfmt!(if disk_full { MNotEnoughDisk } else { MErrWrite }, name));
    ask(MRetryAbort) == 1
}

pub fn ui_dict_limit(file_name: &str, dict: u64, max_dict: u64) -> bool {
    mprintf(&wfmt!("\n%s", file_name));
    const GB: u64 = 1024 * 1024 * 1024;
    let dict = dict / GB + if !dict.is_multiple_of(GB) { 1 } else { 0 };
    let max_dict = max_dict / GB;
    mprintf(&wfmt!(MDictNotAllowed, dict as u32, max_dict as u32, dict as u32));
    mprintf(&wfmt!(MDictExtrAnyway, dict as u32, dict as u32));
    mprintf("\n");
    false
}

pub fn ui_get_month_name(m: u32) -> &'static str {
    const N: [&str; 12] = [
        MMonthJan, MMonthFeb, MMonthMar, MMonthApr, MMonthMay, MMonthJun, MMonthJul, MMonthAug, MMonthSep,
        MMonthOct, MMonthNov, MMonthDec,
    ];
    N.get(m as usize).copied().unwrap_or("")
}

pub fn ui_get_week_day_name(d: u32) -> &'static str {
    const N: [&str; 7] = [MWeekDaySun, MWeekDayMon, MWeekDayTue, MWeekDayWed, MWeekDayThu, MWeekDayFri, MWeekDaySat];
    N.get(d as usize).copied().unwrap_or("")
}

/// Results of overwrite prompt.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AskRep {
    Replace,
    Skip,
    ReplaceAll,
    SkipAll,
    Rename,
    RenameAuto,
    Cancel,
}

pub const UIASKREP_F_NORENAME: u32 = 1;
pub const UIASKREP_F_EXCHSRCDEST: u32 = 2;
pub const UIASKREP_F_SRCFOLDER: u32 = 0x10;

/// Ask user about replacing existing file. Returns choice and possibly
/// a new name entered by user.
pub fn ui_ask_replace(name: &mut String, file_size: Option<i64>, file_time: Option<&crate::timefn::RarTime>, flags: u32) -> AskRep {
    let mut fd = crate::find::FindData::default();
    crate::find::fast_find(name, &mut fd, false);
    let size1 = fd.size.to_string();
    let date1 = fd.mtime.get_text(false);
    match (file_size, file_time) {
        (Some(sz), Some(tm)) => {
            let size2 = sz.to_string();
            let date2 = tm.get_text(false);
            if flags & UIASKREP_F_EXCHSRCDEST == 0 {
                eprintf(&wfmt!(MAskReplace, name.as_str(), size1, date1, size2, date2));
            } else {
                eprintf(&wfmt!(MAskReplace, name.as_str(), size2, date2, size1, date1));
            }
        }
        _ => {
            eprintf("\n");
            eprintf(&wfmt!(MAskOverwrite, name.as_str()));
        }
    }
    let allow_rename = flags & UIASKREP_F_NORENAME == 0;
    let mut choice;
    loop {
        choice = ask(if allow_rename { MYesNoAllRenQ } else { MYesNoAllQ });
        if choice != 0 {
            break;
        }
    }
    match choice {
        1 => return AskRep::Replace,
        2 => return AskRep::Skip,
        3 => return AskRep::ReplaceAll,
        4 => return AskRep::SkipAll,
        _ => {}
    }
    if allow_rename && choice == 5 {
        mprintf(MAskNewName);
        *name = getwstr();
        return AskRep::Rename;
    }
    AskRep::Cancel
}
