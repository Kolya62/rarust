// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#![forbid(unsafe_code)]

fn main() {
    let args: Vec<String> = std::env::args_os().skip(1).map(|a| rarust::unicode::from_os(&a)).collect();
    let code = rarust::run(args);
    std::process::exit(code);
}
