// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! List of strings with a read cursor.

#[derive(Clone, Debug, Default)]
pub struct StringList {
    items: Vec<String>,
    pos: usize,
    saved: Vec<usize>,
}

impl StringList {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn reset(&mut self) {
        self.items.clear();
        self.pos = 0;
        self.saved.clear();
    }
    pub fn add_string(&mut self, s: &str) {
        self.items.push(s.to_string());
    }
    pub fn get_string(&mut self) -> Option<String> {
        let s = self.items.get(self.pos).cloned();
        if s.is_some() {
            self.pos += 1;
        }
        s
    }
    pub fn get_string_num(&self, n: usize) -> Option<&String> {
        self.items.get(n)
    }
    pub fn rewind(&mut self) {
        self.pos = 0;
    }
    pub fn items_count(&self) -> usize {
        self.items.len()
    }
    pub fn items(&self) -> &[String] {
        &self.items
    }
    pub fn search(&self, s: &str, case_sensitive: bool) -> bool {
        self.items.iter().any(|x| if case_sensitive { x == s } else { crate::strfn::wcsicomp_eq(x, s) })
    }
    pub fn save_position(&mut self) {
        self.saved.push(self.pos);
    }
    pub fn restore_position(&mut self) {
        if let Some(p) = self.saved.pop() {
            self.pos = p;
        }
    }
}
