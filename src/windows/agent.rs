// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Virtainer authors

use crate::shell_protocol::Sessions;
use crate::{
    commands::{exec::ExecTable, file::FileTable},
    config::Config,
};
use std::sync::Mutex;

pub struct Agent {
    pub config: Config,
    pub files: FileTable,
    pub execs: ExecTable,
    pub shells: Sessions,
    pub provision: Mutex<serde_json::Value>,
}
impl Agent {
    pub fn new(config: Config, provision: serde_json::Value) -> Self {
        Self {
            config,
            files: FileTable::default(),
            execs: ExecTable::default(),
            shells: Sessions::default(),
            provision: Mutex::new(provision),
        }
    }
}
