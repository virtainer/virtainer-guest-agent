// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Virtainer authors

//! State shared by every connection.
//!
//! File handles, exec'd processes and the freeze state outlive a connection:
//! a client may open a file on one vsock connection and read it on the next,
//! exactly as with qemu-ga on a persistent virtio-serial channel.

use std::path::PathBuf;

use crate::commands::{exec::ExecTable, file::FileTable, fsfreeze::Freezer};
use crate::config::Config;
use crate::shell::Sessions;

pub struct Agent {
    pub config: Config,
    pub freezer: Freezer,
    pub files: FileTable,
    pub execs: ExecTable,
    pub shells: Sessions,
}

impl Agent {
    pub fn new(config: Config, runtime_dir: PathBuf) -> Self {
        let freezer = Freezer::new(runtime_dir.join("frozen"), config.freeze_timeout);
        Self {
            config,
            freezer,
            files: FileTable::default(),
            execs: ExecTable::default(),
            shells: Sessions::default(),
        }
    }
}
