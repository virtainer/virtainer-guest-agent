// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Virtainer authors

//! Platform-independent Windows seed and provisioning logic, tested on Linux.

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub mod fat12;
