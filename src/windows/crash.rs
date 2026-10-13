// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Virtainer authors

//! `__io.virtainer_last_crash` through the Windows Event Log API. The events
//! are interpreted in windows_support/crash.rs.

use crate::{
    qmp::{QgaError, Reply},
    windows::api::wide,
    windows_support::crash,
};
use serde_json::Value;
use std::{io, ptr};
use windows_sys::Win32::{
    Foundation::{ERROR_INSUFFICIENT_BUFFER, ERROR_NO_MORE_ITEMS},
    System::EventLog::{
        EvtClose, EvtNext, EvtQuery, EvtQueryChannelPath, EvtQueryReverseDirection, EvtRender,
        EvtRenderEventXml, EVT_HANDLE,
    },
};

const BATCH: usize = 16;
const TIMEOUT_MS: u32 = 10_000;

struct Owned(EVT_HANDLE);
impl Drop for Owned {
    fn drop(&mut self) {
        // SAFETY: the handle came from EvtQuery or EvtNext and is closed once.
        unsafe { EvtClose(self.0) };
    }
}

pub fn last_crash() -> Reply {
    read().map_err(|e| QgaError::os("failed to read the System event log", &e))
}

fn read() -> io::Result<Value> {
    let channel = wide(crash::CHANNEL);
    let query = wide(crash::QUERY);
    // SAFETY: both strings are NUL-terminated and outlive the call; a null
    // session means the local computer.
    let results = unsafe {
        EvtQuery(
            0,
            channel.as_ptr(),
            query.as_ptr(),
            EvtQueryChannelPath | EvtQueryReverseDirection,
        )
    };
    if results == 0 {
        return Err(io::Error::last_os_error());
    }
    let results = Owned(results);
    let mut boot = crash::Boot::default();
    let mut buffer = Vec::new();
    loop {
        let mut handles = [0; BATCH];
        let mut returned = 0;
        // SAFETY: handles has room for BATCH events; returned outlives the call.
        let ok = unsafe {
            EvtNext(
                results.0,
                BATCH as u32,
                handles.as_mut_ptr(),
                TIMEOUT_MS,
                0,
                &mut returned,
            )
        };
        if ok == 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(ERROR_NO_MORE_ITEMS as i32) {
                break;
            }
            return Err(error);
        }
        let events: Vec<_> = handles[..returned as usize]
            .iter()
            .map(|&h| Owned(h))
            .collect();
        for event in &events {
            let xml = render(event.0, &mut buffer)?;
            // Events this agent cannot read are not crash reports.
            if let Some(event) = crash::Event::parse(&xml) {
                if !boot.push(&event) {
                    return Ok(boot.finish());
                }
            }
        }
    }
    // The log was cleared during this boot: everything left is from it.
    Ok(boot.finish())
}

fn render(event: EVT_HANDLE, buffer: &mut Vec<u16>) -> io::Result<String> {
    loop {
        let mut used = 0u32;
        let mut properties = 0u32;
        // SAFETY: buffer is writable for its byte length; the out-parameters
        // outlive the call.
        let ok = unsafe {
            EvtRender(
                0,
                event,
                EvtRenderEventXml,
                (buffer.len() * 2) as u32,
                if buffer.is_empty() {
                    ptr::null_mut()
                } else {
                    buffer.as_mut_ptr().cast()
                },
                &mut used,
                &mut properties,
            )
        };
        if ok != 0 {
            let text = &buffer[..(used as usize / 2).min(buffer.len())];
            let end = text.iter().position(|&c| c == 0).unwrap_or(text.len());
            return Ok(String::from_utf16_lossy(&text[..end]));
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32)
            || used as usize <= buffer.len() * 2
        {
            return Err(error);
        }
        buffer.resize((used as usize).div_ceil(2), 0);
    }
}
