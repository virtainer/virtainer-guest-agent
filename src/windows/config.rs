// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Virtainer authors

//! Windows RPC filters, read from the private ProgramData directory.

#[derive(Default)]
pub struct Config {
    pub block_rpcs: Vec<String>,
    pub allow_rpcs: Option<Vec<String>>,
}
impl Config {
    pub fn load() -> Result<Self, String> {
        let path = crate::windows::data_dir().join("virtainer-guest-agent.conf");
        let text = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => return Err(e.to_string()),
        };
        let mut c = Self::default();
        for (index, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (key, value) = line
                .split_once('=')
                .ok_or_else(|| format!("config line {}: expected key = value", index + 1))?;
            let list = value
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect();
            match key.trim() {
                "block-rpcs" => c.block_rpcs = list,
                "allow-rpcs" => c.allow_rpcs = Some(list),
                _ => return Err(format!("config line {}: unknown key", index + 1)),
            }
        }
        Ok(c)
    }
    pub fn enabled(&self, name: &str) -> bool {
        self.allow_rpcs
            .as_ref()
            .is_none_or(|list| list.iter().any(|s| s == name))
            && !self.block_rpcs.iter().any(|s| s == name)
    }
}
