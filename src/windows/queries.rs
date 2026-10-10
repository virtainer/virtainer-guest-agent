// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Virtainer authors

//! Windows inventory through built-in CIM/NetTCPIP cmdlets.

use crate::{
    qmp::{QgaError, Reply},
    sys,
};
use serde_json::json;
fn query(code: &str, action: &str) -> Reply {
    let out = sys::ps(code, &json!({}), action, &[]).map_err(QgaError::generic)?;
    serde_json::from_slice(&out)
        .map_err(|_| QgaError::generic(format!("{action}: invalid inventory response")))
}
pub fn osinfo() -> Reply {
    query(
        r#"
$o=Get-CimInstance Win32_OperatingSystem;
[ordered]@{'kernel-name'='Windows';'kernel-release'=$o.Version;'kernel-version'=$o.BuildNumber;
'machine'='x86_64';'id'='mswindows';'name'=$o.Caption;'pretty-name'=$o.Caption;
'version'=$o.Version;'version-id'=$o.Version} | ConvertTo-Json -Compress
"#,
        "get OS info",
    )
}
pub fn interfaces() -> Reply {
    query(
        r#"
$result=@(Get-NetAdapter -IncludeHidden | ForEach-Object {
$a=$_;
$entry=[ordered]@{'name'=$a.Name};
if($a.MacAddress){$entry['hardware-address']=$a.MacAddress.Replace('-',':').ToLowerInvariant()};
$ips=@(Get-NetIPAddress -InterfaceIndex $a.ifIndex -ErrorAction SilentlyContinue | ForEach-Object {
[ordered]@{'ip-address'=$_.IPAddress;'ip-address-type'=if($_.AddressFamily -eq 'IPv4'){'ipv4'}else{'ipv6'};'prefix'=[int]$_.PrefixLength}
});
if($ips.Count){$entry['ip-addresses']=$ips}; $entry
});
ConvertTo-Json -InputObject $result -Depth 5 -Compress
"#,
        "get network interfaces",
    )
}
