// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Virtainer authors

//! `__io.virtainer_last_crash`: the bug check (blue screen) that ended the
//! previous boot, from the System event log of the current boot.
//!
//! Windows records a bug check after the reboot that follows it: Kernel-Power
//! event 41 early in the boot (stop code and parameters), and event 1001 from
//! WER-SystemErrorReporting once the dump has been saved (stop code,
//! parameters and dump path). The log is read newest first and stops at
//! Kernel-General event 12, which starts every boot. The reply is the same
//! for the whole boot, so a host can ask again, for example once event 1001
//! has arrived with the dump path.

use serde_json::{json, Value};

pub const NAME: &str = "__io.virtainer_last_crash";
pub const CHANNEL: &str = "System";
pub const QUERY: &str = "*[System[\
(Provider[@Name='Microsoft-Windows-Kernel-General'] and EventID=12) or \
(Provider[@Name='Microsoft-Windows-Kernel-Power'] and EventID=41) or \
(Provider[@Name='Microsoft-Windows-WER-SystemErrorReporting'] and EventID=1001)]]";

const BOOT: (&str, u32) = ("Microsoft-Windows-Kernel-General", 12);
const KERNEL_POWER: (&str, u32) = ("Microsoft-Windows-Kernel-Power", 41);
const BUG_CHECK: (&str, u32) = ("Microsoft-Windows-WER-SystemErrorReporting", 1001);

/// The parts of one rendered event (EvtRenderEventXml) that are used here.
#[derive(Debug, PartialEq)]
pub struct Event {
    provider: String,
    id: u32,
    time: String,
    data: Vec<(String, String)>,
}

impl Event {
    pub fn parse(xml: &str) -> Option<Self> {
        let system = element(xml, "System")?;
        let provider = attribute(system, "Provider", "Name")?;
        let id = element(system, "EventID")?.trim().parse().ok()?;
        let time = attribute(system, "TimeCreated", "SystemTime").unwrap_or_default();
        let mut data = Vec::new();
        let mut rest = element(xml, "EventData").unwrap_or("");
        while let Some(start) = find_tag(rest, "Data") {
            rest = &rest[start..];
            let end = rest.find('>')?;
            let name = attribute(&rest[..=end], "Data", "Name").unwrap_or_default();
            let value = if rest[..end].ends_with('/') {
                String::new()
            } else {
                let close = rest.find("</Data>")?;
                unescape(&rest[end + 1..close])
            };
            data.push((name, value));
            rest = &rest[end + 1..];
        }
        Some(Self {
            provider,
            id,
            time,
            data,
        })
    }
    fn is(&self, (provider, id): (&str, u32)) -> bool {
        self.id == id && self.provider == provider
    }
    fn data(&self, name: &str) -> Option<&str> {
        self.data
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.trim())
    }
}

#[derive(Debug, PartialEq)]
struct Crash {
    time: String,
    code: u32,
    parameters: [u64; 4],
    dump: Option<String>,
}

/// Collects the crash events of the current boot, newest first.
#[derive(Default)]
pub struct Boot {
    kernel_power: Option<Crash>,
    bug_check: Option<Crash>,
}

impl Boot {
    /// Takes the next older event; false once the boot's start is reached.
    pub fn push(&mut self, event: &Event) -> bool {
        if event.is(BOOT) {
            return false;
        }
        if event.is(KERNEL_POWER) && self.kernel_power.is_none() {
            self.kernel_power = kernel_power(event);
        } else if event.is(BUG_CHECK) && self.bug_check.is_none() {
            self.bug_check = bug_check(event);
        }
        true
    }

    /// The reply: null when the previous boot did not end in a bug check.
    pub fn finish(self) -> Value {
        // Event 1001 is read from the dump; Kernel-Power 41 is logged first
        // and carries the earlier time.
        let crash = match (self.bug_check, self.kernel_power) {
            (Some(mut crash), Some(power)) => {
                crash.time = power.time;
                crash
            }
            (Some(crash), None) | (None, Some(crash)) => crash,
            (None, None) => return Value::Null,
        };
        let mut reply = json!({
            "time": crash.time,
            "stop-code": format!("0x{:08X}", crash.code),
        });
        if let Some(name) = stop_name(crash.code) {
            reply["stop-name"] = json!(name);
        }
        reply["parameters"] = json!(crash
            .parameters
            .iter()
            .map(|p| format!("0x{p:016X}"))
            .collect::<Vec<_>>());
        if let Some(dump) = crash.dump {
            reply["dump-path"] = json!(dump);
        }
        reply
    }
}

/// Kernel-Power 41 is logged after every unexpected restart; a stop code
/// of 0 means the previous boot ended without a bug check (a reset or a
/// power loss).
fn kernel_power(event: &Event) -> Option<Crash> {
    let code = u32::try_from(number(event.data("BugcheckCode")?)?).ok()?;
    if code == 0 {
        return None;
    }
    let mut parameters = [0; 4];
    for (i, parameter) in parameters.iter_mut().enumerate() {
        *parameter = number(event.data(&format!("BugcheckParameter{}", i + 1))?)?;
    }
    Some(Crash {
        time: event.time.clone(),
        code,
        parameters,
        dump: None,
    })
}

/// Event 1001's param1 reads `0x000000ef (0xffff..., 0x0, 0x0, 0x0)` and
/// param2 is the dump path, empty when no dump was saved.
fn bug_check(event: &Event) -> Option<Crash> {
    let text = event.data("param1")?;
    let (code, rest) = text.split_once('(')?;
    let code = u32::try_from(number(code)?).ok()?;
    let mut values = rest.strip_suffix(')')?.split(',').map(number);
    let mut parameters = [0; 4];
    for parameter in &mut parameters {
        *parameter = values.next()??;
    }
    if values.next().is_some() {
        return None;
    }
    let dump = event
        .data("param2")
        .filter(|path| !path.is_empty())
        .map(str::to_owned);
    Some(Crash {
        time: event.time.clone(),
        code,
        parameters,
        dump,
    })
}

/// A decimal or 0x-prefixed hexadecimal number.
fn number(text: &str) -> Option<u64> {
    let text = text.trim();
    match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => text.parse().ok(),
    }
}

/// The start of `<tag` followed by whitespace, `>` or `/`.
fn find_tag(xml: &str, tag: &str) -> Option<usize> {
    let open = format!("<{tag}");
    let mut from = 0;
    while let Some(i) = xml[from..].find(&open) {
        let start = from + i;
        let after = start + open.len();
        match xml[after..].chars().next() {
            Some(c) if c == '>' || c == '/' || c.is_whitespace() => return Some(start),
            _ => from = after,
        }
    }
    None
}

/// The content of the first `<tag ...>...</tag>`.
fn element<'a>(xml: &'a str, tag: &str) -> Option<&'a str> {
    let start = find_tag(xml, tag)?;
    let body = start + xml[start..].find('>')? + 1;
    let end = body + xml[body..].find(&format!("</{tag}>"))?;
    Some(&xml[body..end])
}

/// An attribute of the first `<tag ...>`, unescaped.
fn attribute(xml: &str, tag: &str, name: &str) -> Option<String> {
    let start = find_tag(xml, tag)?;
    let open = &xml[start..start + xml[start..].find('>')?];
    let mut rest = open;
    loop {
        let i = rest.find(name)?;
        let before = rest[..i].chars().next_back();
        let after = rest[i + name.len()..].trim_start();
        rest = &rest[i + name.len()..];
        if !before.is_some_and(char::is_whitespace) {
            continue;
        }
        let Some(value) = after.strip_prefix('=') else {
            continue;
        };
        let value = value.trim_start();
        let quote = value.chars().next().filter(|q| *q == '\'' || *q == '"')?;
        let value = &value[1..];
        return Some(unescape(&value[..value.find(quote)?]));
    }
}

fn unescape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        rest = &rest[i..];
        let decoded = rest.find(';').and_then(|end| {
            let c = match &rest[1..end] {
                "amp" => '&',
                "lt" => '<',
                "gt" => '>',
                "quot" => '"',
                "apos" => '\'',
                entity => {
                    let code = match entity.strip_prefix("#x") {
                        Some(hex) => u32::from_str_radix(hex, 16).ok(),
                        None => entity.strip_prefix('#')?.parse().ok(),
                    };
                    char::from_u32(code?)?
                }
            };
            Some((c, end + 1))
        });
        match decoded {
            Some((c, len)) => {
                out.push(c);
                rest = &rest[len..];
            }
            None => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// Names from Microsoft's bug check code reference, sorted by code.
const STOP_NAMES: &[(u32, &str)] = &[
    (0x0000_0001, "APC_INDEX_MISMATCH"),
    (0x0000_000A, "IRQL_NOT_LESS_OR_EQUAL"),
    (0x0000_0019, "BAD_POOL_HEADER"),
    (0x0000_001A, "MEMORY_MANAGEMENT"),
    (0x0000_001E, "KMODE_EXCEPTION_NOT_HANDLED"),
    (0x0000_0020, "KERNEL_APC_PENDING_DURING_EXIT"),
    (0x0000_0023, "FAT_FILE_SYSTEM"),
    (0x0000_0024, "NTFS_FILE_SYSTEM"),
    (0x0000_002E, "DATA_BUS_ERROR"),
    (0x0000_003B, "SYSTEM_SERVICE_EXCEPTION"),
    (0x0000_0044, "MULTIPLE_IRP_COMPLETE_REQUESTS"),
    (0x0000_004A, "IRQL_GT_ZERO_AT_SYSTEM_SERVICE"),
    (0x0000_004E, "PFN_LIST_CORRUPT"),
    (0x0000_0050, "PAGE_FAULT_IN_NONPAGED_AREA"),
    (0x0000_0051, "REGISTRY_ERROR"),
    (0x0000_0067, "CONFIG_INITIALIZATION_FAILED"),
    (0x0000_0069, "IO1_INITIALIZATION_FAILED"),
    (0x0000_006B, "PROCESS1_INITIALIZATION_FAILED"),
    (0x0000_0074, "BAD_SYSTEM_CONFIG_INFO"),
    (0x0000_0077, "KERNEL_STACK_INPAGE_ERROR"),
    (0x0000_007A, "KERNEL_DATA_INPAGE_ERROR"),
    (0x0000_007B, "INACCESSIBLE_BOOT_DEVICE"),
    (0x0000_007D, "INSTALL_MORE_MEMORY"),
    (0x0000_007E, "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED"),
    (0x0000_007F, "UNEXPECTED_KERNEL_MODE_TRAP"),
    (0x0000_0080, "NMI_HARDWARE_FAILURE"),
    (0x0000_008E, "KERNEL_MODE_EXCEPTION_NOT_HANDLED"),
    (0x0000_009C, "MACHINE_CHECK_EXCEPTION"),
    (0x0000_009F, "DRIVER_POWER_STATE_FAILURE"),
    (0x0000_00A0, "INTERNAL_POWER_ERROR"),
    (0x0000_00A5, "ACPI_BIOS_ERROR"),
    (0x0000_00B8, "ATTEMPTED_SWITCH_FROM_DPC"),
    (0x0000_00BE, "ATTEMPTED_WRITE_TO_READONLY_MEMORY"),
    (0x0000_00C1, "SPECIAL_POOL_DETECTED_MEMORY_CORRUPTION"),
    (0x0000_00C2, "BAD_POOL_CALLER"),
    (0x0000_00C4, "DRIVER_VERIFIER_DETECTED_VIOLATION"),
    (0x0000_00C5, "DRIVER_CORRUPTED_EXPOOL"),
    (0x0000_00C7, "TIMER_OR_DPC_INVALID"),
    (0x0000_00CA, "PNP_DETECTED_FATAL_ERROR"),
    (
        0x0000_00CE,
        "DRIVER_UNLOADED_WITHOUT_CANCELLING_PENDING_OPERATIONS",
    ),
    (0x0000_00D1, "DRIVER_IRQL_NOT_LESS_OR_EQUAL"),
    (0x0000_00D5, "DRIVER_PAGE_FAULT_IN_FREED_SPECIAL_POOL"),
    (0x0000_00D8, "DRIVER_USED_EXCESSIVE_PTES"),
    (0x0000_00DE, "POOL_CORRUPTION_IN_FILE_AREA"),
    (0x0000_00E2, "MANUALLY_INITIATED_CRASH"),
    (0x0000_00E3, "RESOURCE_NOT_OWNED"),
    (0x0000_00E6, "DRIVER_VERIFIER_DMA_VIOLATION"),
    (0x0000_00EA, "THREAD_STUCK_IN_DEVICE_DRIVER"),
    (0x0000_00ED, "UNMOUNTABLE_BOOT_VOLUME"),
    (0x0000_00EF, "CRITICAL_PROCESS_DIED"),
    (0x0000_00F2, "HARDWARE_INTERRUPT_STORM"),
    (0x0000_00F4, "CRITICAL_OBJECT_TERMINATION"),
    (0x0000_00F5, "FLTMGR_FILE_SYSTEM"),
    (0x0000_00F7, "DRIVER_OVERRAN_STACK_BUFFER"),
    (0x0000_00FC, "ATTEMPTED_EXECUTE_OF_NOEXECUTE_MEMORY"),
    (0x0000_00FE, "BUGCODE_USB_DRIVER"),
    (0x0000_0101, "CLOCK_WATCHDOG_TIMEOUT"),
    (0x0000_0109, "CRITICAL_STRUCTURE_CORRUPTION"),
    (0x0000_010D, "WDF_VIOLATION"),
    (0x0000_010E, "VIDEO_MEMORY_MANAGEMENT_INTERNAL"),
    (0x0000_0113, "VIDEO_DXGKRNL_FATAL_ERROR"),
    (0x0000_0116, "VIDEO_TDR_FAILURE"),
    (0x0000_0117, "VIDEO_TDR_TIMEOUT_DETECTED"),
    (0x0000_0119, "VIDEO_SCHEDULER_INTERNAL_ERROR"),
    (0x0000_0124, "WHEA_UNCORRECTABLE_ERROR"),
    (0x0000_0127, "PAGE_NOT_ZERO"),
    (0x0000_012B, "FAULTY_HARDWARE_CORRUPTED_PAGE"),
    (0x0000_012E, "INVALID_MDL_RANGE"),
    (0x0000_0133, "DPC_WATCHDOG_VIOLATION"),
    (0x0000_0139, "KERNEL_SECURITY_CHECK_FAILURE"),
    (0x0000_013A, "KERNEL_MODE_HEAP_CORRUPTION"),
    (0x0000_0144, "BUGCODE_USB3_DRIVER"),
    (0x0000_014B, "SOC_SUBSYSTEM_FAILURE"),
    (0x0000_014F, "PDC_WATCHDOG_TIMEOUT"),
    (0x0000_0154, "UNEXPECTED_STORE_EXCEPTION"),
    (0x0000_0157, "KERNEL_THREAD_PRIORITY_FLOOR_VIOLATION"),
    (0x0000_0158, "ILLEGAL_IOMMU_PAGE_FAULT"),
    (0x0000_0160, "WIN32K_ATOMIC_CHECK_FAILURE"),
    (0x0000_0161, "LIVE_SYSTEM_DUMP"),
    (0x0000_018B, "SECURE_KERNEL_ERROR"),
    (
        0x0000_0192,
        "KERNEL_AUTO_BOOST_LOCK_ACQUISITION_WITH_RAISED_IRQL",
    ),
    (0x0000_01CA, "SYNTHETIC_WATCHDOG_TIMEOUT"),
    (0xDEAD_DEAD, "MANUALLY_INITIATED_CRASH1"),
];

fn stop_name(code: u32) -> Option<&'static str> {
    STOP_NAMES
        .binary_search_by_key(&code, |(c, _)| *c)
        .ok()
        .map(|i| STOP_NAMES[i].1)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NS: &str = "xmlns='http://schemas.microsoft.com/win/2004/08/events/event'";

    fn boot(time: &str) -> String {
        format!(
            "<Event {NS}><System><Provider Name='Microsoft-Windows-Kernel-General' \
             Guid='{{a68ca8b7-004f-d7b6-a698-07e2de0f1f5d}}'/><EventID>12</EventID>\
             <TimeCreated SystemTime='{time}'/><EventRecordID>500</EventRecordID></System>\
             <EventData><Data Name='MajorVersion'>10</Data></EventData></Event>"
        )
    }
    fn power(code: &str, p1: &str) -> String {
        format!(
            "<Event {NS}><System><Provider Name='Microsoft-Windows-Kernel-Power' \
             Guid='{{331c3b3a-2005-44c2-ac5e-77220c37d6b4}}'/><EventID>41</EventID>\
             <Version>8</Version><TimeCreated SystemTime='2026-10-13T15:02:11.5000000Z'/>\
             </System><EventData><Data Name='BugcheckCode'>{code}</Data>\
             <Data Name='BugcheckParameter1'>{p1}</Data>\
             <Data Name='BugcheckParameter2'>0x0</Data>\
             <Data Name='BugcheckParameter3'>0x0</Data>\
             <Data Name='BugcheckParameter4'>0x0</Data>\
             <Data Name='SleepInProgress'>0</Data><Data Name='PowerButtonTimestamp'>0</Data>\
             <Data Name='BootAppStatus'/></EventData></Event>"
        )
    }
    fn wer(param1: &str, dump: &str) -> String {
        format!(
            "<Event {NS}><System><Provider Name=\"Microsoft-Windows-WER-SystemErrorReporting\" \
             EventSourceName=\"BugCheck\"/><EventID Qualifiers=\"16384\">1001</EventID>\
             <TimeCreated SystemTime=\"2026-10-13T15:02:40.1234567Z\"/></System><EventData>\
             <Data Name=\"param1\">{param1}</Data><Data Name=\"param2\">{dump}</Data>\
             <Data Name=\"param3\">a1b2c3d4-0000-0000-0000-000000000000</Data></EventData></Event>"
        )
    }
    fn last(newest_first: &[String]) -> Value {
        let mut boot = Boot::default();
        for xml in newest_first {
            if !boot.push(&Event::parse(xml).unwrap()) {
                break;
            }
        }
        boot.finish()
    }

    #[test]
    fn parses_rendered_events() {
        let event = Event::parse(&power("239", "0xffffe40ae6d6f080")).unwrap();
        assert_eq!(event.provider, "Microsoft-Windows-Kernel-Power");
        assert_eq!(event.id, 41);
        assert_eq!(event.time, "2026-10-13T15:02:11.5000000Z");
        assert_eq!(event.data("BugcheckCode"), Some("239"));
        assert_eq!(event.data("BootAppStatus"), Some(""));
        assert_eq!(event.data("Missing"), None);
        let event = Event::parse(&wer("0x1 (0x0, 0x0, 0x0, 0x0)", "C:\\a&amp;b.dmp")).unwrap();
        assert_eq!(event.id, 1001);
        assert_eq!(event.data("param2"), Some("C:\\a&b.dmp"));
        assert_eq!(Event::parse("<Event><System></System></Event>"), None);
        assert_eq!(Event::parse("not xml"), None);
    }

    #[test]
    fn both_events_merge_into_one_report() {
        let reply = last(&[
            wer(
                "0x000000ef (0xffffe40ae6d6f080, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000)",
                "C:\\Windows\\MEMORY.DMP",
            ),
            power("239", "0xffffe40ae6d6f080"),
            boot("2026-10-13T15:02:10.0000000Z"),
            power("10", "0x1"),
        ]);
        assert_eq!(
            reply,
            json!({
                "time": "2026-10-13T15:02:11.5000000Z",
                "stop-code": "0x000000EF",
                "stop-name": "CRITICAL_PROCESS_DIED",
                "parameters": ["0xFFFFE40AE6D6F080", "0x0000000000000000",
                               "0x0000000000000000", "0x0000000000000000"],
                "dump-path": "C:\\Windows\\MEMORY.DMP",
            })
        );
        let keys: Vec<_> = reply.as_object().unwrap().keys().cloned().collect();
        assert_eq!(
            keys,
            ["time", "stop-code", "stop-name", "parameters", "dump-path"]
        );
    }

    #[test]
    fn kernel_power_alone_reports_without_a_dump() {
        let reply = last(&[power("0x50", "18446744073709551615"), boot("t")]);
        assert_eq!(reply["stop-code"], "0x00000050");
        assert_eq!(reply["stop-name"], "PAGE_FAULT_IN_NONPAGED_AREA");
        assert_eq!(reply["parameters"][0], "0xFFFFFFFFFFFFFFFF");
        assert!(reply.get("dump-path").is_none());
    }

    #[test]
    fn bug_check_alone_without_dump_or_known_name() {
        let reply = last(&[wer("0x00001234 (0x1, 0x2, 0x3, 0x4)", "")]);
        assert_eq!(
            reply,
            json!({"time": "2026-10-13T15:02:40.1234567Z", "stop-code": "0x00001234",
                   "parameters": ["0x0000000000000001", "0x0000000000000002",
                                  "0x0000000000000003", "0x0000000000000004"]})
        );
    }

    #[test]
    fn nothing_in_this_boot_is_null() {
        assert_eq!(last(&[]), Value::Null);
        // Older boots' crashes are not this boot's report.
        assert_eq!(
            last(&[
                boot("t"),
                power("239", "0x1"),
                wer("0xef (0x1, 0x0, 0x0, 0x0)", "x")
            ]),
            Value::Null
        );
        // A reset or power loss: Kernel-Power 41 without a stop code.
        assert_eq!(last(&[power("0", "0x0"), boot("t")]), Value::Null);
    }

    #[test]
    fn malformed_crash_events_are_ignored() {
        assert_eq!(last(&[wer("0xef", "x"), boot("t")]), Value::Null);
        assert_eq!(last(&[wer("0xef (0x1, 0x2, 0x3)", "x")]), Value::Null);
        assert_eq!(
            last(&[wer("0xef (0x1, 0x2, 0x3, 0x4, 0x5)", "x")]),
            Value::Null
        );
        assert_eq!(last(&[power("0x100000000", "0x1")]), Value::Null);
        assert_eq!(last(&[power("239", "zz")]), Value::Null);
    }

    #[test]
    fn helpers() {
        assert_eq!(number(" 0X1f "), Some(31));
        assert_eq!(number("12"), Some(12));
        assert_eq!(number(""), None);
        assert_eq!(
            unescape("a&lt;b&gt;&quot;&apos;&#65;&#x42;&bogus;&"),
            "a<b>\"'AB&bogus;&"
        );
        assert_eq!(
            attribute("<X Foo='1' Name='a&amp;b'/>", "X", "Name"),
            Some("a&b".into())
        );
        assert_eq!(attribute("<X OtherName='1'/>", "X", "Name"), None);
        assert_eq!(
            element("<EventIDx>1</EventIDx><EventID>2</EventID>", "EventID"),
            Some("2")
        );
        assert_eq!(stop_name(0xEF), Some("CRITICAL_PROCESS_DIED"));
        assert_eq!(stop_name(0xDEAD_DEAD), Some("MANUALLY_INITIATED_CRASH1"));
        assert_eq!(stop_name(2), None);
        assert!(STOP_NAMES.windows(2).all(|w| w[0].0 < w[1].0));
    }
}
