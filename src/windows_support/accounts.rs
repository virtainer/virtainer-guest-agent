// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Virtainer authors

//! Input for disabling the built-in Administrator account. The account is
//! resolved by SID on Windows, and the helper refuses when the requested
//! administrator is that same account; names are never compared, because the
//! built-in account may be renamed or localized.

use super::provision::Admin;
use serde_json::{json, Value};

/// The helper input naming the account that must stay enabled.
pub fn disable_builtin(admin: &Admin) -> Value {
    json!({"username":admin.username})
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::windows_support::provision::Provision;

    fn admin(username: &str) -> Admin {
        Provision::parse(
            &serde_json::to_vec(&json!({
                "schema":1,"instance_id":"00000000-0000-4000-8000-000000000001",
                "seed_version":"a".repeat(64),
                "admin":{"username":username,"password":"private-test-value","disable_builtin":true}
            }))
            .unwrap(),
        )
        .unwrap()
        .admin
        .unwrap()
    }

    #[test]
    fn input_names_only_the_account_to_keep() {
        let input = disable_builtin(&admin("ops"));
        assert_eq!(input, json!({"username":"ops"}));
        assert!(!input.to_string().contains("private-test-value"));
    }

    #[test]
    fn a_replacement_account_named_administrator_is_left_to_the_sid_check() {
        let input = disable_builtin(&admin("Administrator"));
        assert_eq!(input, json!({"username":"Administrator"}));
    }

    #[test]
    fn helper_resolves_the_builtin_account_by_sid() {
        let script = include_str!("../windows/builtin.ps1");
        assert!(script.contains("AccountAdministratorSid"));
        assert!(script.contains("AccountDomainSid"));
        assert!(script.contains("S-1-5-32-544"));
        assert!(script.contains("Disable-LocalUser -InputObject $builtin"));
        assert!(!script.contains("-Name 'Administrator'"));
        assert!(!script.contains("-Name \"Administrator\""));
    }
}
