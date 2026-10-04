// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Virtainer authors

//! QMP request validation and QAPI-style argument checking.
//!
//! Error texts follow QEMU's (`qmp-dispatch.c`, `qobject-input-visitor.c`)
//! so a client that matches on qemu-ga's messages keeps working.

use std::fmt::Display;
use std::io;

use serde_json::{json, Map, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorClass {
    GenericError,
    CommandNotFound,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QgaError {
    pub class: ErrorClass,
    pub desc: String,
}

impl QgaError {
    pub fn generic(desc: impl Into<String>) -> Self {
        Self {
            class: ErrorClass::GenericError,
            desc: desc.into(),
        }
    }

    pub fn command_not_found(desc: impl Into<String>) -> Self {
        Self {
            class: ErrorClass::CommandNotFound,
            desc: desc.into(),
        }
    }

    /// `error_setg_errno` spelling: "<context>: <strerror>".
    pub fn os(context: impl Display, err: &io::Error) -> Self {
        Self::generic(format!("{context}: {}", crate::sys::strerror(err)))
    }

    pub fn to_json(&self) -> Value {
        let class = match self.class {
            ErrorClass::GenericError => "GenericError",
            ErrorClass::CommandNotFound => "CommandNotFound",
        };
        json!({ "class": class, "desc": self.desc })
    }
}

pub type Reply = Result<Value, QgaError>;

/// A validated request: the command name and its arguments.
#[derive(Debug)]
pub struct Request {
    pub execute: String,
    pub arguments: Map<String, Value>,
}

/// Check the request envelope. `Err` carries the `id` to echo, if any.
pub fn parse_request(value: Value) -> Result<(Request, Option<Value>), (QgaError, Option<Value>)> {
    let Value::Object(mut members) = value else {
        return Err((QgaError::generic("QMP input must be a JSON object"), None));
    };
    let id = members.remove("id");
    let mut execute = None;
    let mut arguments = Map::new();
    for (name, member) in members {
        match name.as_str() {
            "execute" => match member {
                Value::String(command) => execute = Some(command),
                _ => {
                    return Err((
                        QgaError::generic("QMP input member 'execute' must be a string"),
                        id,
                    ))
                }
            },
            "arguments" => match member {
                Value::Object(map) => arguments = map,
                _ => {
                    return Err((
                        QgaError::generic("QMP input member 'arguments' must be an object"),
                        id,
                    ))
                }
            },
            other => {
                return Err((
                    QgaError::generic(format!("QMP input member '{other}' is unexpected")),
                    id,
                ))
            }
        }
    }
    match execute {
        Some(execute) => Ok((Request { execute, arguments }, id)),
        None => Err((QgaError::generic("QMP input lacks member 'execute'"), id)),
    }
}

/// Command arguments, consumed member by member in schema order.
///
/// Like QAPI's input visitor: a missing required member, a wrong type and a
/// member nobody consumed (checked by [`Args::finish`]) are all errors.
pub struct Args {
    members: Map<String, Value>,
    path: String,
}

impl Args {
    pub fn new(members: Map<String, Value>) -> Self {
        Self {
            members,
            path: String::new(),
        }
    }

    fn name(&self, member: &str) -> String {
        if self.path.is_empty() {
            member.to_string()
        } else {
            format!("{}.{member}", self.path)
        }
    }

    fn missing(&self, member: &str) -> QgaError {
        QgaError::generic(format!("Parameter '{}' is missing", self.name(member)))
    }

    fn take(&mut self, member: &str) -> Option<Value> {
        self.members.remove(member)
    }

    pub fn opt_str(&mut self, member: &str) -> Result<Option<String>, QgaError> {
        match self.take(member) {
            None => Ok(None),
            Some(value) => expect_str(value, &self.name(member)).map(Some),
        }
    }

    pub fn str(&mut self, member: &str) -> Result<String, QgaError> {
        self.opt_str(member)?.ok_or_else(|| self.missing(member))
    }

    pub fn opt_int(&mut self, member: &str) -> Result<Option<i64>, QgaError> {
        match self.take(member) {
            None => Ok(None),
            Some(value) => expect_int(&value, &self.name(member)).map(Some),
        }
    }

    pub fn int(&mut self, member: &str) -> Result<i64, QgaError> {
        self.opt_int(member)?.ok_or_else(|| self.missing(member))
    }

    pub fn uint(&mut self, member: &str) -> Result<u64, QgaError> {
        let value = self.take(member).ok_or_else(|| self.missing(member))?;
        match value.as_u64().or_else(|| value.as_i64().map(|v| v as u64)) {
            // QEMU accepts negative values here for backward compatibility.
            Some(v) => Ok(v),
            None => Err(QgaError::generic(format!(
                "Parameter '{}' expects uint64",
                self.name(member)
            ))),
        }
    }

    pub fn opt_bool(&mut self, member: &str) -> Result<Option<bool>, QgaError> {
        match self.take(member) {
            None => Ok(None),
            Some(Value::Bool(b)) => Ok(Some(b)),
            Some(_) => Err(type_error(&self.name(member), "boolean")),
        }
    }

    pub fn bool(&mut self, member: &str) -> Result<bool, QgaError> {
        self.opt_bool(member)?.ok_or_else(|| self.missing(member))
    }

    pub fn opt_str_list(&mut self, member: &str) -> Result<Option<Vec<String>>, QgaError> {
        let Some(value) = self.take(member) else {
            return Ok(None);
        };
        let name = self.name(member);
        let Value::Array(items) = value else {
            return Err(type_error(&name, "array"));
        };
        items
            .into_iter()
            .enumerate()
            .map(|(i, item)| expect_str(item, &format!("{name}[{i}]")))
            .collect::<Result<Vec<_>, _>>()
            .map(Some)
    }

    pub fn str_list(&mut self, member: &str) -> Result<Vec<String>, QgaError> {
        self.opt_str_list(member)?
            .ok_or_else(|| self.missing(member))
    }

    /// A required list of objects; `visit` reads each element's members.
    pub fn object_list<T>(
        &mut self,
        member: &str,
        mut visit: impl FnMut(&mut Args) -> Result<T, QgaError>,
    ) -> Result<Vec<T>, QgaError> {
        let value = self.take(member).ok_or_else(|| self.missing(member))?;
        let name = self.name(member);
        let Value::Array(items) = value else {
            return Err(type_error(&name, "array"));
        };
        let mut out = Vec::with_capacity(items.len());
        for (i, item) in items.into_iter().enumerate() {
            let path = format!("{name}[{i}]");
            let Value::Object(members) = item else {
                return Err(type_error(&path, "object"));
            };
            let mut nested = Args { members, path };
            out.push(visit(&mut nested)?);
            nested.finish()?;
        }
        Ok(out)
    }

    /// The raw member, for QAPI alternates that the caller decodes itself.
    pub fn opt_raw(&mut self, member: &str) -> (Option<Value>, String) {
        let name = self.name(member);
        (self.take(member), name)
    }

    pub fn finish(self) -> Result<(), QgaError> {
        match self.members.keys().next() {
            None => Ok(()),
            Some(extra) => Err(QgaError::generic(format!(
                "Parameter '{}' is unexpected",
                self.name(extra)
            ))),
        }
    }
}

pub fn type_error(name: &str, expected: &str) -> QgaError {
    QgaError::generic(format!(
        "Invalid parameter type for '{name}', expected: {expected}"
    ))
}

fn expect_str(value: Value, name: &str) -> Result<String, QgaError> {
    match value {
        Value::String(s) => Ok(s),
        _ => Err(type_error(name, "string")),
    }
}

fn expect_int(value: &Value, name: &str) -> Result<i64, QgaError> {
    value.as_i64().ok_or_else(|| type_error(name, "integer"))
}

/// Decode a QAPI enum member given as a string.
pub fn enum_value<'a>(
    value: &str,
    name: &str,
    allowed: &'a [&'a str],
) -> Result<&'a str, QgaError> {
    allowed
        .iter()
        .find(|candidate| **candidate == value)
        .copied()
        .ok_or_else(|| {
            QgaError::generic(format!(
                "Parameter '{name}' does not accept value '{value}'"
            ))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(value: Value) -> Args {
        match value {
            Value::Object(map) => Args::new(map),
            _ => unreachable!(),
        }
    }

    #[test]
    fn envelope_errors_use_qemu_wording() {
        let err = |v: Value| parse_request(v).unwrap_err().0.desc;
        assert_eq!(err(json!([1])), "QMP input must be a JSON object");
        assert_eq!(err(json!({})), "QMP input lacks member 'execute'");
        assert_eq!(
            err(json!({"execute": 1})),
            "QMP input member 'execute' must be a string"
        );
        assert_eq!(
            err(json!({"execute": "x", "arguments": []})),
            "QMP input member 'arguments' must be an object"
        );
        assert_eq!(
            err(json!({"execute": "x", "exec-oob": "y"})),
            "QMP input member 'exec-oob' is unexpected"
        );
    }

    #[test]
    fn id_is_returned_even_when_the_envelope_is_bad() {
        let (_, id) = parse_request(json!({"id": 7})).unwrap_err();
        assert_eq!(id, Some(json!(7)));
    }

    #[test]
    fn argument_errors_use_qapi_wording() {
        let mut a = args(json!({"id": "x"}));
        assert_eq!(
            a.int("id").unwrap_err().desc,
            "Invalid parameter type for 'id', expected: integer"
        );
        let mut a = args(json!({}));
        assert_eq!(
            a.str("path").unwrap_err().desc,
            "Parameter 'path' is missing"
        );
        let a = args(json!({"bogus": 1}));
        assert_eq!(
            a.finish().unwrap_err().desc,
            "Parameter 'bogus' is unexpected"
        );
        let mut a = args(json!({"n": 1.5}));
        assert!(a.int("n").is_err());
        let mut a = args(json!({"arg": ["a", 2]}));
        assert_eq!(
            a.opt_str_list("arg").unwrap_err().desc,
            "Invalid parameter type for 'arg[1]', expected: string"
        );
    }

    #[test]
    fn nested_objects_carry_their_path() {
        let mut a = args(json!({"vcpus": [{"logical-id": 0, "online": true, "x": 1}]}));
        let err = a
            .object_list("vcpus", |v| {
                v.int("logical-id")?;
                v.bool("online")
            })
            .unwrap_err();
        assert_eq!(err.desc, "Parameter 'vcpus[0].x' is unexpected");

        let mut a = args(json!({"vcpus": [{"logical-id": 0}]}));
        let err = a
            .object_list("vcpus", |v| {
                v.int("logical-id")?;
                v.bool("online")
            })
            .unwrap_err();
        assert_eq!(err.desc, "Parameter 'vcpus[0].online' is missing");
    }

    #[test]
    fn uint_accepts_negative_like_qemu() {
        let mut a = args(json!({"n": -1}));
        assert_eq!(a.uint("n").unwrap(), u64::MAX);
        let mut a = args(json!({"n": "1"}));
        assert_eq!(
            a.uint("n").unwrap_err().desc,
            "Parameter 'n' expects uint64"
        );
    }
}
