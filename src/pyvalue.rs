//! Python value semantics over decoded MessagePack, without allocation.
//!
//! Adapted from the `lxmf_core::handlers` helpers that mirror `len()`,
//! indexing, `==`, `int()` and `float()` in the Python announce validators.

use crate::canonical::{self, Head};
use crate::lxmf::skip_value;

/// Python whitespace for `str.strip()`.
pub(crate) fn is_python_space(c: char) -> bool {
    c.is_whitespace() || matches!(c, '\u{1c}'..='\u{1f}')
}

/// Python `str.strip()` with no arguments.
pub(crate) fn python_strip(text: &str) -> &str {
    text.trim_matches(is_python_space)
}

/// Characters stripped by Python `bytes.strip()` / skipped by `int(bytes)`.
fn is_ascii_python_space(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\n' | '\r' | '\x0b' | '\x0c')
}

/// Non-ASCII Unicode 15.0 `Nd` runs as `(first, length)`; each run starts at zero.
const DECIMAL_RUNS: [(u32, u32); 63] = [
    (0x660, 10),
    (0x6f0, 10),
    (0x7c0, 10),
    (0x966, 10),
    (0x9e6, 10),
    (0xa66, 10),
    (0xae6, 10),
    (0xb66, 10),
    (0xbe6, 10),
    (0xc66, 10),
    (0xce6, 10),
    (0xd66, 10),
    (0xde6, 10),
    (0xe50, 10),
    (0xed0, 10),
    (0xf20, 10),
    (0x1040, 10),
    (0x1090, 10),
    (0x17e0, 10),
    (0x1810, 10),
    (0x1946, 10),
    (0x19d0, 10),
    (0x1a80, 10),
    (0x1a90, 10),
    (0x1b50, 10),
    (0x1bb0, 10),
    (0x1c40, 10),
    (0x1c50, 10),
    (0xa620, 10),
    (0xa8d0, 10),
    (0xa900, 10),
    (0xa9d0, 10),
    (0xa9f0, 10),
    (0xaa50, 10),
    (0xabf0, 10),
    (0xff10, 10),
    (0x104a0, 10),
    (0x10d30, 10),
    (0x11066, 10),
    (0x110f0, 10),
    (0x11136, 10),
    (0x111d0, 10),
    (0x112f0, 10),
    (0x11450, 10),
    (0x114d0, 10),
    (0x11650, 10),
    (0x116c0, 10),
    (0x11730, 10),
    (0x118e0, 10),
    (0x11950, 10),
    (0x11c50, 10),
    (0x11d50, 10),
    (0x11da0, 10),
    (0x11f50, 10),
    (0x16a60, 10),
    (0x16ac0, 10),
    (0x16b50, 10),
    (0x1d7ce, 50),
    (0x1e140, 10),
    (0x1e2f0, 10),
    (0x1e4f0, 10),
    (0x1e950, 10),
    (0x1fbf0, 10),
];

/// Decimal value of a digit accepted by Python `int(str)`.
fn decimal_digit(c: char, unicode: bool) -> Option<u32> {
    if let Some(d) = c.to_digit(10) {
        return Some(d);
    }
    if !unicode || c.is_ascii() {
        return None;
    }
    let code = c as u32;
    DECIMAL_RUNS
        .iter()
        .find(|&&(first, length)| (first..first + length).contains(&code))
        .map(|&(first, _)| (code - first) % 10)
}

/// Text of a str/bin value with Python's surrounding whitespace removed, and
/// whether Unicode digits are allowed (str) or not (bytes).
fn numeric_text<'a>(value: Head<'a>) -> Option<(&'a str, bool)> {
    match value {
        Head::Str(text) => Some((python_strip(text), true)),
        Head::Bin(bytes) => {
            let text = core::str::from_utf8(bytes).ok().filter(|t| t.is_ascii())?;
            Some((text.trim_matches(is_ascii_python_space), false))
        }
        _ => None,
    }
}

/// Digits with single underscores between them; calls `digit` for each one.
fn digit_run(text: &str, unicode: bool, mut digit: impl FnMut(u32)) -> Option<()> {
    let mut any = false;
    let mut previous_digit = false;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '_' {
            let next_digit = chars
                .peek()
                .is_some_and(|n| decimal_digit(*n, unicode).is_some());
            if !previous_digit || !next_digit {
                return None;
            }
            previous_digit = false;
            continue;
        }
        digit(decimal_digit(c, unicode)?);
        previous_digit = true;
        any = true;
    }
    any.then_some(())
}

/// Python `int(value)`; `None` where Python raises. Saturates outside `i128`.
pub(crate) fn int(value: Head<'_>) -> Option<i128> {
    match value {
        Head::Int(n) => Some(n),
        Head::Bool(b) => Some(i128::from(b)),
        Head::Float(f) => f.is_finite().then_some(f as i128),
        Head::Str(_) | Head::Bin(_) => {
            let (text, unicode) = numeric_text(value)?;
            let (negative, digits) = match text.strip_prefix('-') {
                Some(rest) => (true, rest),
                None => (false, text.strip_prefix('+').unwrap_or(text)),
            };
            let mut magnitude = 0i128;
            digit_run(digits, unicode, |d| {
                magnitude = magnitude.saturating_mul(10).saturating_add(i128::from(d));
            })?;
            Some(if negative { -magnitude } else { magnitude })
        }
        _ => None,
    }
}

/// Whether Python `float(value)` succeeds.
pub(crate) fn float_ok(value: Head<'_>) -> bool {
    match value {
        Head::Int(_) | Head::Bool(_) | Head::Float(_) => true,
        Head::Str(_) | Head::Bin(_) => float_text_ok(value).is_some(),
        _ => false,
    }
}

fn float_text_ok(value: Head<'_>) -> Option<()> {
    let (text, unicode) = numeric_text(value)?;
    let body = text.strip_prefix(['+', '-']).unwrap_or(text);
    for special in ["inf", "infinity", "nan"] {
        if body.eq_ignore_ascii_case(special) {
            return Some(());
        }
    }
    let (mantissa, exponent) = match body.find(['e', 'E']) {
        Some(at) => (&body[..at], Some(&body[at + 1..])),
        None => (body, None),
    };
    let (whole, fraction) = match mantissa.split_once('.') {
        Some((w, f)) => (w, Some(f)),
        None => (mantissa, None),
    };
    let part = |part: &str| part.is_empty() || digit_run(part, unicode, |_| {}).is_some();
    if !part(whole) || !fraction.is_none_or(part) {
        return None;
    }
    if whole.is_empty() && fraction.is_none_or(str::is_empty) {
        return None;
    }
    if let Some(exponent) = exponent {
        let digits = exponent.strip_prefix(['+', '-']).unwrap_or(exponent);
        digit_run(digits, unicode, |_| {})?;
    }
    Some(())
}

/// `Some(state)` when Python's `value == True` or `value == False` holds.
pub(crate) fn bool_state(value: Head<'_>) -> Option<bool> {
    if canonical::equals_int(value, 1) {
        Some(true)
    } else if canonical::equals_int(value, 0) {
        Some(false)
    } else {
        None
    }
}

/// Python `len()`; `None` where Python raises `TypeError`.
pub(crate) fn len(data: &[u8], value: Head<'_>) -> Option<usize> {
    match value {
        Head::Array { count, .. } => Some(count),
        Head::Map { count, first } => canonical::map_len(data, first, count).ok(),
        Head::Str(text) => Some(text.chars().count()),
        Head::Bin(bytes) => Some(bytes.len()),
        _ => None,
    }
}

/// Python `value[index]` for a non-negative integer index.
pub(crate) fn index<'a>(data: &'a [u8], value: Head<'a>, index: usize) -> Option<Head<'a>> {
    match value {
        Head::Array { count, first } => {
            if index >= count {
                return None;
            }
            let mut pos = first;
            for _ in 0..index {
                pos = skip_value(data, pos, 0).ok()?;
            }
            canonical::head(data, pos).ok().map(|(head, _)| head)
        }
        Head::Bin(bytes) => bytes.get(index).map(|b| Head::Int(i128::from(*b))),
        Head::Str(text) => {
            let (at, c) = text.char_indices().nth(index)?;
            Some(Head::Str(&text[at..at + c.len_utf8()]))
        }
        Head::Map { count, first } => {
            let mut key = first;
            for _ in 0..count {
                let value = skip_value(data, key, 0).ok()?;
                let (head, _) = canonical::head(data, key).ok()?;
                if canonical::equals_int(head, index as i128) {
                    return canonical::head(data, value).ok().map(|(head, _)| head);
                }
                key = skip_value(data, value, 0).ok()?;
            }
            None
        }
        _ => None,
    }
}
