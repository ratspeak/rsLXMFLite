//! MessagePack acceptance rules of the umsgpack decoder Python LXMF uses, and
//! its canonical re-encoding (`packb(unpackb(value))`), without allocation.
//!
//! Adapted from `lxmf_core::message::canonical` within this crate's profile:
//! nesting depth at most 8, at most `MAX_MAP_ENTRIES` entries in any map and
//! no extension types. Duplicate keys are found by pairwise comparison, which
//! the entry limit keeps bounded on small targets.

use crate::lxmf::{LxmfError, skip_value};

/// Entry limit of every map, at any depth, in this crate's MessagePack profile.
pub(crate) const MAX_MAP_ENTRIES: usize = 64;
const MAX_DEPTH: u8 = 8;
const MALFORMED: LxmfError = LxmfError::MalformedPayload;

/// Destination of canonical bytes.
pub(crate) trait Sink {
    const EMITS: bool = true;
    fn put(&mut self, bytes: &[u8]) -> Result<(), LxmfError>;
}

/// Validation only.
pub(crate) struct Discard;
impl Sink for Discard {
    const EMITS: bool = false;
    fn put(&mut self, _: &[u8]) -> Result<(), LxmfError> {
        Ok(())
    }
}

/// One decoded MessagePack header; floats are widened to f64 as Python does.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Head<'a> {
    Nil,
    Bool(bool),
    Int(i128),
    Float(f64),
    Str(&'a str),
    Bin(&'a [u8]),
    Array { count: usize, first: usize },
    Map { count: usize, first: usize },
}

fn read_be(data: &[u8], at: usize, width: usize) -> Result<(u64, usize), LxmfError> {
    let end = at
        .checked_add(width)
        .filter(|&end| end <= data.len())
        .ok_or(MALFORMED)?;
    let value = data[at..end]
        .iter()
        .fold(0u64, |acc, byte| (acc << 8) | u64::from(*byte));
    Ok((value, end))
}

fn take(data: &[u8], at: usize, length: u64) -> Result<(&[u8], usize), LxmfError> {
    let length = usize::try_from(length).map_err(|_| MALFORMED)?;
    let end = at
        .checked_add(length)
        .filter(|&end| end <= data.len())
        .ok_or(MALFORMED)?;
    Ok((&data[at..end], end))
}

/// Decode the header at `pos`. Returns the end of a scalar, or the position of
/// the first item of an array or map. Rejects `0xc1`, extension types, invalid
/// UTF-8 strings and truncation.
pub(crate) fn head(data: &[u8], pos: usize) -> Result<(Head<'_>, usize), LxmfError> {
    let marker = *data.get(pos).ok_or(MALFORMED)?;
    let p = pos + 1;
    let int = |width: usize, signed: bool| -> Result<(Head<'_>, usize), LxmfError> {
        let (raw, end) = read_be(data, p, width)?;
        let shift = 64 - 8 * width as u32;
        let value = if signed {
            i128::from(((raw << shift) as i64) >> shift)
        } else {
            i128::from(raw)
        };
        Ok((Head::Int(value), end))
    };
    let length = |width: usize| read_be(data, p, width);
    Ok(match marker {
        0x00..=0x7f => (Head::Int(i128::from(marker)), p),
        0xe0..=0xff => (Head::Int(i128::from(marker as i8)), p),
        0xc0 => (Head::Nil, p),
        0xc2 | 0xc3 => (Head::Bool(marker == 0xc3), p),
        0xcc => return int(1, false),
        0xcd => return int(2, false),
        0xce => return int(4, false),
        0xcf => return int(8, false),
        0xd0 => return int(1, true),
        0xd1 => return int(2, true),
        0xd2 => return int(4, true),
        0xd3 => return int(8, true),
        0xca => {
            let (raw, end) = read_be(data, p, 4)?;
            (Head::Float(f64::from(f32::from_bits(raw as u32))), end)
        }
        0xcb => {
            let (raw, end) = read_be(data, p, 8)?;
            (Head::Float(f64::from_bits(raw)), end)
        }
        0xa0..=0xbf | 0xd9..=0xdb => {
            let (size, start) = match marker {
                0xd9 => length(1)?,
                0xda => length(2)?,
                0xdb => length(4)?,
                _ => (u64::from(marker & 0x1f), p),
            };
            let (bytes, end) = take(data, start, size)?;
            let text = core::str::from_utf8(bytes).map_err(|_| MALFORMED)?;
            (Head::Str(text), end)
        }
        0xc4..=0xc6 => {
            let (size, start) = length(1 << (marker - 0xc4))?;
            let (bytes, end) = take(data, start, size)?;
            (Head::Bin(bytes), end)
        }
        0x90..=0x9f | 0xdc | 0xdd | 0x80..=0x8f | 0xde | 0xdf => {
            let (count, first) = match marker {
                0xdc | 0xde => length(2)?,
                0xdd | 0xdf => length(4)?,
                _ => (u64::from(marker & 0x0f), p),
            };
            let count = usize::try_from(count).map_err(|_| MALFORMED)?;
            if matches!(marker, 0x90..=0x9f | 0xdc | 0xdd) {
                (Head::Array { count, first }, first)
            } else {
                (Head::Map { count, first }, first)
            }
        }
        _ => return Err(MALFORMED),
    })
}

fn write_int<S: Sink>(out: &mut S, value: i128) -> Result<(), LxmfError> {
    if value < 0 {
        if value >= -32 {
            out.put(&[value as i8 as u8])
        } else if value >= i128::from(i8::MIN) {
            out.put(&[0xd0, value as i8 as u8])
        } else if value >= i128::from(i16::MIN) {
            out.put(&[0xd1])?;
            out.put(&(value as i16).to_be_bytes())
        } else if value >= i128::from(i32::MIN) {
            out.put(&[0xd2])?;
            out.put(&(value as i32).to_be_bytes())
        } else {
            out.put(&[0xd3])?;
            out.put(&(value as i64).to_be_bytes())
        }
    } else if value < 128 {
        out.put(&[value as u8])
    } else if value <= i128::from(u8::MAX) {
        out.put(&[0xcc, value as u8])
    } else if value <= i128::from(u16::MAX) {
        out.put(&[0xcd])?;
        out.put(&(value as u16).to_be_bytes())
    } else if value <= i128::from(u32::MAX) {
        out.put(&[0xce])?;
        out.put(&(value as u32).to_be_bytes())
    } else {
        out.put(&[0xcf])?;
        out.put(&(value as u64).to_be_bytes())
    }
}

/// Smallest header for `length`: a fix form below `fix.1`, then 8/16/32-bit forms
/// (`wide[0] == 0` when the type has no 8-bit form).
fn write_len<S: Sink>(
    out: &mut S,
    length: usize,
    fix: Option<(u8, usize)>,
    wide: [u8; 3],
) -> Result<(), LxmfError> {
    match fix {
        Some((base, limit)) if length < limit => out.put(&[base | length as u8]),
        _ if length <= usize::from(u8::MAX) && wide[0] != 0 => out.put(&[wide[0], length as u8]),
        _ if length <= usize::from(u16::MAX) => {
            out.put(&[wide[1]])?;
            out.put(&(length as u16).to_be_bytes())
        }
        _ => {
            let length = u32::try_from(length).map_err(|_| LxmfError::TooLong)?;
            out.put(&[wide[2]])?;
            out.put(&length.to_be_bytes())
        }
    }
}

/// Validate one value at `pos` and write its canonical encoding to `out`.
/// Returns the end of the value; bytes after it are not examined.
pub(crate) fn walk<S: Sink>(
    data: &[u8],
    pos: usize,
    depth: u8,
    out: &mut S,
) -> Result<usize, LxmfError> {
    if depth > MAX_DEPTH {
        return Err(MALFORMED);
    }
    let (value, end) = head(data, pos)?;
    match value {
        Head::Nil => out.put(&[0xc0])?,
        Head::Bool(value) => out.put(&[0xc2 | u8::from(value)])?,
        Head::Int(value) => write_int(out, value)?,
        Head::Float(value) => {
            out.put(&[0xcb])?;
            out.put(&value.to_bits().to_be_bytes())?;
        }
        Head::Str(text) => {
            write_len(out, text.len(), Some((0xa0, 32)), [0xd9, 0xda, 0xdb])?;
            out.put(text.as_bytes())?;
        }
        Head::Bin(bytes) => {
            write_len(out, bytes.len(), None, [0xc4, 0xc5, 0xc6])?;
            out.put(bytes)?;
        }
        Head::Array { count, first } => {
            write_len(out, count, Some((0x90, 16)), [0, 0xdc, 0xdd])?;
            let mut item = first;
            for _ in 0..count {
                item = walk(data, item, depth + 1, out)?;
            }
            return Ok(item);
        }
        Head::Map { count, first } => return walk_map(data, first, count, depth, out),
    }
    Ok(end)
}

fn walk_map<S: Sink>(
    data: &[u8],
    first: usize,
    count: usize,
    depth: u8,
    out: &mut S,
) -> Result<usize, LxmfError> {
    if count > MAX_MAP_ENTRIES {
        return Err(LxmfError::TooManyFields);
    }
    let mut pos = first;
    let mut unique = 0usize;
    for index in 0..count {
        let key = pos;
        // Lists become tuples and bypass the duplicate check; later ones overwrite.
        let list = matches!(data.get(key), Some(0x90..=0x9f | 0xdc | 0xdd));
        pos = walk(data, key, depth + 1, &mut Discard)?;
        if !list && !hashable(data, key)? {
            return Err(MALFORMED);
        }
        let earlier = first_equal(data, first, index, key)?;
        if earlier && !list {
            return Err(MALFORMED);
        }
        // When emitting, values are validated once, by the emitting walk below.
        pos = if S::EMITS {
            skip_value(data, pos, 0)?
        } else {
            walk(data, pos, depth + 1, &mut Discard)?
        };
        if list && !hashable(data, key)? {
            return Err(MALFORMED);
        }
        if !earlier {
            unique += 1;
        }
    }
    if S::EMITS {
        write_len(out, unique, Some((0x80, 16)), [0, 0xde, 0xdf])?;
        let mut key = first;
        for index in 0..count {
            let value = skip_value(data, key, 0)?;
            let next = skip_value(data, value, 0)?;
            if first_equal(data, first, index, key)? {
                // Overwritten list-key values are still decoded by Python.
                walk(data, value, depth + 1, &mut Discard)?;
            } else {
                walk(data, key, depth + 1, out)?;
                // A repeated list key keeps its first position and takes the last value.
                let mut last = value;
                let mut later = next;
                for _ in index + 1..count {
                    let later_value = skip_value(data, later, 0)?;
                    if keys_equal(data, key, later)? {
                        last = later_value;
                    }
                    later = skip_value(data, later_value, 0)?;
                }
                if last != value {
                    walk(data, value, depth + 1, &mut Discard)?;
                }
                walk(data, last, depth + 1, out)?;
            }
            key = next;
        }
    }
    Ok(pos)
}

/// Python `len()` of a valid map: its number of distinct keys.
pub(crate) fn map_len(data: &[u8], first: usize, count: usize) -> Result<usize, LxmfError> {
    let mut key = first;
    let mut unique = 0;
    for index in 0..count {
        if !first_equal(data, first, index, key)? {
            unique += 1;
        }
        key = skip_value(data, skip_value(data, key, 0)?, 0)?;
    }
    Ok(unique)
}

/// Python `value == target` for an integer target.
pub(crate) fn equals_int(value: Head<'_>, target: i128) -> bool {
    matches!(identity(value), Identity::Number(n) if n == target)
}

/// Whether an earlier key of the map starting at `first` equals the key at `key`.
fn first_equal(data: &[u8], first: usize, index: usize, key: usize) -> Result<bool, LxmfError> {
    let mut earlier = first;
    for _ in 0..index {
        if keys_equal(data, earlier, key)? {
            return Ok(true);
        }
        earlier = skip_value(data, skip_value(data, earlier, 0)?, 0)?;
    }
    Ok(false)
}

/// Python hashability: maps, and tuples containing maps, are unhashable.
fn hashable(data: &[u8], pos: usize) -> Result<bool, LxmfError> {
    match head(data, pos)?.0 {
        Head::Map { .. } => Ok(false),
        Head::Array { count, first } => {
            let mut item = first;
            for _ in 0..count {
                if !hashable(data, item)? {
                    return Ok(false);
                }
                item = skip_value(data, item, 0)?;
            }
            Ok(true)
        }
        _ => Ok(true),
    }
}

/// Python value identity of a map key.
enum Identity<'a> {
    Nil,
    Number(i128),
    Float(u64),
    NaN,
    Str(&'a [u8]),
    Bin(&'a [u8]),
    Tuple(usize, usize),
    Unhashable,
}

fn identity(value: Head<'_>) -> Identity<'_> {
    match value {
        Head::Nil => Identity::Nil,
        Head::Bool(value) => Identity::Number(i128::from(value)),
        Head::Int(value) => Identity::Number(value),
        Head::Float(value) if value.is_nan() => Identity::NaN,
        // Integral floats equal the integer of the same value.
        Head::Float(value)
            if value > -1.0e38 && value < 1.0e38 && (value as i128) as f64 == value =>
        {
            Identity::Number(value as i128)
        }
        Head::Float(value) => Identity::Float(value.to_bits()),
        Head::Str(text) => Identity::Str(text.as_bytes()),
        Head::Bin(bytes) => Identity::Bin(bytes),
        Head::Array { count, first } => Identity::Tuple(count, first),
        Head::Map { .. } => Identity::Unhashable,
    }
}

/// Python `==` between two hashable keys; NaN never equals anything.
fn keys_equal(data: &[u8], a: usize, b: usize) -> Result<bool, LxmfError> {
    Ok(
        match (identity(head(data, a)?.0), identity(head(data, b)?.0)) {
            (Identity::Nil, Identity::Nil) => true,
            (Identity::Number(x), Identity::Number(y)) => x == y,
            (Identity::Float(x), Identity::Float(y)) => x == y,
            (Identity::Str(x), Identity::Str(y)) | (Identity::Bin(x), Identity::Bin(y)) => x == y,
            (Identity::Tuple(n, mut x), Identity::Tuple(m, mut y)) => {
                if n != m {
                    return Ok(false);
                }
                for _ in 0..n {
                    if !keys_equal(data, x, y)? {
                        return Ok(false);
                    }
                    x = skip_value(data, x, 0)?;
                    y = skip_value(data, y, 0)?;
                }
                true
            }
            _ => false,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    struct Collect(Vec<u8>);
    impl Sink for Collect {
        fn put(&mut self, bytes: &[u8]) -> Result<(), LxmfError> {
            self.0.extend_from_slice(bytes);
            Ok(())
        }
    }

    fn canon(input: &[u8]) -> Result<Vec<u8>, LxmfError> {
        let mut out = Collect(Vec::new());
        let end = walk(input, 0, 0, &mut out)?;
        assert_eq!(end, input.len());
        Ok(out.0)
    }

    #[test]
    fn reencodes_minimally_and_widens_floats() {
        let cases: &[(&[u8], &[u8])] = &[
            (
                &[0x91, 0xca, 0x3f, 0xc0, 0, 0],
                &[0x91, 0xcb, 0x3f, 0xf8, 0, 0, 0, 0, 0, 0],
            ),
            (&[0xcd, 0, 5], &[5]),
            (&[0xd9, 2, b'h', b'i'], &[0xa2, b'h', b'i']),
            (&[0xde, 0, 1, 1, 2], &[0x81, 1, 2]),
            (&[0xc5, 0, 1, 0xaa], &[0xc4, 1, 0xaa]),
            (&[0xd0, 0xff], &[0xff]),
            (&[0xd1, 0x00, 0x7f], &[0x7f]),
            (&[0x82, 0x91, 1, 1, 0x91, 1, 2], &[0x81, 0x91, 1, 2]),
        ];
        for (input, expected) in cases {
            assert_eq!(canon(input).unwrap(), *expected, "{input:02x?}");
        }
    }

    #[test]
    fn rejects_what_the_python_decoder_rejects() {
        for input in [
            &[0x82, 1, 1, 1, 2][..],
            &[0x82, 1, 1, 0xcb, 0x3f, 0xf0, 0, 0, 0, 0, 0, 0, 2],
            &[0x82, 0xc3, 1, 1, 2],
            &[0x81, 0x80, 1],
            &[0x81, 0x91, 0x80, 1],
            &[0xa1, 0xff],
            &[0xc1],
            &[0xd4, 1, 0],
        ] {
            assert!(canon(input).is_err(), "{input:02x?}");
        }
        let nan = [0xcb, 0x7f, 0xf8, 0, 0, 0, 0, 0, 0];
        let map = [&[0x82][..], &nan, &[1], &nan, &[2]].concat();
        assert_eq!(canon(&map).unwrap(), map);
        assert_eq!(
            canon(&[0x82, 0xa1, b'a', 1, 0xc4, 1, b'a', 2])
                .unwrap()
                .len(),
            8
        );
        // Embedded profile: at most 64 entries in any nested map.
        let mut wide = std::vec![0xde, 0, 65];
        for key in 0..65u8 {
            wide.extend_from_slice(&[key, 0xc0]);
        }
        assert_eq!(canon(&wide), Err(LxmfError::TooManyFields));
        wide[2] = 64;
        wide.truncate(wide.len() - 2);
        assert_eq!(canon(&wide).unwrap()[..3], [0xde, 0, 64]);
    }
}
