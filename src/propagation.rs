//! Bounded client codecs adapted from `lxmf-core::{handlers, message}`.
//! Rust owns wire validation; discovery, scheduling and persistence belong to
//! the embedding runtime. No allocation or propagation-node server is provided.

use crate::canonical::{self, Discard, Head};
use crate::lxmf::{LXMF_PACKED_PREFIX, LxmfError, skip_value, value_as_bytes};
use crate::pyvalue;
use rns_lite_core::{crypto, identity::identity_hash};
use sha2::{Digest, Sha256};

/// Name key of node announce metadata (`LXMF.PN_META_NAME`).
pub const PN_META_NAME: u8 = 0x01;

/// One bounded `/get` operation. Fetch never includes haves: deleting a remote
/// copy requires a separate Purge after the embedding storage owner commits it.
#[derive(Clone, Copy, Debug)]
pub enum GetRequest<'a> {
    List,
    Fetch {
        transient_id: &'a [u8; 32],
        limit_bytes: u16,
    },
    Purge {
        durable_transient_id: &'a [u8; 32],
    },
}

/// Pack the Link REQUEST plaintext `[timestamp, hash("/get"), data]`.
/// Adapted from `rns-link::Link::prepare_request` and the LXMF propagation client.
/// Always fits a Link packet. The request ID is the TRANSMITTED packet hash's
/// first 16 bytes for packet delivery, not the hash of these plaintext bytes.
/// This helper neither sends nor tracks the request. The host must install
/// that ID, Link incarnation and deadline before driver admission/callbacks.
pub fn build_get_request(
    timestamp: f64,
    request: GetRequest<'_>,
    out: &mut [u8],
) -> Result<usize, LxmfError> {
    if !timestamp.is_finite()
        || timestamp < 0.0
        || matches!(request, GetRequest::Fetch { limit_bytes: 0, .. })
    {
        return Err(LxmfError::MalformedPayload);
    }
    let body_len = match request {
        GetRequest::List => 3,
        GetRequest::Purge { .. } => 37,
        GetRequest::Fetch { .. } => 46,
    };
    let total = 28 + body_len;
    if out.len() < total {
        return Err(LxmfError::OutputTooSmall);
    }
    out[0] = 0x93;
    out[1] = 0xcb;
    out[2..10].copy_from_slice(&timestamp.to_be_bytes());
    out[10..12].copy_from_slice(&[0xc4, 16]);
    out[12..28].copy_from_slice(&Sha256::digest(b"/get")[..16]);
    match request {
        GetRequest::List => out[28..31].copy_from_slice(&[0x92, 0xc0, 0xc0]),
        GetRequest::Purge {
            durable_transient_id,
        } => {
            out[28..33].copy_from_slice(&[0x92, 0xc0, 0x91, 0xc4, 32]);
            out[33..65].copy_from_slice(durable_transient_id);
        }
        GetRequest::Fetch {
            transient_id,
            limit_bytes,
        } => {
            out[28..32].copy_from_slice(&[0x93, 0x91, 0xc4, 32]);
            out[32..64].copy_from_slice(transient_id);
            out[64] = 0x90; // no purge during fetch
            out[65] = 0xcb;
            out[66..74].copy_from_slice(&(f64::from(limit_bytes) / 1000.0).to_be_bytes());
        }
    }
    Ok(total)
}

/// Match a decrypted packet/Resource RESPONSE envelope to `expected_id` and
/// return its borrowed, still-encoded response value. Extra envelope elements
/// and trailing data are rejected. The caller checks authenticated Link ownership,
/// the request's live state and deadline; this helper has no request registry.
pub fn response_data<'a>(data: &'a [u8], expected_id: &[u8; 16]) -> Result<&'a [u8], LxmfError> {
    let mut items = array_items(data)?;
    if items.len() != 2 {
        return Err(LxmfError::MalformedPayload);
    }
    let id = items.next().ok_or(LxmfError::MalformedPayload)?;
    if value_as_bytes(id) != Some(expected_id.as_slice()) {
        return Err(LxmfError::MalformedPayload);
    }
    items.next().ok_or(LxmfError::MalformedPayload)
}

/// Validate the entire node list but retain only its first advertised ID.
/// The server determines ordering. Re-list after a bounded fetch/purge cycle.
pub fn first_available(data: &[u8]) -> Result<(Option<[u8; 32]>, usize), LxmfError> {
    available_at(data, 0)
}

/// Validate every advertised ID, retaining only the requested position. A
/// bounded client can skip an undecryptable entry without caching the whole
/// inbox or allowing that entry to block all later messages.
pub fn available_at(data: &[u8], index: usize) -> Result<(Option<[u8; 32]>, usize), LxmfError> {
    let items = array_items(data)?;
    let count = items.len();
    let mut first = None;
    for (position, item) in items.enumerate() {
        let id: [u8; 32] = value_as_bytes(item)
            .ok_or(LxmfError::MalformedPayload)?
            .try_into()
            .map_err(|_| LxmfError::MalformedPayload)?;
        if position == index {
            first = Some(id);
        }
    }
    Ok((first, count))
}

/// A one-message fetch may return an empty list (gone/limit refusal), or one
/// encrypted entry. Refuse unsolicited extra entries and malformed item types.
pub fn fetched_message(data: &[u8]) -> Result<Option<&[u8]>, LxmfError> {
    let mut items = array_items(data)?;
    if items.len() > 1 {
        return Err(LxmfError::MalformedPayload);
    }
    items
        .next()
        .map(|item| value_as_bytes(item).ok_or(LxmfError::MalformedPayload))
        .transpose()
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct NodeAnnounce<'a> {
    /// Python `int()` of the timebase, clamped to the `i64` range.
    pub timebase: i64,
    pub enabled: bool,
    /// Decimal kilobytes, below zero clamped to zero. The caller must check
    /// conversion to its local byte and buffer limits; a valid `u64` value need
    /// not fit a 32-bit device.
    pub transfer_limit_kb: u64,
    pub sync_limit_kb: u64,
    /// Costs as the upstream announce handler takes them: the fractional
    /// slot 7 when present, else `int()` of slot 5. Values are not clamped;
    /// use [`node_outbound_stamp_cost_fp`] for the cost a stamp must meet.
    pub stamp_cost: f64,
    pub stamp_flex: f64,
    pub peering_cost: f64,
    /// Advertised name as [`node_announce_name`] returns it.
    pub name: Option<&'a str>,
}

/// Validate one complete array using the supported MessagePack value types.
/// Reject trailing bytes, excessive nesting, truncated values and MessagePack
/// extension types. Work is bounded by the input slice, whose size the caller limits.
pub fn array_items(data: &[u8]) -> Result<ArrayItems<'_>, LxmfError> {
    if skip_value(data, 0, 0)? != data.len() {
        return Err(LxmfError::MalformedPayload);
    }
    let (pos, remaining) = match data[0] {
        b @ 0x90..=0x9f => (1, usize::from(b & 15)),
        0xdc => (
            3,
            u16::from_be_bytes(data[1..3].try_into().unwrap()) as usize,
        ),
        0xdd => (
            5,
            u32::from_be_bytes(data[1..5].try_into().unwrap()) as usize,
        ),
        _ => return Err(LxmfError::MalformedPayload),
    };
    Ok(ArrayItems {
        data,
        pos,
        remaining,
    })
}

pub struct ArrayItems<'a> {
    data: &'a [u8],
    pos: usize,
    remaining: usize,
}

impl<'a> Iterator for ArrayItems<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        // The constructor already validated every item and recursion bound.
        let end = skip_value(self.data, self.pos, 0).ok()?;
        let item = &self.data[self.pos..end];
        self.pos = end;
        self.remaining -= 1;
        Some(item)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl ExactSizeIterator for ArrayItems<'_> {}

/// The leading value under Python's decoder rules; later bytes are ignored, as
/// `umsgpack.unpackb` ignores them.
fn decode_python(data: &[u8]) -> Option<Head<'_>> {
    canonical::walk(data, 0, 0, &mut Discard).ok()?;
    canonical::head(data, 0).ok().map(|(head, _)| head)
}

/// Python `float()` succeeds on the first three items of a list.
fn floats(data: &[u8], list: Head<'_>) -> Option<()> {
    if !matches!(list, Head::Array { .. }) {
        return None;
    }
    for i in 0..3 {
        pyvalue::float_ok(pyvalue::index(data, list, i)?).then_some(())?;
    }
    Some(())
}

/// The decoded announce when Python `pn_announce_data_is_valid` accepts it.
fn valid_node_announce(data: &[u8]) -> Option<Head<'_>> {
    let value = decode_python(data)?;
    let length = pyvalue::len(data, value)?;
    if length < 7 {
        return None;
    }
    let at = |i| pyvalue::index(data, value, i);
    pyvalue::int(at(1)?)?;
    pyvalue::bool_state(at(2)?)?;
    pyvalue::int(at(3)?)?;
    pyvalue::int(at(4)?)?;
    floats(data, at(5)?)?;
    if !matches!(at(6)?, Head::Map { .. }) {
        return None;
    }
    if length > 7 {
        floats(data, at(7)?)?;
    }
    Some(value)
}

/// Python `pn_announce_data_is_valid`, including its `int()`/`float()`
/// coercions and the transitional slot 7 check. Within this crate's
/// MessagePack profile: nesting depth 8, 64 entries per map, no extension types.
pub fn node_announce_is_valid(data: &[u8]) -> bool {
    valid_node_announce(data).is_some()
}

/// Python `pn_name_from_app_data`: the raw UTF-8 binary name metadata of valid
/// node announce data. It is not filtered; sanitize and bound it before display.
pub fn node_announce_name(data: &[u8]) -> Option<&str> {
    let value = valid_node_announce(data)?;
    let metadata = pyvalue::index(data, value, 6)?;
    match pyvalue::index(data, metadata, usize::from(PN_META_NAME))? {
        Head::Bin(bytes) => core::str::from_utf8(bytes).ok(),
        _ => None,
    }
}

/// Parse node app data that [`node_announce_is_valid`] accepts, after the
/// caller authenticates and binds the announce. Values are extracted with
/// Python `int()` as the upstream announce handler does, and `None` is
/// returned where that conversion raises; a non-finite slot 7 cost is refused.
/// Bytes after the array are ignored.
pub fn parse_node_announce(data: &[u8]) -> Option<NodeAnnounce<'_>> {
    let value = valid_node_announce(data)?;
    let int_at = |i| pyvalue::int(pyvalue::index(data, value, i)?);
    let limit = |raw: i128| raw.clamp(0, i128::from(u64::MAX)) as u64;
    let ceil_costs = pyvalue::index(data, value, 5)?;
    for i in 0..3 {
        pyvalue::int(pyvalue::index(data, ceil_costs, i)?)?;
    }
    let fractional = pyvalue::len(data, value)? > 7;
    let costs = pyvalue::index(data, value, if fractional { 7 } else { 5 })?;
    let cost = |i| {
        let item = pyvalue::index(data, costs, i)?;
        if fractional {
            pyvalue::float(item).filter(|c| c.is_finite())
        } else {
            pyvalue::int(item).map(|c| c as f64)
        }
    };
    Some(NodeAnnounce {
        timebase: int_at(1)?.clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64,
        enabled: pyvalue::bool_state(pyvalue::index(data, value, 2)?)?,
        transfer_limit_kb: limit(int_at(3)?),
        sync_limit_kb: limit(int_at(4)?),
        stamp_cost: cost(0)?,
        stamp_flex: cost(1)?,
        peering_cost: cost(2)?,
        name: node_announce_name(data),
    })
}

/// The fixed-point propagation stamp cost a client must meet for a node, as
/// upstream `LXMRouter.get_outbound_propagation_cost` derives it from cached
/// app data: slot 7's first cost when present, else slot 5's, used only when
/// it is an integer or float (not a bool), clamped to `0..=100`. `None` where
/// upstream has no cost.
pub fn node_outbound_stamp_cost_fp(data: &[u8]) -> Option<u16> {
    let value = valid_node_announce(data)?;
    let slot = if pyvalue::len(data, value)? > 7 { 7 } else { 5 };
    let cost = match pyvalue::index(data, pyvalue::index(data, value, slot)?, 0)? {
        Head::Int(n) => n as f64,
        // Python's max(0, min(nan, 100)) is 0.
        Head::Float(f) if f.is_nan() => 0.0,
        Head::Float(f) => f,
        _ => return None,
    };
    crate::stamp::cost_to_fp(cost.clamp(0.0, 100.0))
}

/// First byte of the MessagePack delivery-announce format (fixarray or
/// array16); anything else is the original raw-name format.
fn is_announce_array_marker(byte: u8) -> bool {
    matches!(byte, 0x90..=0x9f | 0xdc)
}

/// Python `display_name_from_app_data`, copied into `out`: the name with NUL
/// characters and surrounding whitespace removed, or the whole original-format
/// data when it is UTF-8. `Ok(None)` where Python returns `None`; `OutputTooSmall`
/// when the name does not fit (it is never longer than `data`). The name is
/// not filtered; sanitize and bound it before display.
pub fn display_name<'o>(data: &[u8], out: &'o mut [u8]) -> Result<Option<&'o str>, LxmfError> {
    let Some(&first) = data.first() else {
        return Ok(None);
    };
    let strip_nul = is_announce_array_marker(first);
    let name = if strip_nul {
        let Some(list) = decode_python(data) else {
            return Ok(None);
        };
        // A str element has no .decode() in Python and yields None.
        let Some(Head::Bin(bytes)) = pyvalue::index(data, list, 0) else {
            return Ok(None);
        };
        let Ok(text) = core::str::from_utf8(bytes) else {
            return Ok(None);
        };
        // Trimming NULs with the whitespace equals Python's replace-then-strip.
        text.trim_matches(|c| c == '\0' || pyvalue::is_python_space(c))
    } else {
        match core::str::from_utf8(data) {
            Ok(text) => text,
            Err(_) => return Ok(None),
        }
    };
    let mut length = 0;
    for chunk in name.split(|c| strip_nul && c == '\0') {
        let end = length + chunk.len();
        out.get_mut(length..end)
            .ok_or(LxmfError::OutputTooSmall)?
            .copy_from_slice(chunk.as_bytes());
        length = end;
    }
    // UTF-8 pieces split at an ASCII NUL join to UTF-8.
    Ok(core::str::from_utf8(&out[..length]).ok())
}

/// Python `stamp_cost_from_app_data` for delivery announces, as the trusted
/// `announced_stamp_cost` returns it: element 3 when it is an integer or
/// float, else element 1, where a bool counts as 0 or 1.
///
/// `Some(None)` is where the upstream handler records no cost: a nil cost,
/// empty or original-format data, or a list shorter than two. `None` means
/// unknown: undecodable data or a cost that is not a number, where upstream
/// keeps the previous cost. Values are returned unclamped, including negative
/// costs and costs above 100, which [`crate::stamp::StampSearch::new`] refuses.
/// Never interpret `None` as free delivery.
pub fn delivery_stamp_cost(data: &[u8]) -> Option<Option<f64>> {
    let Some(&first) = data.first() else {
        return Some(None);
    };
    if !is_announce_array_marker(first) {
        return Some(None);
    }
    let list = decode_python(data)?;
    let Head::Array { count, .. } = list else {
        return Some(None);
    };
    if count < 2 {
        return Some(None);
    }
    let number = |value| match value {
        Head::Int(n) => Some(n as f64),
        Head::Float(f) => Some(f),
        _ => None,
    };
    if let Some(cost) = pyvalue::index(data, list, 3).and_then(number) {
        return Some(Some(cost));
    }
    match pyvalue::index(data, list, 1)? {
        Head::Nil => Some(None),
        Head::Bool(b) => Some(Some(f64::from(u8::from(b)))),
        other => number(other).map(Some),
    }
}

/// Encode delivery announce app data as upstream `LXMRouter.get_announce_app_data`:
/// `[name, ceil(cost), [SF_COMPRESSION], cost]`, where `cost` is the cost on
/// the 1/256 grid when it lies in `(0, 100)` and nil otherwise. The name is
/// written unchanged as binary. Returns the length written to `out`.
pub fn delivery_announce_app_data(
    display_name: Option<&str>,
    stamp_cost: Option<f64>,
    out: &mut [u8],
) -> Result<usize, LxmfError> {
    let cost_fp = stamp_cost
        .filter(|cost| *cost > 0.0 && *cost < 100.0)
        .and_then(crate::stamp::cost_to_fp);
    let mut writer = SliceWriter { out, len: 0 };
    writer.put(&[0x94])?;
    match display_name {
        None => writer.put(&[0xc0])?,
        Some(name) => {
            let length = name.len();
            if length <= usize::from(u8::MAX) {
                writer.put(&[0xc4, length as u8])?;
            } else {
                let length = u16::try_from(length).map_err(|_| LxmfError::TooLong)?;
                writer.put(&[0xc5])?;
                writer.put(&length.to_be_bytes())?;
            }
            writer.put(name.as_bytes())?;
        }
    }
    match cost_fp {
        // ceil(cost) of a cost on the grid; at most 100, a positive fixint.
        Some(fp) if fp != 0 => writer.put(&[fp.div_ceil(256) as u8])?,
        _ => writer.put(&[0xc0])?,
    }
    // [SF_COMPRESSION]
    writer.put(&[0x91, 0x00])?;
    match cost_fp {
        Some(fp) => {
            writer.put(&[0xcb])?;
            writer.put(&(f64::from(fp) / 256.0).to_be_bytes())?;
        }
        None => writer.put(&[0xc0])?,
    }
    Ok(writer.len)
}

struct SliceWriter<'a> {
    out: &'a mut [u8],
    len: usize,
}

impl SliceWriter<'_> {
    fn put(&mut self, bytes: &[u8]) -> Result<(), LxmfError> {
        let end = self.len + bytes.len();
        self.out
            .get_mut(self.len..end)
            .ok_or(LxmfError::OutputTooSmall)?
            .copy_from_slice(bytes);
        self.len = end;
        Ok(())
    }
}

/// Append a recipient PoW (32 bytes) or ticket (16 bytes) to a freshly packed
/// four-element message. Its signed region and message ID stay unchanged.
/// This checks framing and stamp length, not the signature or proof of work.
pub fn append_recipient_stamp(
    packed: &mut [u8],
    packed_len: usize,
    stamp: &[u8],
) -> Result<usize, LxmfError> {
    if packed_len <= LXMF_PACKED_PREFIX
        || packed_len > packed.len()
        || !matches!(stamp.len(), 16 | 32)
        || packed[LXMF_PACKED_PREFIX] != 0x94
        || skip_value(&packed[..packed_len], LXMF_PACKED_PREFIX, 0)? != packed_len
    {
        return Err(LxmfError::MalformedPayload);
    }
    let end = packed_len
        .checked_add(2 + stamp.len())
        .ok_or(LxmfError::TooLong)?;
    if end > packed.len() {
        return Err(LxmfError::OutputTooSmall);
    }
    packed[packed_len] = 0xc4;
    packed[packed_len + 1] = stamp.len() as u8;
    packed[packed_len + 2..end].copy_from_slice(stamp);
    packed[LXMF_PACKED_PREFIX] = 0x95;
    Ok(end)
}

/// Encrypt a full signed packed message in place, retaining the destination
/// prefix. The caller must supply a correctly signed message and fresh
/// cryptographic `ephemeral_priv`/`iv`; this function does not validate its signature.
/// Returns the entry length BEFORE the PN stamp and its transient ID.
/// Persist/reuse these exact encrypted bytes for retries and resumable PoW.
pub fn encrypt_message(
    buffer: &mut [u8],
    packed_len: usize,
    recipient_public_key: &[u8; 64],
    ratchet: Option<&[u8; 32]>,
    ephemeral_priv: &[u8; 32],
    iv: &[u8; 16],
) -> Result<(usize, [u8; 32]), LxmfError> {
    if packed_len <= LXMF_PACKED_PREFIX || packed_len > buffer.len() {
        return Err(LxmfError::MalformedPayload);
    }
    let recipient_hash = identity_hash(recipient_public_key);
    let destination =
        rns_lite_core::identity::destination_hash_from_name("lxmf.delivery", Some(&recipient_hash));
    if buffer[..16] != destination {
        return Err(LxmfError::DestinationMismatch);
    }
    let plaintext_len = packed_len - 16;
    let total = 16usize
        .checked_add(crypto::ecies_ciphertext_len(plaintext_len)?)
        .ok_or(LxmfError::TooLong)?;
    if total > buffer.len() {
        return Err(LxmfError::OutputTooSmall);
    }
    let start = 16 + crypto::ECIES_PLAINTEXT_OFFSET;
    buffer.copy_within(16..packed_len, start);
    let target: [u8; 32] = ratchet
        .copied()
        .unwrap_or_else(|| recipient_public_key[..32].try_into().unwrap());
    crypto::ecies_encrypt_in_place(
        &target,
        &recipient_hash,
        ephemeral_priv,
        iv,
        &mut buffer[16..total],
        plaintext_len,
    )?;
    Ok((total, Sha256::digest(&buffer[..total]).into()))
}

/// Decrypt one `/get` entry (the node has already stripped its PN stamp),
/// trying retained recipient keys in caller-supplied order, then the base key.
/// Supply newest-first keys and bound the slice length; there is no built-in cap.
/// Pass exactly the encrypted entry, without unused buffer capacity. Restores
/// the full packed message for ordinary LXMF signature validation. Authentication
/// is not sender validation: callers must still use `parse_link` before storing.
/// The returned transient ID refers to the original encrypted entry, for purge
/// only after durable local acceptance.
pub fn decrypt_message(
    buffer: &mut [u8],
    me: &rns_lite_core::identity::LocalIdentity,
    ratchet_privs: &[[u8; 32]],
) -> Result<(usize, [u8; 32], Option<usize>), LxmfError> {
    if buffer.len() < 16 + crypto::ECIES_FIXED_OVERHEAD + 16 {
        return Err(LxmfError::MalformedPayload);
    }
    if buffer[..16] != me.lxmf_delivery_hash() {
        return Err(LxmfError::DestinationMismatch);
    }
    let transient_id = Sha256::digest(&*buffer).into();
    let base: &[u8; 32] = me.private_key()[..32].try_into().unwrap();
    for (index, key) in ratchet_privs
        .iter()
        .chain(core::iter::once(base))
        .enumerate()
    {
        if let Ok(n) = crypto::ecies_decrypt_in_place(key, me.identity_hash(), &mut buffer[16..]) {
            let start = 16 + crypto::ECIES_PLAINTEXT_OFFSET;
            buffer.copy_within(start..start + n, 16);
            return Ok((
                16 + n,
                transient_id,
                (index < ratchet_privs.len()).then_some(index),
            ));
        }
    }
    Err(LxmfError::Crypto)
}

/// Wrap one retained encrypted entry plus its PN stamp for upload. Cost zero
/// still requires the 32-byte PN stamp. `timestamp` is the upload timestamp,
/// independent of the original signed message timestamp. The encrypted entry
/// plus stamp must fit a MessagePack bin16 value and the supplied buffer.
/// This helper does not validate the encrypted entry or stamp's proof of work.
pub fn wrap_upload(
    buffer: &mut [u8],
    encrypted_len: usize,
    stamp: &[u8; 32],
    timestamp: f64,
) -> Result<usize, LxmfError> {
    if !timestamp.is_finite()
        || encrypted_len < 16 + crypto::ECIES_FIXED_OVERHEAD + 16
        || encrypted_len > buffer.len()
    {
        return Err(LxmfError::MalformedPayload);
    }
    let entry_len = encrypted_len.checked_add(32).ok_or(LxmfError::TooLong)?;
    if entry_len > u16::MAX as usize {
        return Err(LxmfError::TooLong);
    }
    let prefix = if entry_len <= u8::MAX as usize {
        13
    } else {
        14
    };
    let total = entry_len.checked_add(prefix).ok_or(LxmfError::TooLong)?;
    if total > buffer.len() {
        return Err(LxmfError::OutputTooSmall);
    }
    buffer.copy_within(0..encrypted_len, prefix);
    buffer[prefix + encrypted_len..total].copy_from_slice(stamp);
    buffer[..2].copy_from_slice(&[0x92, 0xcb]);
    buffer[2..10].copy_from_slice(&timestamp.to_be_bytes());
    buffer[10] = 0x91;
    if prefix == 13 {
        buffer[11..13].copy_from_slice(&[0xc4, entry_len as u8]);
    } else {
        buffer[11] = 0xc5;
        buffer[12..14].copy_from_slice(&(entry_len as u16).to_be_bytes());
    }
    Ok(total)
}
