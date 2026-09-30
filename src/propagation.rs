//! Bounded client codecs adapted from `lxmf-core::{handlers, message}`.
//! Rust owns wire validation; discovery, scheduling and persistence belong to
//! the embedding runtime. No allocation or propagation-node server is provided.

use crate::lxmf::{LXMF_PACKED_PREFIX, LxmfError, field_value, skip_value, value_as_bytes};
use rns_lite_core::{crypto, identity::identity_hash};
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct NodeAnnounce<'a> {
    pub timebase: u64,
    pub enabled: bool,
    /// Decimal kilobytes, as in the trusted LXMF announce codec.
    pub transfer_limit_kb: u64,
    pub sync_limit_kb: u64,
    pub stamp_cost: u8,
    pub stamp_flex: u8,
    pub peering_cost: u8,
    /// Raw advertised name. The UI must sanitize and bound it before display.
    pub name: Option<&'a [u8]>,
}

/// Fully validate one bounded MessagePack array, including unknown extensions.
/// Reject trailing bytes, excessive nesting and impossible length prefixes.
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

fn unsigned(data: &[u8]) -> Option<u64> {
    match *data.first()? {
        b @ 0x00..=0x7f => Some(u64::from(b)),
        0xcc => Some(u64::from(*data.get(1)?)),
        0xcd => Some(u64::from(u16::from_be_bytes(
            data.get(1..3)?.try_into().ok()?,
        ))),
        0xce => Some(u64::from(u32::from_be_bytes(
            data.get(1..5)?.try_into().ok()?,
        ))),
        0xcf => Some(u64::from_be_bytes(data.get(1..9)?.try_into().ok()?)),
        0xd0 => u64::try_from(*data.get(1)? as i8).ok(),
        0xd1 => u64::try_from(i16::from_be_bytes(data.get(1..3)?.try_into().ok()?)).ok(),
        0xd2 => u64::try_from(i32::from_be_bytes(data.get(1..5)?.try_into().ok()?)).ok(),
        0xd3 => u64::try_from(i64::from_be_bytes(data.get(1..9)?.try_into().ok()?)).ok(),
        0xca | 0xcb => {
            let number = if data[0] == 0xca {
                f32::from_be_bytes(data.get(1..5)?.try_into().ok()?) as f64
            } else {
                f64::from_be_bytes(data.get(1..9)?.try_into().ok()?)
            };
            // Avoid Rust's saturating float cast accepting NaN/infinity/overflow.
            (number.is_finite() && (0.0..18446744073709551616.0).contains(&number))
                .then_some(number as u64)
        }
        _ => None,
    }
}

/// Parse signed-announce app data only after Reticulum authentication/binding.
/// Numeric fields follow trusted integer/float truncation. Unlike the desktop
/// parser, negative/overflowed timebases fail closed instead of wrapping.
pub fn parse_node_announce(data: &[u8]) -> Option<NodeAnnounce<'_>> {
    let mut items = array_items(data).ok()?;
    if items.len() < 7 {
        return None;
    }
    items.next()?; // Legacy flag is ignored by the current protocol.
    let timebase = unsigned(items.next()?)?;
    if timebase > i64::MAX as u64 {
        return None;
    }
    let enabled = match items.next()? {
        [0xc2] => false,
        [0xc3] => true,
        _ => return None,
    };
    let transfer_limit_kb = unsigned(items.next()?)?;
    let sync_limit_kb = unsigned(items.next()?)?;
    // Runtime byte-limit conversion must never wrap on a 32-bit MCU.
    transfer_limit_kb.checked_mul(1000)?;
    sync_limit_kb.checked_mul(1000)?;
    let mut costs = array_items(items.next()?).ok()?;
    if costs.len() < 3 {
        return None;
    }
    let stamp_cost = u8::try_from(unsigned(costs.next()?)?).ok()?;
    let stamp_flex = u8::try_from(unsigned(costs.next()?)?).ok()?;
    let peering_cost = u8::try_from(unsigned(costs.next()?)?).ok()?;
    let metadata = items.next()?;
    if !matches!(metadata.first(), Some(0x80..=0x8f | 0xde | 0xdf)) {
        return None;
    }
    let name = field_value(metadata, 1).and_then(value_as_bytes);
    Some(NodeAnnounce {
        timebase,
        enabled,
        transfer_limit_kb,
        sync_limit_kb,
        stamp_cost,
        stamp_flex,
        peering_cost,
        name,
    })
}

/// `None` means unknown/malformed metadata; `Some(None)` is a known nil cost.
/// Never interpret absent or malformed metadata as free delivery.
pub fn delivery_stamp_cost(data: &[u8]) -> Option<Option<u8>> {
    let mut items = array_items(data).ok()?;
    items.next()?;
    let cost = items.next()?;
    if cost == [0xc0] {
        Some(None)
    } else {
        // Delivery costs are integer-only in the trusted delivery parser.
        if matches!(cost.first(), Some(0xca | 0xcb)) {
            return None;
        }
        Some(Some(u8::try_from(unsigned(cost)?).ok()?))
    }
}

/// Append a recipient PoW (32 bytes) or ticket (16 bytes) to a freshly packed
/// four-element message. Its signed region and message ID stay unchanged.
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
/// prefix. Returns the entry length BEFORE the PN stamp and its transient ID.
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
/// trying retained recipient keys newest-first and then the base key. Restores
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
    let base: [u8; 32] = me.private_key()[..32].try_into().unwrap();
    for (index, key) in ratchet_privs
        .iter()
        .chain(core::iter::once(&base))
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
/// independent of the original signed message timestamp.
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
