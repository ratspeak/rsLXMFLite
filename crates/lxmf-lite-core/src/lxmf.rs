//! LXMF opportunistic and packed Link/Resource message codec — `no_std`, no-alloc.
//!
//! Faithful to Python LXMF `LXMessage` and rsLXMF `lxmf-core`. The plaintext LXMF message is:
//!
//! ```text
//! packed   = dest_hash(16) || source_hash(16) || signature(64) || msgpack([ts, title, content, fields])
//! hash     = sha256(dest_hash || source_hash || msgpack_payload_4elem)   (= message_id, 32 bytes)
//! signature= source.sign(dest_hash || source_hash || payload || hash)    (Ed25519)
//! ```
//!
//! `dest_hash`/`source_hash` are the recipient's / sender's `lxmf.delivery` DESTINATION hashes. For
//! OPPORTUNISTIC delivery the leading `dest_hash` is stripped (the RNS packet header carries it) and
//! everything after it is ECIES-encrypted to the recipient identity ([`rns_lite_core::crypto`]). The plaintext
//! `packed` is deterministic given a fixed timestamp, so it is byte-exact provable vs Python LXMF.
//!
//! Builders emit empty `fields`; parsers tolerate non-empty fields and a trailing
//! stamp element (stripped before hashing/verifying, matching `LXMessage.unpack_from_bytes`).
//!
//! Notes / known limitations:
//! - **Canonical msgpack assumption.** The 4-element payload used for the hash is the on-wire payload
//!   with the array marker forced to `0x94` (and the stamp truncated). This is byte-identical to
//!   Python's re-`packb` for any CONFORMANT sender (Python/Sideband/rsDeck all emit canonical
//!   msgpack — fixarray, float64, minimal bin headers), so it produces the same hash for every
//!   message Python accepts. A hypothetical non-canonical sender would be validated by lite (the
//!   signature is genuinely over its bytes) but rejected by Python's canonical re-pack — a leniency
//!   divergence, not a forgery risk. Full canonical re-encoding is deferred.
//! - **Ratchets:** the `*_ratchet` variants decrypt via the retained ring
//!   ([`rns_lite_core::ratchet`]) newest-first with base-key fallback, and encrypt to a peer's
//!   remembered ratchet (upstream posture: always enable, never enforce). A caller that peeks to
//!   recall the source identity should pass the returned key index to
//!   [`parse_opportunistic_ratchet_hint`], avoiding a second full ring scan.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};

use rns_lite_core::crypto::{self, CryptoError};
use rns_lite_core::identity::{
    LXMF_DELIVERY_NAME, LocalIdentity, destination_hash_from_parts, identity_hash, name_hash,
};
use rns_lite_core::wire::sha256;

pub const LXMF_DEST_LENGTH: usize = 16;
pub const LXMF_SIGNATURE_LENGTH: usize = 64;
pub const MESSAGE_ID_LENGTH: usize = 32;

/// `source_hash(16) + signature(64)` prefix the ECIES plaintext carries before the msgpack payload.
const PLAINTEXT_PREFIX: usize = LXMF_DEST_LENGTH + LXMF_SIGNATURE_LENGTH;
/// Largest msgpack payload that still fits a single-frame ECIES packet.
pub const MAX_LXMF_PAYLOAD: usize = crypto::MAX_ECIES_PLAINTEXT - PLAINTEXT_PREFIX;
const PLAINTEXT_MAX: usize = crypto::MAX_ECIES_PLAINTEXT;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LxmfError {
    /// title + content too large to fit a single-frame message.
    TooLong,
    /// Caller's output buffer is too small.
    OutputTooSmall,
    /// Decrypt / HMAC / padding failed.
    Crypto,
    /// msgpack payload is malformed or uses an unsupported element type.
    MalformedPayload,
    /// Ed25519 signature did not validate against the source identity.
    SignatureInvalid,
    /// `source_hash` does not bind to the supplied source public key.
    SourceHashMismatch,
    /// Link/resource-delivered message's leading `dest_hash` is not our delivery destination.
    DestinationMismatch,
}

impl From<CryptoError> for LxmfError {
    fn from(e: CryptoError) -> Self {
        match e {
            // Too large for a single frame -> the caller should fall back to link delivery,
            // mirroring Python's OPPORTUNISTIC -> DIRECT downgrade.
            CryptoError::PlaintextTooLong => LxmfError::TooLong,
            CryptoError::OutputTooSmall => LxmfError::OutputTooSmall,
            CryptoError::AuthenticationFailed => LxmfError::Crypto,
        }
    }
}

// ---- minimal msgpack for [f64, bin, bin, map] ----

/// Append a msgpack bin (`bin8`/`bin16`/`bin32`) of `data` at `pos`; returns the new position.
fn put_bin(out: &mut [u8], pos: usize, data: &[u8]) -> Result<usize, LxmfError> {
    let len = data.len();
    let header = if len <= u8::MAX as usize {
        3
    } else if len <= u16::MAX as usize {
        4
    } else {
        6
    } + len;
    if pos + header > out.len() {
        return Err(LxmfError::OutputTooSmall);
    }
    let mut p = pos;
    if len <= u8::MAX as usize {
        out[p] = 0xc4;
        out[p + 1] = len as u8;
        p += 2;
    } else if len <= u16::MAX as usize {
        out[p] = 0xc5;
        out[p + 1..p + 3].copy_from_slice(&(len as u16).to_be_bytes());
        p += 3;
    } else {
        out[p] = 0xc6;
        out[p + 1..p + 5].copy_from_slice(&(len as u32).to_be_bytes());
        p += 5;
    }
    out[p..p + len].copy_from_slice(data);
    Ok(p + len)
}

/// Pack `[timestamp, title, content, {}]` into `out`; returns the payload length.
fn pack_payload(
    timestamp: f64,
    title: &[u8],
    content: &[u8],
    out: &mut [u8],
) -> Result<usize, LxmfError> {
    if out.len() < 10 {
        return Err(LxmfError::OutputTooSmall);
    }
    out[0] = 0x94; // fixarray, 4 elements
    out[1] = 0xcb; // float64
    out[2..10].copy_from_slice(&timestamp.to_be_bytes());
    let mut p = put_bin(out, 10, title)?;
    p = put_bin(out, p, content)?;
    if p + 1 > out.len() {
        return Err(LxmfError::OutputTooSmall);
    }
    out[p] = 0x80; // fixmap, 0 entries (empty fields)
    Ok(p + 1)
}

/// Skip one msgpack value starting at `pos`; returns the position just past it (ALWAYS
/// `<= data.len()`, or `MalformedPayload`). Total + bounded: every length-prefixed arm uses checked
/// arithmetic and validates the end against `data.len()`, so an attacker-controlled length (incl. a
/// 0xFFFFFFFF bin32 that would wrap a 32-bit `usize` on the ESP32-S3) can never read OOB or return a
/// position past the buffer. Bounded recursion (depth <= 8). Supports the types LXMF payloads/fields
/// use (ints, bin/str, float, nil, bool, arrays, maps).
fn skip_value(data: &[u8], pos: usize, depth: u8) -> Result<usize, LxmfError> {
    if depth > 8 || pos >= data.len() {
        return Err(LxmfError::MalformedPayload);
    }
    let b = data[pos];
    let p = pos + 1; // p <= data.len() (pos < len)
    let len = data.len();
    // Read an `nb`-byte big-endian length prefix at `at` (value may be attacker-controlled).
    let len_at = |at: usize, nb: usize| -> Result<usize, LxmfError> {
        let end = at.checked_add(nb).filter(|&e| e <= len);
        let end = end.ok_or(LxmfError::MalformedPayload)?;
        let mut v = 0usize;
        for &x in &data[at..end] {
            v = v
                .checked_shl(8)
                .and_then(|s| s.checked_add(x as usize))
                .ok_or(LxmfError::MalformedPayload)?;
        }
        Ok(v)
    };
    // `start + n`, checked + bounded to data.len().
    let body = |start: usize, n: usize| -> Result<usize, LxmfError> {
        start
            .checked_add(n)
            .filter(|&e| e <= len)
            .ok_or(LxmfError::MalformedPayload)
    };
    // count*2 for maps, checked.
    let kv = |n: usize| -> Result<usize, LxmfError> {
        n.checked_mul(2).ok_or(LxmfError::MalformedPayload)
    };
    match b {
        0x00..=0x7f | 0xe0..=0xff | 0xc0 | 0xc2 | 0xc3 => Ok(p), // fixint / nil / bool
        0xcc | 0xd0 => body(p, 1),
        0xcd | 0xd1 => body(p, 2),
        0xca | 0xce | 0xd2 => body(p, 4),
        0xcb | 0xcf | 0xd3 => body(p, 8),
        0xc4 | 0xd9 => {
            let n = len_at(p, 1)?;
            body(p + 1, n)
        }
        0xc5 | 0xda => {
            let n = len_at(p, 2)?;
            body(p + 2, n)
        }
        0xc6 | 0xdb => {
            let n = len_at(p, 4)?;
            body(p + 4, n)
        }
        0xa0..=0xbf => body(p, (b & 0x1f) as usize), // fixstr
        0x90..=0x9f => skip_n(data, p, (b & 0x0f) as usize, depth), // fixarray
        0x80..=0x8f => skip_n(data, p, 2 * (b & 0x0f) as usize, depth), // fixmap (k+v)
        0xdc => {
            let n = len_at(p, 2)?;
            skip_n(data, p + 2, n, depth)
        }
        0xdd => {
            let n = len_at(p, 4)?;
            skip_n(data, p + 4, n, depth)
        }
        0xde => {
            let n = len_at(p, 2)?;
            skip_n(data, p + 2, kv(n)?, depth)
        }
        0xdf => {
            let n = len_at(p, 4)?;
            skip_n(data, p + 4, kv(n)?, depth)
        }
        _ => Err(LxmfError::MalformedPayload),
    }
}

fn skip_n(data: &[u8], mut pos: usize, count: usize, depth: u8) -> Result<usize, LxmfError> {
    for _ in 0..count {
        pos = skip_value(data, pos, depth + 1)?;
    }
    Ok(pos)
}

/// A `bin`/`str` value's `(data_slice, end_pos)` at `pos`, or an error. Accepts both bin (`0xc4..6`)
/// and str (`0xa0..bf`/`0xd9..db`) — Python LXMF packs `title`/`content` as bin, but lxmf-core
/// accepts either. Checked + bounded (no 32-bit length overflow / OOB).
fn read_bin(data: &[u8], pos: usize) -> Result<(&[u8], usize), LxmfError> {
    if pos >= data.len() {
        return Err(LxmfError::MalformedPayload);
    }
    let b = data[pos];
    let (hdr, len) = match b {
        0xc4 | 0xd9 if pos + 2 <= data.len() => (2, data[pos + 1] as usize), // bin8 / str8
        0xc5 | 0xda if pos + 3 <= data.len() => {
            (
                3,
                u16::from_be_bytes([data[pos + 1], data[pos + 2]]) as usize,
            ) // bin16 / str16
        }
        0xc6 | 0xdb if pos + 5 <= data.len() => (
            5, // bin32 / str32
            u32::from_be_bytes([data[pos + 1], data[pos + 2], data[pos + 3], data[pos + 4]])
                as usize,
        ),
        0xa0..=0xbf => (1, (b & 0x1f) as usize), // fixstr
        _ => return Err(LxmfError::MalformedPayload),
    };
    let start = pos + hdr;
    let end = start
        .checked_add(len)
        .filter(|&e| e <= data.len())
        .ok_or(LxmfError::MalformedPayload)?;
    Ok((&data[start..end], end))
}

/// A validated, decoded inbound single-frame LXMF message.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct LxmfView<'a> {
    pub message_id: [u8; MESSAGE_ID_LENGTH],
    pub source_hash: [u8; LXMF_DEST_LENGTH],
    pub timestamp: f64,
    pub title: &'a [u8],
    pub content: &'a [u8],
    /// Raw msgpack `fields` element (element 4, stamp excluded), signature-covered like the
    /// rest of the payload. Decoded lazily by callers via [`field_value`]; an empty-fields
    /// message carries the 1-byte fixmap `0x80`.
    pub fields: &'a [u8],
}

/// `dest(16) || source(16) || signature(64)` prefix of the FULL packed message (link/resource form).
pub const LXMF_PACKED_PREFIX: usize = LXMF_DEST_LENGTH + PLAINTEXT_PREFIX;

// ---- build ----

/// Build the DETERMINISTIC plaintext an opportunistic packet carries: `packed[16..]` =
/// `source_hash(16) || signature(64) || msgpack([timestamp, title, content, {}])`. Returns its
/// length and writes the recipient's `lxmf.delivery` dest hash + the 32-byte message id. This is the
/// byte-exact LXMF message (sans the leading dest hash the RNS header carries); proven vs Python LXMF.
#[allow(clippy::too_many_arguments)]
fn build_plaintext(
    source: &LocalIdentity,
    recipient_public_key: &[u8; 64],
    timestamp: f64,
    title: &[u8],
    content: &[u8],
    out_plaintext: &mut [u8],
    out_dest_hash: &mut [u8; LXMF_DEST_LENGTH],
    out_message_id: &mut [u8; MESSAGE_ID_LENGTH],
) -> Result<usize, LxmfError> {
    let nh = name_hash(LXMF_DELIVERY_NAME);
    let recipient_id_hash = identity_hash(recipient_public_key);
    let dest_hash = destination_hash_from_parts(&nh, Some(&recipient_id_hash));
    let source_hash = source.lxmf_delivery_hash();

    // payload = msgpack([timestamp, title, content, {}])
    let mut payload = [0u8; MAX_LXMF_PAYLOAD];
    let plen = pack_payload(timestamp, title, content, &mut payload)?;

    // hashed_part = dest || source || payload -> hash (= message_id); signed_part = hashed_part || hash
    let mut signed = [0u8; LXMF_DEST_LENGTH * 2 + MAX_LXMF_PAYLOAD + MESSAGE_ID_LENGTH];
    signed[..16].copy_from_slice(&dest_hash);
    signed[16..32].copy_from_slice(&source_hash);
    signed[32..32 + plen].copy_from_slice(&payload[..plen]);
    let hashed_len = 32 + plen;
    let hash = sha256(&signed[..hashed_len]);
    signed[hashed_len..hashed_len + 32].copy_from_slice(&hash);
    let signature = source.sign(&signed[..hashed_len + 32]);

    // plaintext = source || signature || payload
    let pt_len = PLAINTEXT_PREFIX + plen;
    if pt_len > out_plaintext.len() || pt_len > PLAINTEXT_MAX {
        return Err(LxmfError::TooLong);
    }
    out_plaintext[..16].copy_from_slice(&source_hash);
    out_plaintext[16..80].copy_from_slice(&signature);
    out_plaintext[80..pt_len].copy_from_slice(&payload[..plen]);

    *out_dest_hash = dest_hash;
    *out_message_id = hash;
    Ok(pt_len)
}

/// Build a single-frame OPPORTUNISTIC LXMF message for `recipient_public_key`, signed by
/// `source` (the local identity). Writes the ECIES-encrypted RNS packet payload into `out` and the
/// recipient's `lxmf.delivery` destination hash (the RNS packet destination) into `out_dest_hash`;
/// `*out_message_id` receives the 32-byte message id. `timestamp` is caller-supplied (no clock);
/// `ephemeral_priv` + `iv` are caller entropy (fix them for deterministic vectors).
#[allow(clippy::too_many_arguments)]
pub fn build_opportunistic(
    source: &LocalIdentity,
    recipient_public_key: &[u8; 64],
    timestamp: f64,
    title: &[u8],
    content: &[u8],
    ephemeral_priv: &[u8; 32],
    iv: &[u8; 16],
    out: &mut [u8],
    out_dest_hash: &mut [u8; LXMF_DEST_LENGTH],
    out_message_id: &mut [u8; MESSAGE_ID_LENGTH],
) -> Result<usize, LxmfError> {
    build_opportunistic_ratchet(
        source,
        recipient_public_key,
        None,
        timestamp,
        title,
        content,
        ephemeral_priv,
        iv,
        out,
        out_dest_hash,
        out_message_id,
    )
}

/// Like [`build_opportunistic`] but ECIES-encrypting to the recipient's announced `ratchet`
/// when one is known (upstream `Destination.encrypt` auto-prefers a remembered ratchet;
/// `None` = base identity key). Plaintext, dest hash, and message id are identical either way —
/// only the ECIES target key changes.
#[allow(clippy::too_many_arguments)]
pub fn build_opportunistic_ratchet(
    source: &LocalIdentity,
    recipient_public_key: &[u8; 64],
    ratchet: Option<&[u8; 32]>,
    timestamp: f64,
    title: &[u8],
    content: &[u8],
    ephemeral_priv: &[u8; 32],
    iv: &[u8; 16],
    out: &mut [u8],
    out_dest_hash: &mut [u8; LXMF_DEST_LENGTH],
    out_message_id: &mut [u8; MESSAGE_ID_LENGTH],
) -> Result<usize, LxmfError> {
    let mut plaintext = [0u8; PLAINTEXT_MAX];
    let pt_len = build_plaintext(
        source,
        recipient_public_key,
        timestamp,
        title,
        content,
        &mut plaintext,
        out_dest_hash,
        out_message_id,
    )?;
    let recipient_id_hash = identity_hash(recipient_public_key);
    let target_x25519: [u8; 32] = match ratchet {
        Some(r) => *r,
        None => recipient_public_key[..32].try_into().unwrap(),
    };
    let n = crypto::ecies_encrypt(
        &plaintext[..pt_len],
        &target_x25519,
        &recipient_id_hash,
        ephemeral_priv,
        iv,
        out,
    )?;
    Ok(n)
}

/// Build the deterministic LXMF plaintext (`packed[16..]`) only — for byte-exact parity vectors.
/// Uses the same internal plaintext builder as the encrypted message path. Returns the
/// plaintext length and fills the destination hash and message ID.
#[allow(clippy::too_many_arguments)]
pub fn build_plaintext_for_parity(
    source: &LocalIdentity,
    recipient_public_key: &[u8; 64],
    timestamp: f64,
    title: &[u8],
    content: &[u8],
    out_plaintext: &mut [u8],
    out_dest_hash: &mut [u8; LXMF_DEST_LENGTH],
    out_message_id: &mut [u8; MESSAGE_ID_LENGTH],
) -> Result<usize, LxmfError> {
    build_plaintext(
        source,
        recipient_public_key,
        timestamp,
        title,
        content,
        out_plaintext,
        out_dest_hash,
        out_message_id,
    )
}

// ---- parse ----

/// Decrypt + validate an inbound single-frame OPPORTUNISTIC LXMF packet payload addressed to
/// `me` (the local identity), signed by the identity whose 64-byte public key is `source_public_key`
/// (known from the source's announce). On success returns the decoded [`LxmfView`]. `scratch` holds
/// the decrypted plaintext (use [`crypto::MAX_ECIES_PLAINTEXT`] bytes) and must outlive the view.
pub fn parse_opportunistic<'a>(
    me: &LocalIdentity,
    packet_payload: &[u8],
    source_public_key: &[u8; 64],
    scratch: &'a mut [u8],
) -> Result<LxmfView<'a>, LxmfError> {
    if scratch.len() < crypto::MAX_ECIES_PLAINTEXT {
        return Err(LxmfError::OutputTooSmall);
    }
    let my_x25519: [u8; 32] = me.private_key()[..32].try_into().unwrap();
    let pt_len = crypto::ecies_decrypt(packet_payload, &my_x25519, me.identity_hash(), scratch)?;
    parse_decrypted(me, source_public_key, scratch, pt_len)
}

/// Like [`parse_opportunistic`] but trying `ratchet_privs` (our retained ring keys, newest first)
/// before the base identity key (upstream `Identity.decrypt` with ratchets; the base-key fallback
/// is never disabled). Also returns which ring index decrypted the payload (`None` = base key).
pub fn parse_opportunistic_ratchet<'a>(
    me: &LocalIdentity,
    ratchet_privs: &[[u8; 32]],
    packet_payload: &[u8],
    source_public_key: &[u8; 64],
    scratch: &'a mut [u8],
) -> Result<(LxmfView<'a>, Option<usize>), LxmfError> {
    if scratch.len() < crypto::MAX_ECIES_PLAINTEXT {
        return Err(LxmfError::OutputTooSmall);
    }
    let my_x25519: [u8; 32] = me.private_key()[..32].try_into().unwrap();
    let (pt_len, which) = crypto::ecies_decrypt_with_ratchets(
        packet_payload,
        ratchet_privs,
        &my_x25519,
        me.identity_hash(),
        scratch,
    )?;
    Ok((
        parse_decrypted(me, source_public_key, scratch, pt_len)?,
        which,
    ))
}

/// Validate an opportunistic payload using exactly the key selected by an
/// earlier [`peek_source_opportunistic_ratchet`] call.
///
/// `ratchet_index = Some(i)` tries only retained key `i`; `None` tries only the
/// base identity key. An out-of-range or incorrect hint fails closed and never
/// falls back to a ring scan. This keeps the normal source-recall pipeline to at
/// most one 64-key scan while retaining the original scanning API for callers
/// that do not peek first.
pub fn parse_opportunistic_ratchet_hint<'a>(
    me: &LocalIdentity,
    ratchet_privs: &[[u8; 32]],
    ratchet_index: Option<usize>,
    packet_payload: &[u8],
    source_public_key: &[u8; 64],
    scratch: &'a mut [u8],
) -> Result<LxmfView<'a>, LxmfError> {
    if scratch.len() < crypto::MAX_ECIES_PLAINTEXT {
        return Err(LxmfError::OutputTooSmall);
    }
    let my_x25519: [u8; 32] = me.private_key()[..32].try_into().unwrap();
    let pt_len = crypto::ecies_decrypt_with_ratchet_hint(
        packet_payload,
        ratchet_privs,
        &my_x25519,
        me.identity_hash(),
        ratchet_index,
        scratch,
    )?;
    parse_decrypted(me, source_public_key, scratch, pt_len)
}

fn parse_decrypted<'a>(
    me: &LocalIdentity,
    source_public_key: &[u8; 64],
    scratch: &'a [u8],
    pt_len: usize,
) -> Result<LxmfView<'a>, LxmfError> {
    let plaintext = &scratch[..pt_len];

    // plaintext = source_hash(16) || signature(64) || payload
    if plaintext.len() < PLAINTEXT_PREFIX + 1 {
        return Err(LxmfError::MalformedPayload);
    }
    let mut source_hash = [0u8; LXMF_DEST_LENGTH];
    source_hash.copy_from_slice(&plaintext[..16]);
    let mut signature = [0u8; LXMF_SIGNATURE_LENGTH];
    signature.copy_from_slice(&plaintext[16..80]);
    let payload = &plaintext[80..];

    // Bind source_hash to the supplied source public key (its lxmf.delivery dest).
    let nh = name_hash(LXMF_DELIVERY_NAME);
    let src_id_hash = identity_hash(source_public_key);
    if destination_hash_from_parts(&nh, Some(&src_id_hash)) != source_hash {
        return Err(LxmfError::SourceHashMismatch);
    }

    // Decode the array: [timestamp, title, content, fields, (stamp)?]. Strip the stamp for hashing.
    if payload.is_empty() || payload[0] & 0xf0 != 0x90 {
        return Err(LxmfError::MalformedPayload);
    }
    let n_elems = (payload[0] & 0x0f) as usize;
    if n_elems < 4 {
        return Err(LxmfError::MalformedPayload);
    }
    if payload.len() < 10 || payload[1] != 0xcb {
        return Err(LxmfError::MalformedPayload);
    }
    let timestamp = f64::from_be_bytes(payload[2..10].try_into().unwrap());
    let (title, after_title) = read_bin(payload, 10)?;
    let (content, after_content) = read_bin(payload, after_title)?;
    let after_fields = skip_value(payload, after_content, 0)?; // element 4 (fields)

    // The 4-element payload used for hashing (Python strips the stamp and re-packs as 4 elements):
    // bytes [0..after_fields] with the array marker forced to 0x94.
    let mut payload4 = [0u8; MAX_LXMF_PAYLOAD];
    let p4_len = after_fields;
    if p4_len > MAX_LXMF_PAYLOAD {
        return Err(LxmfError::MalformedPayload);
    }
    payload4[..p4_len].copy_from_slice(&payload[..p4_len]);
    payload4[0] = 0x94;

    // hashed_part = my_dest || source || payload4 ; hash ; signed_part = hashed_part || hash
    let my_dest = me.lxmf_delivery_hash();
    let mut signed = [0u8; LXMF_DEST_LENGTH * 2 + MAX_LXMF_PAYLOAD + MESSAGE_ID_LENGTH];
    signed[..16].copy_from_slice(&my_dest);
    signed[16..32].copy_from_slice(&source_hash);
    signed[32..32 + p4_len].copy_from_slice(&payload4[..p4_len]);
    let hashed_len = 32 + p4_len;
    let hash = sha256(&signed[..hashed_len]);
    signed[hashed_len..hashed_len + 32].copy_from_slice(&hash);

    // Verify the Ed25519 signature with the source identity's ed25519 public key.
    let mut ed_pub = [0u8; 32];
    ed_pub.copy_from_slice(&source_public_key[32..]);
    let key = VerifyingKey::from_bytes(&ed_pub).map_err(|_| LxmfError::SignatureInvalid)?;
    let sig = Signature::from_bytes(&signature);
    key.verify(&signed[..hashed_len + 32], &sig)
        .map_err(|_| LxmfError::SignatureInvalid)?;

    Ok(LxmfView {
        message_id: hash,
        source_hash,
        timestamp,
        title,
        content,
        fields: &payload[after_content..after_fields],
    })
}

/// Decrypt-only PEEK of an inbound opportunistic payload's embedded `source_hash` (the first 16
/// plaintext bytes), so the caller can recall the source public key BEFORE running the full
/// validating [`parse_opportunistic`] (Python `Identity.recall` flow — the source is unknown at
/// arrival). Fail-closed: reveals only the 16-byte hash; nothing is validated or stored here.
/// `scratch` holds the decrypted plaintext ([`crypto::MAX_ECIES_PLAINTEXT`] bytes).
pub fn peek_source_opportunistic(
    me: &LocalIdentity,
    packet_payload: &[u8],
    scratch: &mut [u8],
) -> Result<[u8; LXMF_DEST_LENGTH], LxmfError> {
    peek_source_opportunistic_ratchet(me, &[], packet_payload, scratch).map(|(hash, _)| hash)
}

/// Ratchet-aware [`peek_source_opportunistic`]: tries `ratchet_privs` newest-first before the
/// base key, so ratcheted inbound can be peeked for source recall too. Returns the source hash
/// and which ring index decrypted (`None` = base key).
pub fn peek_source_opportunistic_ratchet(
    me: &LocalIdentity,
    ratchet_privs: &[[u8; 32]],
    packet_payload: &[u8],
    scratch: &mut [u8],
) -> Result<([u8; LXMF_DEST_LENGTH], Option<usize>), LxmfError> {
    if scratch.len() < crypto::MAX_ECIES_PLAINTEXT {
        return Err(LxmfError::OutputTooSmall);
    }
    let my_x25519: [u8; 32] = me.private_key()[..32].try_into().unwrap();
    let (pt_len, which) = crypto::ecies_decrypt_with_ratchets(
        packet_payload,
        ratchet_privs,
        &my_x25519,
        me.identity_hash(),
        scratch,
    )?;
    if pt_len < PLAINTEXT_PREFIX + 1 {
        return Err(LxmfError::MalformedPayload);
    }
    let mut source_hash = [0u8; LXMF_DEST_LENGTH];
    source_hash.copy_from_slice(&scratch[..16]);
    Ok((source_hash, which))
}

/// Build the FULL packed LXMF message — `dest(16) || source(16) || signature(64) || msgpack
/// payload` — for LINK/RESOURCE delivery (Python `DIRECT`: the sender transmits the full packed
/// bytes in a single link packet or as a resource; no ECIES wrap, the link session crypto replaces
/// it). Byte-identical to Python `LXMessage.pack()`. `scratch` is working memory for the
/// hashed/signed regions and must be at least `64 + payload` bytes (size it to `out.len()`);
/// payload capacity is bounded by the smaller of `out.len() - 96` and `scratch.len() - 64`.
#[allow(clippy::too_many_arguments)]
pub fn build_link(
    source: &LocalIdentity,
    recipient_public_key: &[u8; 64],
    timestamp: f64,
    title: &[u8],
    content: &[u8],
    out: &mut [u8],
    scratch: &mut [u8],
    out_dest_hash: &mut [u8; LXMF_DEST_LENGTH],
    out_message_id: &mut [u8; MESSAGE_ID_LENGTH],
) -> Result<usize, LxmfError> {
    if scratch.len() < 64 + 11 || out.len() < LXMF_PACKED_PREFIX + 11 {
        return Err(LxmfError::OutputTooSmall);
    }
    let nh = name_hash(LXMF_DELIVERY_NAME);
    let recipient_id_hash = identity_hash(recipient_public_key);
    let dest_hash = destination_hash_from_parts(&nh, Some(&recipient_id_hash));
    let source_hash = source.lxmf_delivery_hash();

    // scratch = dest(16) || source(16) || payload(plen) || hash(32); payload packed in place.
    let scratch_len = scratch.len();
    let plen = pack_payload(
        timestamp,
        title,
        content,
        &mut scratch[32..scratch_len - 32],
    )
    .map_err(|_| LxmfError::TooLong)?;
    if out.len() < LXMF_PACKED_PREFIX + plen {
        return Err(LxmfError::TooLong);
    }
    scratch[..16].copy_from_slice(&dest_hash);
    scratch[16..32].copy_from_slice(&source_hash);
    let hash = sha256(&scratch[..32 + plen]);
    scratch[32 + plen..64 + plen].copy_from_slice(&hash);
    let signature = source.sign(&scratch[..64 + plen]);

    out[..16].copy_from_slice(&dest_hash);
    out[16..32].copy_from_slice(&source_hash);
    out[32..96].copy_from_slice(&signature);
    out[LXMF_PACKED_PREFIX..LXMF_PACKED_PREFIX + plen].copy_from_slice(&scratch[32..32 + plen]);

    *out_dest_hash = dest_hash;
    *out_message_id = hash;
    Ok(LXMF_PACKED_PREFIX + plen)
}

/// Validate a FULL packed LXMF message received over an established link (single link packet or
/// assembled resource; the caller has already link-decrypted / reassembled it): `dest(16) ||
/// source(16) || signature(64) || msgpack payload`. `me` must be the delivery destination
/// (`DestinationMismatch` otherwise); `source_public_key` is recalled by the caller from
/// `data[16..32]`. Same stamp-strip + signature semantics as [`parse_opportunistic`]
/// (Python `LXMessage.unpack_from_bytes`). `scratch` is working memory for the hashed/signed
/// region and must be at least `64 + payload` bytes (size it to `data.len()`).
pub fn parse_link<'a>(
    me: &LocalIdentity,
    data: &'a [u8],
    source_public_key: &[u8; 64],
    scratch: &mut [u8],
) -> Result<LxmfView<'a>, LxmfError> {
    if data.len() < LXMF_PACKED_PREFIX + 1 {
        return Err(LxmfError::MalformedPayload);
    }
    let mut dest_hash = [0u8; LXMF_DEST_LENGTH];
    dest_hash.copy_from_slice(&data[..16]);
    if dest_hash != me.lxmf_delivery_hash() {
        return Err(LxmfError::DestinationMismatch);
    }
    let mut source_hash = [0u8; LXMF_DEST_LENGTH];
    source_hash.copy_from_slice(&data[16..32]);
    let mut signature = [0u8; LXMF_SIGNATURE_LENGTH];
    signature.copy_from_slice(&data[32..96]);
    let payload = &data[96..];

    // Bind source_hash to the supplied source public key (its lxmf.delivery dest).
    let nh = name_hash(LXMF_DELIVERY_NAME);
    let src_id_hash = identity_hash(source_public_key);
    if destination_hash_from_parts(&nh, Some(&src_id_hash)) != source_hash {
        return Err(LxmfError::SourceHashMismatch);
    }

    // Decode [timestamp, title, content, fields, (stamp)?]; strip the stamp for hashing.
    if payload.is_empty() || payload[0] & 0xf0 != 0x90 {
        return Err(LxmfError::MalformedPayload);
    }
    if (payload[0] & 0x0f) < 4 {
        return Err(LxmfError::MalformedPayload);
    }
    if payload.len() < 10 || payload[1] != 0xcb {
        return Err(LxmfError::MalformedPayload);
    }
    let timestamp = f64::from_be_bytes(payload[2..10].try_into().unwrap());
    let (title, after_title) = read_bin(payload, 10)?;
    let (content, after_content) = read_bin(payload, after_title)?;
    let after_fields = skip_value(payload, after_content, 0)?; // element 4 (fields)

    // scratch = dest || source || payload4(marker forced 0x94) || hash; verify over it.
    let p4_len = after_fields;
    if scratch.len() < 64 + p4_len {
        return Err(LxmfError::OutputTooSmall);
    }
    scratch[..16].copy_from_slice(&dest_hash);
    scratch[16..32].copy_from_slice(&source_hash);
    scratch[32..32 + p4_len].copy_from_slice(&payload[..p4_len]);
    scratch[32] = 0x94;
    let hash = sha256(&scratch[..32 + p4_len]);
    scratch[32 + p4_len..64 + p4_len].copy_from_slice(&hash);

    let mut ed_pub = [0u8; 32];
    ed_pub.copy_from_slice(&source_public_key[32..]);
    let key = VerifyingKey::from_bytes(&ed_pub).map_err(|_| LxmfError::SignatureInvalid)?;
    let sig = Signature::from_bytes(&signature);
    key.verify(&scratch[..64 + p4_len], &sig)
        .map_err(|_| LxmfError::SignatureInvalid)?;

    Ok(LxmfView {
        message_id: hash,
        source_hash,
        timestamp,
        title,
        content,
        fields: &payload[after_content..after_fields],
    })
}

// ---- fields helpers (lazy decode of the raw `fields` element) ----

/// Raw msgpack value slice for integer key `key` in a fields map (`fields` = the raw
/// [`LxmfView::fields`] element). `None` if `fields` is not a map, the key is absent, or the
/// encoding is malformed. Non-integer keys are skipped. The LAST occurrence of a duplicated
/// key wins (Python dict-decode semantics). Bounded like the internal `skip_value`; each iteration
/// consumes at least one byte, so the loop is O(len).
pub fn field_value(fields: &[u8], key: u8) -> Option<&[u8]> {
    let (mut pos, count) = read_map_header(fields)?;
    let mut found = None;
    for _ in 0..count {
        let (k, after_key) = match read_int_key(fields, pos) {
            Some((k, after)) => (Some(k), after),
            None => (None, skip_value(fields, pos, 0).ok()?),
        };
        let after_value = skip_value(fields, after_key, 0).ok()?;
        if k == Some(key) {
            found = Some(&fields[after_key..after_value]);
        }
        pos = after_value;
    }
    found
}

/// The `bin`/`str` payload of a single msgpack value, if it is one.
pub fn value_as_bytes(value: &[u8]) -> Option<&[u8]> {
    read_bin(value, 0).ok().map(|(b, _)| b)
}

/// Raw msgpack value slice for `bin`/`str` key `key` in a msgpack map (e.g. a fields value
/// that is itself an encoded map). Same bounds/tolerance as [`field_value`].
pub fn map_bytes_value<'a>(map: &'a [u8], key: &[u8]) -> Option<&'a [u8]> {
    let (mut pos, count) = read_map_header(map)?;
    for _ in 0..count {
        match read_bin(map, pos) {
            Ok((k, after_key)) => {
                let after_value = skip_value(map, after_key, 0).ok()?;
                if k == key {
                    return Some(&map[after_key..after_value]);
                }
                pos = after_value;
            }
            Err(_) => {
                let after_key = skip_value(map, pos, 0).ok()?;
                pos = skip_value(map, after_key, 0).ok()?;
            }
        }
    }
    None
}

/// `(first_entry_pos, entry_count)` of a msgpack map at the start of `data`.
fn read_map_header(data: &[u8]) -> Option<(usize, usize)> {
    let b = *data.first()?;
    match b {
        0x80..=0x8f => Some((1, (b & 0x0f) as usize)),
        0xde if data.len() >= 3 => Some((3, u16::from_be_bytes([data[1], data[2]]) as usize)),
        0xdf if data.len() >= 5 => Some((
            5,
            u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize,
        )),
        _ => None,
    }
}

/// A u8-range msgpack integer at `pos` — every encoding a conformant packer can produce
/// for an LXMF field key: positive fixint, uint8, non-negative int8, and 16-bit forms
/// whose value fits u8. Negative values are never valid field keys (deliberately unlike
/// the micro C++ filter's historical raw `>= 0xE0` branch, which misread msgpack negative
/// fixints as u8 keys).
fn read_int_key(data: &[u8], pos: usize) -> Option<(u8, usize)> {
    let b = *data.get(pos)?;
    match b {
        0x00..=0x7f => Some((b, pos + 1)),
        0xcc => data.get(pos + 1).map(|&v| (v, pos + 2)),
        0xd0 => data
            .get(pos + 1)
            .filter(|&&v| v <= 0x7f)
            .map(|&v| (v, pos + 2)),
        0xcd | 0xd1 => {
            let hi = *data.get(pos + 1)?;
            let lo = *data.get(pos + 2)?;
            (hi == 0).then_some((lo, pos + 3))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn incrementing_key() -> [u8; 64] {
        let mut k = [0u8; 64];
        for (i, b) in k.iter_mut().enumerate() {
            *b = i as u8;
        }
        k
    }

    #[test]
    fn field_value_decodes_all_u8_key_encodings_last_wins() {
        // {0x40(fixint): 1, 0xFB(uint8): "a", 0xFB(int16, 0xd1 00 fb): "b"} — last wins.
        let fields: &[u8] = &[
            0x83, 0x40, 0x01, 0xcc, 0xfb, 0xa1, b'a', 0xd1, 0x00, 0xfb, 0xa1, b'b',
        ];
        assert_eq!(field_value(fields, 0x40), Some(&[0x01u8][..]));
        assert_eq!(
            field_value(fields, 0xfb).and_then(value_as_bytes),
            Some(&b"b"[..])
        );
        // int8 (0xd0) non-negative decodes; negative int8 and negative fixint keys never match.
        let d0: &[u8] = &[0x81, 0xd0, 0x30, 0xc0];
        assert_eq!(field_value(d0, 0x30), Some(&[0xc0u8][..]));
        let neg: &[u8] = &[0x82, 0xd0, 0xfb, 0xc0, 0xe5, 0xc0]; // int8 -5 and fixint -27 keys
        assert_eq!(field_value(neg, 0xfb), None);
        assert_eq!(field_value(neg, 0xe5), None);
        // uint16 above u8 range never matches; non-map input is None.
        let big: &[u8] = &[0x81, 0xcd, 0x01, 0x00, 0xc0];
        assert_eq!(field_value(big, 0x00), None);
        assert_eq!(field_value(&[0xc0], 0x40), None);
    }

    #[test]
    fn opportunistic_roundtrip() {
        // Two distinct identities: source and recipient.
        let source = LocalIdentity::from_private_key(&incrementing_key());
        let recip_key = {
            let mut k = [0u8; 64];
            for (i, b) in k.iter_mut().enumerate() {
                *b = (i as u8).wrapping_add(0x40);
            }
            k
        };
        let recipient = LocalIdentity::from_private_key(&recip_key);

        let mut out = [0u8; 600];
        let mut dest = [0u8; 16];
        let mut mid = [0u8; 32];
        let n = build_opportunistic(
            &source,
            recipient.public_key(),
            1234567890.5,
            b"Hi",
            b"hello world",
            &[0x33; 32],
            &[0x44; 16],
            &mut out,
            &mut dest,
            &mut mid,
        )
        .unwrap();

        // dest is the recipient's lxmf.delivery destination.
        assert_eq!(dest, recipient.lxmf_delivery_hash());

        let mut scratch = [0u8; crypto::MAX_ECIES_PLAINTEXT];
        let view =
            parse_opportunistic(&recipient, &out[..n], source.public_key(), &mut scratch).unwrap();
        assert_eq!(view.message_id, mid);
        assert_eq!(view.timestamp, 1234567890.5);
        assert_eq!(view.title, b"Hi");
        assert_eq!(view.content, b"hello world");
        assert_eq!(view.source_hash, source.lxmf_delivery_hash());
    }

    // Pinned Python RNS/LXMF interoperability vectors, revalidated against upstream
    // RNS 1.4.2 / LXMF 1.0.1; bytes are unchanged since the 1.2.5/0.9.8 originals.
    extern crate std;
    use std::vec::Vec;
    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }
    const SOURCE_PRV: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";
    const RECIPIENT_PRV: &str = "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f";
    const DEST_HASH: &str = "cf0b2a4a8d2a0b6978b71290da7cc80e";
    const MESSAGE_ID: &str = "dceab683f560aad56d128fc7051ceb41ef4cd935430df0eb089a4ea0095be1a4";
    const PLAINTEXT16: &str = "fae321c442e3c9bdcd7a3e79d850e03c886ce9da0df0d8088d5abaf4aee20f88daed4b5f0795015556e650bcfc215045ab73129f6e1e5a9ae45cf7efe6aed1a2ede7fbc089d977c5ea47fff3da2c6e0894cb41d26580b4a00000c4024869c40b68656c6c6f20776f726c6480";
    const ECIES_DET: &str = "7b0d47d93427f8311160781c7c733fd89f88970aef490d8aa0ee19a4cb8a1b14444444444444444444444444444444440d7c1dee5eb3705ffb1071c5a2793fbd560c3b182efc727d9941535dcbc9b12df1985a5fb1084d7efc4e2d3cf97ff76dee026669294ec05d51bf843cd4c3b998b2e66be6b571f6a02cf5fb88480a474b389ba269ae44cf74ac6f699680c83c208d2d3be4fcf5ba8de6b2b18b20a1c90bc0324fa01763f8468836445c617b9ab8b87bda7cf9e4cc0760763516a0ef8f69";
    const PYTHON_BLOB: &str = "d762902286b2608284e235803a959fb9657e4c1c308a6ced5ec60fb28c99ed6d4a99af0f98a241ac49f47b42c70a7aa64bfe86f5f607888314ab81952f37499f69a03bd0764494145eb5301582335f2aa2e679139d8c9aa96b5f0d674b401c0355e2e399d65eee5f9e92bd360d5c3a44cbeb3d822c4c384392ee25121b0cf8f49867f4f9f24a7a0292c35d0a8ba213ee80e3f81ae94be5601ab9c90703b095c2e9871d5c749f443d5c5750d4331a2fe30fb0a94b761c288f7921c7972dde8f4c";

    fn id64(hex: &str) -> [u8; 64] {
        let v = unhex(hex);
        let mut k = [0u8; 64];
        k.copy_from_slice(&v);
        k
    }

    #[test]
    fn build_plaintext_byte_exact_vs_python_lxmf() {
        let source = LocalIdentity::from_private_key(&id64(SOURCE_PRV));
        let recipient = LocalIdentity::from_private_key(&id64(RECIPIENT_PRV));
        let mut pt = [0u8; crypto::MAX_ECIES_PLAINTEXT];
        let mut dest = [0u8; 16];
        let mut mid = [0u8; 32];
        let n = build_plaintext_for_parity(
            &source,
            recipient.public_key(),
            1234567890.5,
            b"Hi",
            b"hello world",
            &mut pt,
            &mut dest,
            &mut mid,
        )
        .unwrap();
        assert_eq!(pt[..n], unhex(PLAINTEXT16)[..]);
        assert_eq!(mid, unhex(MESSAGE_ID)[..]);
        assert_eq!(dest, unhex(DEST_HASH)[..]);
    }

    #[test]
    fn build_opportunistic_byte_exact_ecies_vs_python() {
        let source = LocalIdentity::from_private_key(&id64(SOURCE_PRV));
        let recipient = LocalIdentity::from_private_key(&id64(RECIPIENT_PRV));
        let mut out = [0u8; 600];
        let mut dest = [0u8; 16];
        let mut mid = [0u8; 32];
        let n = build_opportunistic(
            &source,
            recipient.public_key(),
            1234567890.5,
            b"Hi",
            b"hello world",
            &[0x33; 32],
            &[0x44; 16],
            &mut out,
            &mut dest,
            &mut mid,
        )
        .unwrap();
        // Byte-exact with the manually-derived (fixed ephemeral+IV) ECIES that RNS 1.4.2 decrypts.
        assert_eq!(out[..n], unhex(ECIES_DET)[..]);
    }

    #[test]
    fn parse_decrypts_and_validates_python_encrypted_message() {
        // The strong interop direction: a message ENCRYPTED by Python RNS (random ephemeral) is
        // decrypted + signature-validated by the lite parser.
        let source = LocalIdentity::from_private_key(&id64(SOURCE_PRV));
        let recipient = LocalIdentity::from_private_key(&id64(RECIPIENT_PRV));
        let blob = unhex(PYTHON_BLOB);
        let mut scratch = [0u8; crypto::MAX_ECIES_PLAINTEXT];
        let view =
            parse_opportunistic(&recipient, &blob, source.public_key(), &mut scratch).unwrap();
        assert_eq!(view.title, b"Hi");
        assert_eq!(view.content, b"hello world");
        assert_eq!(view.message_id, unhex(MESSAGE_ID)[..]);
        assert_eq!(view.source_hash, source.lxmf_delivery_hash());
    }

    #[test]
    fn wrong_source_key_fails_validation() {
        let source = LocalIdentity::from_private_key(&incrementing_key());
        let recip_key = [0x77u8; 64];
        let recipient = LocalIdentity::from_private_key(&recip_key);
        let mut out = [0u8; 600];
        let mut dest = [0u8; 16];
        let mut mid = [0u8; 32];
        let n = build_opportunistic(
            &source,
            recipient.public_key(),
            1.0,
            b"t",
            b"c",
            &[0x01; 32],
            &[0x02; 16],
            &mut out,
            &mut dest,
            &mut mid,
        )
        .unwrap();
        // Parse with a DIFFERENT source key -> source-hash binding fails.
        let wrong = LocalIdentity::from_private_key(&[0x09u8; 64]);
        let mut scratch = [0u8; crypto::MAX_ECIES_PLAINTEXT];
        assert_eq!(
            parse_opportunistic(&recipient, &out[..n], wrong.public_key(), &mut scratch),
            Err(LxmfError::SourceHashMismatch)
        );
    }

    #[test]
    fn single_frame_blob_never_exceeds_mdu_and_rejects_oversize() {
        let source = LocalIdentity::from_private_key(&incrementing_key());
        let recipient = LocalIdentity::from_private_key(&[0x55u8; 64]);
        let mut out = [0u8; 600];
        let mut dest = [0u8; 16];
        let mut mid = [0u8; 32];
        // A large-but-valid single-frame message: the emitted blob must fit the MDU so the packet
        // is actually transmittable (and relayable as Header2).
        let content = [0x5au8; 240];
        let n = build_opportunistic(
            &source,
            recipient.public_key(),
            1.0,
            b"subj",
            &content,
            &[1; 32],
            &[2; 16],
            &mut out,
            &mut dest,
            &mut mid,
        )
        .unwrap();
        assert!(n <= rns_lite_core::constants::MDU, "blob {n} exceeds MDU");
        // An over-large message must be rejected (caller falls back to link delivery).
        let too_big = [0x5au8; 400];
        assert!(
            build_opportunistic(
                &source,
                recipient.public_key(),
                1.0,
                b"",
                &too_big,
                &[1; 32],
                &[2; 16],
                &mut out,
                &mut dest,
                &mut mid,
            )
            .is_err()
        );
    }

    #[test]
    fn link_packed_roundtrip_and_peek() {
        let source = LocalIdentity::from_private_key(&incrementing_key());
        let recip_key = {
            let mut k = [0u8; 64];
            for (i, b) in k.iter_mut().enumerate() {
                *b = (i as u8).wrapping_add(0x40);
            }
            k
        };
        let recipient = LocalIdentity::from_private_key(&recip_key);

        // Content larger than the single-frame budget: only deliverable link/resource.
        let content = [0x5au8; 1200];
        let mut out = [0u8; 2048];
        let mut scratch = [0u8; 2048];
        let mut dest = [0u8; 16];
        let mut mid = [0u8; 32];
        let n = build_link(
            &source,
            recipient.public_key(),
            1234567890.5,
            b"Hi",
            &content,
            &mut out,
            &mut scratch,
            &mut dest,
            &mut mid,
        )
        .unwrap();
        assert_eq!(dest, recipient.lxmf_delivery_hash());
        assert_eq!(&out[..16], &dest);

        let view = parse_link(&recipient, &out[..n], source.public_key(), &mut scratch).unwrap();
        assert_eq!(view.message_id, mid);
        assert_eq!(view.title, b"Hi");
        assert_eq!(view.content, &content[..]);
        assert_eq!(view.source_hash, source.lxmf_delivery_hash());

        // Wrong recipient -> DestinationMismatch (never validated).
        let wrong = LocalIdentity::from_private_key(&[0x09u8; 64]);
        assert_eq!(
            parse_link(&wrong, &out[..n], source.public_key(), &mut scratch),
            Err(LxmfError::DestinationMismatch)
        );
        // Tampered signature -> SignatureInvalid.
        let mut bad = [0u8; 2048];
        bad[..n].copy_from_slice(&out[..n]);
        bad[40] ^= 0x01;
        assert_eq!(
            parse_link(&recipient, &bad[..n], source.public_key(), &mut scratch),
            Err(LxmfError::SignatureInvalid)
        );

        // Opportunistic peek recovers the embedded source hash decrypt-only.
        let mut blob = [0u8; 600];
        let mut mid2 = [0u8; 32];
        let bn = build_opportunistic(
            &source,
            recipient.public_key(),
            1.0,
            b"t",
            b"c",
            &[0x21; 32],
            &[0x22; 16],
            &mut blob,
            &mut dest,
            &mut mid2,
        )
        .unwrap();
        let mut pscratch = [0u8; crypto::MAX_ECIES_PLAINTEXT];
        let src = peek_source_opportunistic(&recipient, &blob[..bn], &mut pscratch).unwrap();
        assert_eq!(src, source.lxmf_delivery_hash());
    }

    #[test]
    fn link_packed_matches_opportunistic_plaintext_with_dest_prefix() {
        // build_link == dest_hash || build_plaintext (same hash/signature path) for
        // single-frame-sized messages, pinning the two builders to one wire format.
        let source = LocalIdentity::from_private_key(&id64(SOURCE_PRV));
        let recipient = LocalIdentity::from_private_key(&id64(RECIPIENT_PRV));
        let mut pt = [0u8; crypto::MAX_ECIES_PLAINTEXT];
        let mut dest_a = [0u8; 16];
        let mut mid_a = [0u8; 32];
        let n_pt = build_plaintext_for_parity(
            &source,
            recipient.public_key(),
            1234567890.5,
            b"Hi",
            b"hello world",
            &mut pt,
            &mut dest_a,
            &mut mid_a,
        )
        .unwrap();

        let mut out = [0u8; 600];
        let mut scratch = [0u8; 600];
        let mut dest_b = [0u8; 16];
        let mut mid_b = [0u8; 32];
        let n = build_link(
            &source,
            recipient.public_key(),
            1234567890.5,
            b"Hi",
            b"hello world",
            &mut out,
            &mut scratch,
            &mut dest_b,
            &mut mid_b,
        )
        .unwrap();
        assert_eq!(n, 16 + n_pt);
        assert_eq!(&out[..16], &dest_a);
        assert_eq!(&out[16..n], &pt[..n_pt]);
        assert_eq!(mid_a, mid_b);
        assert_eq!(dest_a, dest_b);
        assert_eq!(dest_a, unhex(DEST_HASH)[..]);
        assert_eq!(mid_a, unhex(MESSAGE_ID)[..]);
    }

    #[test]
    fn parser_rejects_crafted_oversize_lengths_without_panic() {
        // bin32 with length 0xFFFFFFFF and almost no body: must be MalformedPayload, never OOB/panic
        // (this is the case that wraps a 32-bit usize on the ESP32-S3).
        let data = [0xc6, 0xff, 0xff, 0xff, 0xff, 0x00];
        assert_eq!(read_bin(&data, 0), Err(LxmfError::MalformedPayload));
        // A fields element (bin32, huge len) inside an otherwise-valid payload: skip_value over it
        // must reject, not panic or return a position past the buffer.
        let mut payload = std::vec::Vec::new();
        payload.push(0x94);
        payload.push(0xcb);
        payload.extend_from_slice(&1.0f64.to_be_bytes());
        payload.extend_from_slice(&[0xc4, 1, b'x']); // title
        payload.extend_from_slice(&[0xc4, 1, b'y']); // content
        let fields_pos = payload.len();
        payload.extend_from_slice(&[0xc6, 0xff, 0xff, 0xff, 0xff]); // fields = bin32 len 0xFFFFFFFF
        assert_eq!(
            skip_value(&payload, fields_pos, 0),
            Err(LxmfError::MalformedPayload)
        );
        // skip_value never returns a position past the buffer for any single byte.
        for b in 0u16..=255 {
            let one = [b as u8];
            if let Ok(end) = skip_value(&one, 0, 0) {
                assert!(end <= one.len());
            }
        }
    }
}
