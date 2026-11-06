//! Compile contract for representative use outside the rsLXMFLite workspace.

use lxmf_lite_core::{LxmfError, LxmfFieldScratch, LxmfView, build_link, parse_link};
use rns_lite_core::LocalIdentity;

pub fn build<'a>(
    source: &LocalIdentity,
    recipient: &LocalIdentity,
    out: &'a mut [u8; 500],
    scratch: &mut [u8; 500],
) -> Result<(&'a [u8], [u8; 32]), LxmfError> {
    let mut destination = [0u8; 16];
    let mut message_id = [0u8; 32];
    let length = build_link(
        source,
        recipient.public_key(),
        1_750_000_000.0,
        b"fixture",
        b"external consumer",
        out,
        scratch,
        &mut destination,
        &mut message_id,
    )?;
    Ok((&out[..length], message_id))
}

pub fn parse<'a>(
    recipient: &LocalIdentity,
    source: &LocalIdentity,
    packed: &'a [u8],
    scratch: &mut [u8],
    field_scratch: &mut LxmfFieldScratch,
) -> Result<LxmfView<'a>, LxmfError> {
    parse_link(
        recipient,
        packed,
        source.public_key(),
        scratch,
        field_scratch,
    )
}

/// An external MCU caller supplies already encoded native audio and all storage.
pub fn build_audio<'a>(
    source: &LocalIdentity,
    recipient: &LocalIdentity,
    native: &[u8],
    out: &'a mut [u8; 3659],
    scratch: &mut [u8; 3659],
) -> Result<&'a [u8], LxmfError> {
    use lxmf_lite_core::{
        AM_CODEC2_700C, AudioField, build_link_with_audio, packed_len_with_audio,
    };
    let expected = packed_len_with_audio(0, 13, AM_CODEC2_700C, native.len())?;
    if expected > out.len() {
        return Err(LxmfError::TooLong);
    }
    let n = build_link_with_audio(
        source,
        recipient.public_key(),
        1_750_000_000.0,
        b"",
        b"Voice message",
        AudioField {
            mode: AM_CODEC2_700C,
            bytes: native,
        },
        out,
        scratch,
        &mut [0; 16],
        &mut [0; 32],
    )?;
    Ok(&out[..n])
}

/// A node reply: caller-encoded results, a ticket stamp, one opportunistic packet.
pub fn build_stamped_reply<'a>(
    node: &LocalIdentity,
    manager: &LocalIdentity,
    results: &[u8],
    ticket: &[u8; 16],
    out: &'a mut [u8; 464],
    scratch: &mut [u8; 464],
) -> Result<&'a [u8], LxmfError> {
    use lxmf_lite_core::{
        FIELD_RESULTS, build_link_with_fields, propagation::append_recipient_stamp,
        seal_opportunistic, stamp::ticket_stamp,
    };
    let mut message_id = [0u8; 32];
    let n = build_link_with_fields(
        node,
        manager.public_key(),
        1_750_000_000.0,
        b"",
        b"Status: ok",
        &[(FIELD_RESULTS, results)],
        out,
        scratch,
        &mut [0; 16],
        &mut message_id,
    )?;
    let n = append_recipient_stamp(out, n, &ticket_stamp(ticket, &message_id))?;
    let n = seal_opportunistic(out, n, manager.public_key(), None, &[1; 32], &[2; 16])?;
    Ok(&out[..n])
}

/// The ticket a manager offered in an authenticated command, if still valid.
pub fn learned_ticket(view: &LxmfView<'_>, now: f64) -> Option<[u8; 16]> {
    lxmf_lite_core::ticket_field(view.fields, now).map(|field| field.ticket)
}
