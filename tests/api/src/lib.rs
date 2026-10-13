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
