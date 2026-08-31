//! Compile contract for representative use outside the rsLXMFLite workspace.

use lxmf_lite_core::{LxmfError, LxmfView, build_link, parse_link};
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
) -> Result<LxmfView<'a>, LxmfError> {
    parse_link(recipient, packed, source.public_key(), scratch)
}
