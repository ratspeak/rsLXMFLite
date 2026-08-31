//! Construct and validate one full-packed LXMF Link message.

use lxmf_lite_core::{build_link, parse_link};
use rns_lite_core::LocalIdentity;

fn main() {
    // Demonstration keys only. Real firmware must provision identities securely
    // and must never embed predictable private keys.
    let source = LocalIdentity::from_private_key(&[0x11; 64]);
    let recipient = LocalIdentity::from_private_key(&[0x22; 64]);
    let mut packed = [0u8; 500];
    let mut build_scratch = [0u8; 500];
    let mut destination = [0u8; 16];
    let mut message_id = [0u8; 32];

    let length = build_link(
        &source,
        recipient.public_key(),
        1_750_000_000.0,
        b"hello",
        b"from a bounded MCU codec",
        &mut packed,
        &mut build_scratch,
        &mut destination,
        &mut message_id,
    )
    .expect("message fits the fixed buffers");

    let mut parse_scratch = [0u8; 500];
    let view = parse_link(
        &recipient,
        &packed[..length],
        source.public_key(),
        &mut parse_scratch,
    )
    .expect("freshly built message validates");

    assert_eq!(view.title, b"hello");
    println!("validated {}-byte LXMF message", length);
}
