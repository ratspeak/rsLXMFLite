//! Native audio fields adapted from the trusted full Rust message codec.
//! These tests qualify signed wire/container behavior, not audio decoding.
use lxmf_core::{constants::DeliveryMethod, message::LxMessage};
use lxmf_lite_core::{
    AM_CODEC2_700C, AudioField, FIELD_AUDIO, LxmfError, audio_field, build_link_with_audio,
    packed_len_with_audio, parse_link,
    propagation::{append_recipient_stamp, decrypt_message, encrypt_message, wrap_upload},
};
use rns_lite_core::LocalIdentity;

fn identities() -> (LocalIdentity, LocalIdentity) {
    (
        LocalIdentity::from_private_key(&[0x51; 64]),
        LocalIdentity::from_private_key(&[0x52; 64]),
    )
}
fn trusted(mode: u8, bytes: &[u8]) -> LxMessage {
    let (source, recipient) = identities();
    let mut message = LxMessage::new(
        recipient.lxmf_delivery_hash(),
        source.lxmf_delivery_hash(),
        "",
        "Voice message",
        DeliveryMethod::Direct,
    );
    message.timestamp = 1234567890.5;
    message.set_audio_field(mode, bytes).unwrap();
    message
        .sign(&rns_crypto::ed25519::Ed25519PrivateKey::from_bytes(
            &[0x51; 32],
        ))
        .unwrap();
    message
}
fn build(
    mode: u8,
    bytes: &[u8],
    out: &mut [u8],
    scratch: &mut [u8],
) -> Result<(usize, [u8; 32]), LxmfError> {
    let (source, recipient) = identities();
    let mut id = [0; 32];
    let n = build_link_with_audio(
        &source,
        recipient.public_key(),
        1234567890.5,
        b"",
        b"Voice message",
        AudioField { mode, bytes },
        out,
        scratch,
        &mut [0; 16],
        &mut id,
    )?;
    Ok((n, id))
}

#[test]
fn signed_audio_is_byte_exact_with_full_rust_and_borrows_payload() {
    assert_eq!(FIELD_AUDIO, lxmf_core::constants::FIELD_AUDIO);
    assert_eq!(AM_CODEC2_700C, lxmf_core::constants::AM_CODEC2_700C);
    let (source, recipient) = identities();
    for mode in [AM_CODEC2_700C, 0x10, 0x7f, 0x80, 0xff] {
        for len in [0, 4, 255, 256, 500, 1500, 3000, 65535, 65536] {
            let bytes: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let reference = trusted(mode, &bytes);
            let size = packed_len_with_audio(0, 13, mode, len).unwrap();
            assert_eq!(size, reference.packed_len().unwrap());
            let mut out = vec![0; size];
            let mut scratch = vec![0; size];
            let (n, id) = build(mode, &bytes, &mut out, &mut scratch).unwrap();
            assert_eq!(n, size);
            assert_eq!(reference.pack().unwrap(), out);
            assert_eq!(reference.hash.unwrap(), id);
            let view = parse_link(&recipient, &out, source.public_key(), &mut scratch).unwrap();
            let field = audio_field(view.fields).unwrap().unwrap();
            assert_eq!(
                field,
                AudioField {
                    mode,
                    bytes: &bytes
                }
            );
            let start = out.as_ptr() as usize;
            let borrowed = field.bytes.as_ptr() as usize;
            assert!(borrowed >= start && borrowed + len <= start + out.len());
            assert_eq!(view.message_id, id);
            let mut unpacked = LxMessage::unpack(&out).unwrap();
            let key = rns_crypto::ed25519::Ed25519PrivateKey::from_bytes(&[0x51; 32]);
            assert!(unpacked.verify(&key.public_key()));
            assert_eq!(unpacked.audio_field().unwrap().unwrap().bytes, bytes);
            if len != 0 {
                let offset = borrowed - start;
                out[offset] ^= 0x80;
                assert!(matches!(
                    parse_link(&recipient, &out, source.public_key(), &mut scratch),
                    Err(LxmfError::SignatureInvalid)
                ));
            }
        }
    }
}

#[test]
fn stamped_propagation_retains_audio_and_the_authenticated_id() {
    let (source, recipient) = identities();
    let trusted_recipient =
        rns_identity::identity::Identity::from_private_key(&[0x52; 64]).unwrap();
    for len in [4, 500, 1500, 3000] {
        for stamp_len in [16, 32] {
            let bytes = vec![0x93; len];
            let mut buffer = [0; 4096];
            let mut scratch = [0; 4096];
            let (n, id) = build(AM_CODEC2_700C, &bytes, &mut buffer, &mut scratch).unwrap();
            let stamp = vec![0x72; stamp_len];
            let n = append_recipient_stamp(&mut buffer, n, &stamp).unwrap();
            let mut reference = trusted(AM_CODEC2_700C, &bytes);
            reference.stamp = Some(stamp);
            assert_eq!(&buffer[..n], reference.pack().unwrap());
            let signed = buffer[..n].to_vec();
            let (encrypted_len, tid) = encrypt_message(
                &mut buffer,
                n,
                recipient.public_key(),
                None,
                &[0x73; 32],
                &[0x74; 16],
            )
            .unwrap();
            assert_eq!(
                trusted_recipient
                    .decrypt(&buffer[16..encrypted_len], None, false)
                    .unwrap(),
                signed[16..]
            );
            let encrypted = buffer[..encrypted_len].to_vec();
            let wrapped = wrap_upload(&mut buffer, encrypted_len, &[0; 32], 1234567890.5).unwrap();
            let (_, entries) = LxMessage::unpack_propagation_wrapper(&buffer[..wrapped]).unwrap();
            assert_eq!(&entries[0][..encrypted_len], encrypted);
            assert_eq!(
                lxmf_core::stamper::validate_pn_stamp(&entries[0], 0)
                    .unwrap()
                    .0,
                tid
            );
            let mut restored = encrypted;
            let (n, received_tid, _) = decrypt_message(&mut restored, &recipient, &[]).unwrap();
            assert_eq!(received_tid, tid);
            assert_eq!(&restored[..n], signed);
            let view = parse_link(
                &recipient,
                &restored[..n],
                source.public_key(),
                &mut scratch,
            )
            .unwrap();
            assert_eq!(view.message_id, id);
            assert_eq!(audio_field(view.fields).unwrap().unwrap().bytes, bytes);
        }
    }
}

#[test]
fn malformed_audio_is_separate_from_message_authentication() {
    let (source, recipient) = identities();
    for value in [
        vec![0x91, 3],                   // missing bytes
        vec![0x93, 3, 0xc4, 0, 0],       // extra member
        vec![0x92, 0xff, 0xc4, 0],       // negative mode
        vec![0x92, 0xcd, 1, 0, 0xc4, 0], // mode overflow
        vec![0x92, 0xc3, 0xc4, 0],       // boolean mode
        vec![0x92, 3, 0xa1, b'x'],       // text instead of binary
        vec![0x92, 3, 0xc0],             // nil data
        vec![0x92, 3, 0x90],             // array instead of binary
    ] {
        let mut message = trusted(3, b"test");
        message.fields.insert(FIELD_AUDIO, value);
        message
            .sign(&rns_crypto::ed25519::Ed25519PrivateKey::from_bytes(
                &[0x51; 32],
            ))
            .unwrap();
        let packed = message.pack().unwrap();
        let mut scratch = vec![0; packed.len()];
        let view = parse_link(&recipient, &packed, source.public_key(), &mut scratch).unwrap();
        assert!(audio_field(view.fields).is_err());
        assert!(message.audio_field().is_err());
    }
}

#[test]
fn strict_audio_map_handles_truncation_duplicate_keys_and_integer_encodings() {
    assert_eq!(audio_field(&[0x80]), Ok(None));
    assert!(audio_field(&[0x80, 0]).is_err());
    assert!(audio_field(&[0x90]).is_err());
    // Last occurrence wins, including a malformed last field.
    assert_eq!(
        audio_field(&[0x82, 7, 0xc0, 7, 0x92, 3, 0xc4, 1, 0x42])
            .unwrap()
            .unwrap(),
        AudioField {
            mode: 3,
            bytes: &[0x42]
        }
    );
    assert!(audio_field(&[0x82, 7, 0x92, 3, 0xc4, 1, 0x42, 7, 0xc0]).is_err());
    for integer in [
        vec![3],
        vec![0xcc, 3],
        vec![0xcd, 0, 3],
        vec![0xce, 0, 0, 0, 3],
        vec![0xcf, 0, 0, 0, 0, 0, 0, 0, 3],
        vec![0xd0, 3],
        vec![0xd1, 0, 3],
        vec![0xd2, 0, 0, 0, 3],
        vec![0xd3, 0, 0, 0, 0, 0, 0, 0, 3],
    ] {
        for array in [vec![0x92], vec![0xdc, 0, 2], vec![0xdd, 0, 0, 0, 2]] {
            let mut map = vec![0x81, 7];
            map.extend_from_slice(&array);
            map.extend_from_slice(&integer);
            map.extend_from_slice(&[0xc4, 4, 1, 2, 3, 4]);
            let field = audio_field(&map).unwrap().unwrap();
            assert_eq!(
                field,
                AudioField {
                    mode: 3,
                    bytes: &[1, 2, 3, 4]
                }
            );
            for end in 0..map.len() {
                assert!(audio_field(&map[..end]).is_err());
            }
        }
    }
    for value in [
        vec![0x81, 7, 0x92, 3, 0xc6, 255, 255, 255, 255],
        vec![0xdf, 255, 255, 255, 255],
        vec![0x81, 7, 0x92, 0xd0, 0xff, 0xc4, 0],
    ] {
        assert!(audio_field(&value).is_err());
    }
    let mut nested = vec![0x81, 7];
    nested.extend_from_slice(&[0x91; 10]);
    nested.push(0);
    assert!(audio_field(&nested).is_err());
}

#[test]
fn exact_capacity_and_count_overflow_are_checked() {
    let bytes = [0x7f; 1500];
    let n = packed_len_with_audio(0, 13, 3, bytes.len()).unwrap();
    // Actual scratch only needs 64 + payload, 32 fewer bytes than packed data.
    assert!(build(3, &bytes, &mut vec![0; n], &mut vec![0; n - 32]).is_ok());
    for (out_len, scratch_len) in [(n - 1, n), (n, n - 33), (0, n), (n, 0)] {
        let mut output = vec![0xa5; out_len];
        assert!(build(3, &bytes, &mut output, &mut vec![0; scratch_len]).is_err());
        assert!(output.iter().all(|&v| v == 0xa5));
    }
    assert!(packed_len_with_audio(usize::MAX, 0, 3, 0).is_err());
    assert!(packed_len_with_audio(0, usize::MAX, 3, 0).is_err());
    assert!(packed_len_with_audio(0, 0, 3, usize::MAX).is_err());
}

#[test]
fn signed_container_matches_pinned_python_fixture() {
    // Regenerate with scripts/create-audio-fixture.py and the references recorded
    // in fixtures/audio-700c.json. The payload is opaque binary, not encoded speech.
    let expected = include_bytes!("fixtures/audio-700c.lxmf");
    let bytes: Vec<u8> = (0..1500).map(|i| (i % 251) as u8).collect();
    let mut output = vec![0; expected.len()];
    let mut scratch = vec![0; expected.len()];
    let (n, id) = build(AM_CODEC2_700C, &bytes, &mut output, &mut scratch).unwrap();
    assert_eq!(&output[..n], expected);
    let (source, recipient) = identities();
    let parsed = parse_link(&recipient, expected, source.public_key(), &mut scratch).unwrap();
    assert_eq!(parsed.message_id, id);
    assert_eq!(
        audio_field(parsed.fields).unwrap().unwrap(),
        AudioField {
            mode: AM_CODEC2_700C,
            bytes: &bytes
        }
    );
}
