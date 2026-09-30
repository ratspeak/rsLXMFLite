use lxmf_core::{constants::DeliveryMethod, handlers, message::LxMessage};
use lxmf_lite_core::{build_link, parse_link, propagation::*};
use rns_lite_core::identity::LocalIdentity;

#[test]
fn announce_matches_trusted_defaults_and_extension_handling() {
    let mut node = handlers::PropagationNodeAnnounceData::new(true, 256, 10240, 16, 3, 18);
    node.timebase = 1234567890;
    node.set_name("relay");
    let data = handlers::get_propagation_node_app_data(&node);
    let parsed = parse_node_announce(&data).unwrap();
    assert_eq!(
        parsed,
        NodeAnnounce {
            timebase: 1234567890,
            enabled: true,
            transfer_limit_kb: 256,
            sync_limit_kb: 10240,
            stamp_cost: 16,
            stamp_flex: 3,
            peering_cost: 18,
            name: Some(b"relay"),
        }
    );
    assert_eq!(
        handlers::parse_pn_announce_data(&data).unwrap().stamp_cost,
        parsed.stamp_cost
    );
    let mut extended = data.clone();
    extended[0] = 0x98;
    extended.extend_from_slice(&[0x92, 0xc0, 0x80]);
    assert_eq!(parse_node_announce(&extended), Some(parsed));
    for n in 0..data.len() {
        assert!(parse_node_announce(&data[..n]).is_none());
    }
    let mut trailing = data.clone();
    trailing.push(0);
    assert!(parse_node_announce(&trailing).is_none());
}

#[test]
fn hostile_announce_fields_fail_closed() {
    // [false, 1, true, 1, 1, [16, 3, 18], {}]
    let data = [0x97, 0xc2, 1, 0xc3, 1, 1, 0x93, 16, 3, 18, 0x80];
    assert!(parse_node_announce(&data).is_some());
    for (offset, byte) in [
        (2, 0xff),
        (3, 0),
        (4, 0xff),
        (6, 0x92),
        (7, 0xff),
        (10, 0x90),
    ] {
        let mut bad = data;
        bad[offset] = byte;
        assert!(parse_node_announce(&bad).is_none(), "offset {offset}");
    }
    for number in [f64::NAN, f64::INFINITY, -1.0, 18446744073709551616.0] {
        let mut bad = data[..4].to_vec();
        bad.push(0xcb);
        bad.extend_from_slice(&number.to_be_bytes());
        bad.extend_from_slice(&data[5..]);
        assert!(parse_node_announce(&bad).is_none());
    }
    let mut fractional = data[..4].to_vec();
    fractional.push(0xcb);
    fractional.extend_from_slice(&1.25f64.to_be_bytes());
    fractional.extend_from_slice(&data[5..]);
    assert_eq!(
        parse_node_announce(&fractional).unwrap().transfer_limit_kb,
        handlers::parse_pn_announce_data(&fractional)
            .unwrap()
            .transfer_limit
    );
    assert!(array_items(&[0xdd, 0xff, 0xff, 0xff, 0xff]).is_err());
    assert!(array_items(&[0x91, 0xc6, 0xff, 0xff, 0xff, 0xff]).is_err());
    let mut nested = vec![0x91; 10];
    nested.push(0xc0);
    assert!(array_items(&nested).is_err());
}

#[test]
fn delivery_cost_distinguishes_unknown_nil_and_integer_without_truncating_overflow() {
    for cost in [None, Some(8), Some(16), Some(254)] {
        assert_eq!(
            delivery_stamp_cost(&handlers::get_announce_app_data(Some("name"), cost)),
            Some(cost)
        );
    }
    assert_eq!(delivery_stamp_cost(&[]), None);
    assert_eq!(delivery_stamp_cost(&[0x91, 0xc0]), None);
    assert_eq!(delivery_stamp_cost(&[0x92, 0xc0, 0xcd, 1, 0]), None);
    assert_eq!(delivery_stamp_cost(&[0x92, 0xc0, 0xff]), None);
    assert_eq!(delivery_stamp_cost(&[0x92, 0xc0, 0xc0]), Some(None));
    assert_eq!(delivery_stamp_cost(&[0x92, 0xc0, 0]), Some(Some(0)));
}

#[test]
fn recipient_stamp_and_propagation_envelope_preserve_signed_message() {
    let source = LocalIdentity::from_private_key(&[0x51; 64]);
    let recipient = LocalIdentity::from_private_key(&[0x52; 64]);
    let trusted_recipient =
        rns_identity::identity::Identity::from_private_key(&[0x52; 64]).unwrap();
    for content_len in [0, 32, 255, 1024, 3000] {
        for stamp_len in [16, 32] {
            let content = "x".repeat(content_len);
            let mut buffer = [0; 4096];
            let mut scratch = [0; 4096];
            let mut destination = [0; 16];
            let mut message_id = [0; 32];
            let n = build_link(
                &source,
                recipient.public_key(),
                1234567890.5,
                b"title",
                content.as_bytes(),
                &mut buffer,
                &mut scratch,
                &mut destination,
                &mut message_id,
            )
            .unwrap();
            let stamp = vec![0x72; stamp_len];
            let n = append_recipient_stamp(&mut buffer, n, &stamp).unwrap();
            let mut trusted = LxMessage::new(
                recipient.lxmf_delivery_hash(),
                source.lxmf_delivery_hash(),
                "title",
                &content,
                DeliveryMethod::Propagated,
            );
            trusted.timestamp = 1234567890.5;
            trusted.stamp = Some(stamp);
            trusted
                .sign(&rns_crypto::ed25519::Ed25519PrivateKey::from_bytes(
                    &[0x51; 32],
                ))
                .unwrap();
            assert_eq!(&buffer[..n], trusted.pack().unwrap());
            assert_eq!(
                parse_link(&recipient, &buffer[..n], source.public_key(), &mut scratch)
                    .unwrap()
                    .message_id,
                message_id
            );
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
                &trusted_recipient
                    .decrypt(&buffer[16..encrypted_len], None, false)
                    .unwrap(),
                &trusted.pack().unwrap()[16..]
            );
            let encrypted = buffer[..encrypted_len].to_vec();
            let total = wrap_upload(&mut buffer, encrypted_len, &[0; 32], 987654321.25).unwrap();
            let (timestamp, entries) =
                LxMessage::unpack_propagation_wrapper(&buffer[..total]).unwrap();
            assert_eq!(timestamp, 987654321.25);
            assert_eq!(entries.len(), 1);
            assert_eq!(&entries[0][..encrypted_len], encrypted);
            assert_eq!(&entries[0][encrypted_len..], &[0; 32]);
            assert_eq!(
                lxmf_core::stamper::validate_pn_stamp(&entries[0], 0)
                    .unwrap()
                    .0,
                tid
            );
            let mut incoming = encrypted;
            let (restored_len, incoming_tid, key) =
                decrypt_message(&mut incoming, &recipient, &[[0x33; 32]]).unwrap();
            assert_eq!(incoming_tid, tid);
            assert_eq!(key, None);
            let view = parse_link(
                &recipient,
                &incoming[..restored_len],
                source.public_key(),
                &mut scratch,
            )
            .unwrap();
            assert_eq!(view.message_id, message_id);
            assert_eq!(view.content, content.as_bytes());
        }
    }
}

#[test]
fn recipient_binding_and_buffer_failure_do_not_modify_message() {
    let source = LocalIdentity::from_private_key(&[0x51; 64]);
    let recipient = LocalIdentity::from_private_key(&[0x52; 64]);
    let mut buffer = [0; 512];
    let mut scratch = [0; 512];
    let n = build_link(
        &source,
        recipient.public_key(),
        1.0,
        b"",
        b"hello",
        &mut buffer,
        &mut scratch,
        &mut [0; 16],
        &mut [0; 32],
    )
    .unwrap();
    let original = buffer;
    assert!(
        encrypt_message(
            &mut buffer,
            n,
            source.public_key(),
            None,
            &[1; 32],
            &[2; 16]
        )
        .is_err()
    );
    assert_eq!(buffer, original);
    assert!(
        encrypt_message(
            &mut buffer[..n],
            n,
            recipient.public_key(),
            None,
            &[1; 32],
            &[2; 16]
        )
        .is_err()
    );
    assert_eq!(buffer, original);
    assert!(append_recipient_stamp(&mut buffer[..n], n, &[0; 32]).is_err());
    assert_eq!(buffer, original);
}
