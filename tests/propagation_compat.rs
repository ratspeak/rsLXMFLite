use lxmf_core::{
    constants::DeliveryMethod,
    handlers,
    message::{LxMessage, LxMessageDraft, RecipientStamp},
};
use lxmf_lite_core::{build_link, parse_link, propagation::*};
use rns_lite_core::identity::LocalIdentity;

#[test]
fn announce_matches_trusted_defaults_and_extension_handling() {
    let mut node = handlers::PropagationNodeAnnounceData::new(true, 256, 10240, 16.25, 3.0, 18.5);
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
            stamp_cost: 16.25,
            stamp_flex: 3.0,
            peering_cost: 18.5,
            name: Some("relay"),
        }
    );
    assert_eq!(
        handlers::parse_pn_announce_data(&data).unwrap().stamp_cost,
        parsed.stamp_cost
    );
    for n in 0..data.len() {
        assert!(parse_node_announce(&data[..n]).is_none());
    }
}

#[test]
fn hostile_announce_fields_match_trusted_coercions() {
    // [false, 1, true, 1, 1, [16, 3, 18], {}]
    let data = [0x97, 0xc2, 1, 0xc3, 1, 1, 0x93, 16, 3, 18, 0x80];
    assert!(parse_node_announce(&data).is_some());
    let check = |bad: &[u8]| {
        let trusted = handlers::parse_pn_announce_data(bad);
        let ours = parse_node_announce(bad);
        assert_eq!(
            node_announce_is_valid(bad),
            handlers::pn_announce_data_is_valid(bad),
            "{bad:02x?}"
        );
        assert_eq!(ours.is_some(), trusted.is_some(), "{bad:02x?}");
        if let (Some(ours), Some(trusted)) = (ours, trusted) {
            assert_eq!(ours.timebase, trusted.timebase);
            assert_eq!(ours.enabled, trusted.node_state);
            assert_eq!(
                ours.transfer_limit_kb,
                trusted.transfer_limit.as_f64() as u64
            );
            assert_eq!(ours.stamp_cost, trusted.stamp_cost);
        }
    };
    for offset in 0..data.len() {
        for byte in [
            0x00, 0x01, 0x7f, 0x80, 0x90, 0x92, 0xa0, 0xc0, 0xc1, 0xc2, 0xff,
        ] {
            let mut bad = data;
            bad[offset] = byte;
            check(&bad);
        }
    }
    for number in [f64::NAN, f64::INFINITY, -1.0, 1.25, 18446744073709551616.0] {
        for slot in [2usize, 4, 7] {
            let mut bad = data[..slot].to_vec();
            bad.push(0xcb);
            bad.extend_from_slice(&number.to_be_bytes());
            bad.extend_from_slice(&data[slot + 1..]);
            check(&bad);
        }
    }
    assert!(array_items(&[0xdd, 0xff, 0xff, 0xff, 0xff]).is_err());
    assert!(array_items(&[0x91, 0xc6, 0xff, 0xff, 0xff, 0xff]).is_err());
    let mut nested = vec![0x91; 10];
    nested.push(0xc0);
    assert!(array_items(&nested).is_err());
    let mut deep = data.to_vec();
    deep.pop();
    deep.extend_from_slice(&[0x81, 0x02]);
    deep.extend_from_slice(&nested);
    assert!(!node_announce_is_valid(&deep));
}

#[test]
fn delivery_cost_round_trips_trusted_announce_data() {
    for cost in [None, Some(8.0), Some(8.5), Some(99.75)] {
        let data = handlers::get_announce_app_data(Some("name"), cost);
        assert_eq!(delivery_stamp_cost(&data), Some(cost));
        assert_eq!(handlers::stamp_cost_from_app_data(&data), cost);
    }
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
            let mut trusted = LxMessageDraft::new(
                recipient.lxmf_delivery_hash(),
                source.lxmf_delivery_hash(),
                "title",
                &content,
                DeliveryMethod::Propagated,
            )
            .unwrap();
            trusted.set_timestamp(1234567890.5).unwrap();
            let trusted = trusted
                .sign(&rns_crypto::ed25519::Ed25519PrivateKey::from_bytes(
                    &[0x51; 32],
                ))
                .unwrap()
                .finalize(RecipientStamp::from_bytes(&stamp))
                .unwrap();
            assert_eq!(&buffer[..n], trusted.pack().unwrap());
            assert_eq!(
                parse_link(
                    &recipient,
                    &buffer[..n],
                    source.public_key(),
                    &mut scratch,
                    &mut lxmf_lite_core::LxmfFieldScratch::new()
                )
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
                lxmf_core::stamper::validate_pn_stamp(&entries[0], 0.0)
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
                &mut lxmf_lite_core::LxmfFieldScratch::new(),
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
