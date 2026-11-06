//! Caller-encoded fields, ticket stamps and stamped opportunistic sealing.
//! Byte parity with the trusted `lxmf-core` draft codec, plus vectors packed,
//! parsed, signature-checked and stamp-checked by upstream Python LXMF.
use lxmf_core::{
    constants::DeliveryMethod,
    message::{LxMessage, LxMessageDraft, RecipientStamp},
    ticket::Ticket,
};
use lxmf_lite_core::{
    EncodedField, FIELD_RESULTS, FIELD_TICKET, LxmfError, LxmfFieldScratch, MAX_FIELDS,
    TicketField, build_link, build_link_with_fields, build_opportunistic_ratchet_with_fields,
    build_opportunistic_with_fields,
    lxmf::{field_value, parse_opportunistic_ratchet},
    packed_len, packed_len_with_fields, parse_link, parse_opportunistic,
    propagation::append_recipient_stamp,
    seal_opportunistic,
    stamp::{Progress, StampKind, StampSearch, TICKET_LENGTH, Workblock, ticket_stamp},
    ticket_field,
};
use rns_lite_core::{LocalIdentity, ratchet::ratchet_public_bytes};
use serde_json::Value;

const TIMESTAMP: f64 = 1234567890.5;
const NODE: [u8; 64] = [0x51; 64];
const MANAGER: [u8; 64] = [0x52; 64];

fn lite(key: &[u8; 64]) -> LocalIdentity {
    LocalIdentity::from_private_key(key)
}
fn trusted(key: &[u8; 64]) -> rns_identity::identity::Identity {
    rns_identity::identity::Identity::from_private_key(key).unwrap()
}
fn signing_key(key: &[u8; 64]) -> rns_crypto::ed25519::Ed25519PrivateKey {
    rns_crypto::ed25519::Ed25519PrivateKey::from_bytes(&key[32..].try_into().unwrap())
}
fn hex(value: &Value) -> Vec<u8> {
    let text = value.as_str().unwrap();
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn trusted_draft(content: &str, fields: &[EncodedField<'_>]) -> LxMessageDraft {
    let mut draft = LxMessageDraft::new(
        lite(&MANAGER).lxmf_delivery_hash(),
        lite(&NODE).lxmf_delivery_hash(),
        "",
        content,
        DeliveryMethod::Direct,
    )
    .unwrap();
    draft.set_timestamp(TIMESTAMP).unwrap();
    for &(id, value) in fields {
        draft.set_msgpack_field(id, value.to_vec()).unwrap();
    }
    draft
}

fn lite_link(
    content: &[u8],
    fields: &[EncodedField<'_>],
) -> Result<(Vec<u8>, [u8; 32]), LxmfError> {
    let size = packed_len_with_fields(0, content.len(), fields)?;
    let mut out = vec![0; size + 34];
    let mut scratch = vec![0; size];
    let mut id = [0; 32];
    let n = build_link_with_fields(
        &lite(&NODE),
        lite(&MANAGER).public_key(),
        TIMESTAMP,
        b"",
        content,
        fields,
        &mut out,
        &mut scratch,
        &mut [0; 16],
        &mut id,
    )?;
    assert_eq!(n, size);
    out.truncate(n);
    Ok((out, id))
}

fn nested(depth: usize) -> Vec<u8> {
    let mut value = vec![0x91; depth];
    value.push(0xc0);
    value
}

fn field_sets() -> Vec<Vec<(u8, Vec<u8>)>> {
    let bin300: Vec<u8> = [&[0xc5, 0x01, 0x2c][..], &[0x77; 300]].concat();
    let bin70k: Vec<u8> = [&[0xc6, 0x00, 0x01, 0x11, 0x70][..], &[0x78; 70000]].concat();
    let mut sets = vec![
        vec![],
        vec![(FIELD_RESULTS, vec![0x81, 0x00, 0x01])],
        // Reverse order: output must follow the trusted ascending-id map.
        vec![
            (0xff, vec![0xc3]),
            (0x80, vec![0xa3, b'a', b'b', b'c']),
            (0x7f, vec![0xcd, 0x12, 0x34]),
            (
                FIELD_RESULTS,
                vec![0x82, 0x00, 0x01, 0x06, 0x92, 0x0b, 0x05],
            ),
            (0x00, vec![0xc0]),
        ],
        vec![
            (0x10, bin300),
            (
                0x11,
                vec![0xcb, 0x41, 0xd2, 0x65, 0x80, 0xb4, 0x80, 0x00, 0x00],
            ),
            (0x12, nested(7)),
            (0x13, vec![0xde, 0x00, 0x01, 0xa1, b'k', 0xe0]),
        ],
        vec![(0x20, bin70k)],
    ];
    for count in [15u8, 16, 64] {
        sets.push(
            (0..count)
                .map(|i| (i.wrapping_mul(37), vec![i & 0x7f]))
                .collect(),
        );
    }
    sets
}

#[test]
fn field_builders_are_byte_exact_with_trusted_set_msgpack_field() {
    assert_eq!(FIELD_RESULTS, lxmf_core::constants::FIELD_RESULTS);
    assert_eq!(FIELD_TICKET, lxmf_core::constants::FIELD_TICKET);
    assert_eq!(TICKET_LENGTH, lxmf_core::constants::TICKET_LENGTH);
    let (node, manager) = (lite(&NODE), lite(&MANAGER));
    for set in field_sets() {
        let fields: Vec<EncodedField<'_>> = set.iter().map(|(id, v)| (*id, v.as_slice())).collect();
        for content in ["", "Status: ok", &"x".repeat(300)] {
            let reference = trusted_draft(content, &fields)
                .sign(&signing_key(&NODE))
                .unwrap();
            assert_eq!(
                packed_len_with_fields(0, content.len(), &fields).unwrap(),
                reference.packed_len().unwrap()
            );
            let reference_id = reference.message_id();
            let reference = reference.finalize(None).unwrap();
            let (packed, id) = lite_link(content.as_bytes(), &fields).unwrap();
            assert_eq!(packed, reference.pack().unwrap());
            assert_eq!(id, reference_id);

            let mut scratch = vec![0; packed.len()];
            let view = parse_link(
                &manager,
                &packed,
                node.public_key(),
                &mut scratch,
                &mut LxmfFieldScratch::new(),
            )
            .unwrap();
            for &(field, value) in &fields {
                assert_eq!(field_value(view.fields, field), Some(value));
            }
            let unpacked = LxMessage::unpack(&packed).unwrap();
            assert!(unpacked.verify_signature(&signing_key(&NODE).public_key()));
            assert_eq!(unpacked.fields().len(), fields.len());
        }
    }
}

#[test]
fn empty_fields_keep_the_existing_text_wire() {
    let (packed, id) = lite_link(b"hello", &[]).unwrap();
    let mut out = vec![0; packed.len()];
    let mut scratch = vec![0; packed.len()];
    let mut old_id = [0; 32];
    build_link(
        &lite(&NODE),
        lite(&MANAGER).public_key(),
        TIMESTAMP,
        b"",
        b"hello",
        &mut out,
        &mut scratch,
        &mut [0; 16],
        &mut old_id,
    )
    .unwrap();
    assert_eq!((out, old_id), (packed, id));
    assert_eq!(
        packed_len(0, 5).unwrap(),
        packed_len_with_fields(0, 5, &[]).unwrap()
    );
}

#[test]
fn invalid_field_entries_are_rejected_before_signing() {
    let one: &[u8] = &[0x01];
    let duplicate = [(1, one), (2, one), (1, one)];
    assert_eq!(lite_link(b"", &duplicate), Err(LxmfError::DuplicateField));
    let many: Vec<EncodedField<'_>> = (0..=MAX_FIELDS as u8).map(|id| (id, one)).collect();
    assert_eq!(lite_link(b"", &many), Err(LxmfError::TooManyFields));
    let depth8 = nested(8);
    for value in [
        &[][..],
        &[0x01, 0x02],
        &[0xc4, 0x02, 0x00],
        &[0x92, 0x01],
        &[0xc1],
        &[0xd4, 0x01, 0x00], // extension types are outside the embedded profile
        &depth8,
    ] {
        assert_eq!(
            packed_len_with_fields(0, 0, &[(FIELD_RESULTS, value)]),
            Err(LxmfError::MalformedPayload),
            "{value:02x?}"
        );
        assert_eq!(
            lite_link(b"", &[(FIELD_RESULTS, value)]),
            Err(LxmfError::MalformedPayload)
        );
    }
}

#[test]
fn opportunistic_fields_match_trusted_and_seal_matches_the_one_shot_builder() {
    let (node, manager) = (lite(&NODE), lite(&MANAGER));
    let ratchet_private = [0x53; 32];
    let ratchet = ratchet_public_bytes(&ratchet_private);
    let results: &[u8] = &[
        0x82, 0x00, 0x01, 0x01, 0xa6, b's', b't', b'a', b't', b'u', b's',
    ];
    let fields = [(FIELD_RESULTS, results)];
    let reference = trusted_draft("Status: ok", &fields)
        .sign(&signing_key(&NODE))
        .unwrap()
        .finalize(None)
        .unwrap()
        .pack()
        .unwrap();
    for target in [None, Some(&ratchet)] {
        let mut out = [0; rns_lite_core::constants::MDU];
        let (mut destination, mut id) = ([0; 16], [0; 32]);
        let n = build_opportunistic_ratchet_with_fields(
            &node,
            manager.public_key(),
            target,
            TIMESTAMP,
            b"",
            b"Status: ok",
            &fields,
            &[0x31; 32],
            &[0x32; 16],
            &mut out,
            &mut destination,
            &mut id,
        )
        .unwrap();
        assert_eq!(destination, manager.lxmf_delivery_hash());
        let ring = [&ratchet_private];
        let plaintext = trusted(&MANAGER)
            .decrypt(&out[..n], target.map(|_| &ring[..]), target.is_some())
            .unwrap();
        assert_eq!(plaintext, reference[16..]);

        let (mut sealed, _) = lite_link(b"Status: ok", &fields).unwrap();
        assert_eq!(&sealed[16..], &reference[16..]);
        sealed.resize(rns_lite_core::constants::MDU, 0);
        let packed_len = reference.len();
        let m = seal_opportunistic(
            &mut sealed,
            packed_len,
            manager.public_key(),
            target,
            &[0x31; 32],
            &[0x32; 16],
        )
        .unwrap();
        assert_eq!(&sealed[..m], &out[..n]);
    }
    let mut base = [0; 600];
    let n = build_opportunistic_with_fields(
        &node,
        manager.public_key(),
        TIMESTAMP,
        b"",
        b"Status: ok",
        &fields,
        &[0x31; 32],
        &[0x32; 16],
        &mut base,
        &mut [0; 16],
        &mut [0; 32],
    )
    .unwrap();
    let mut scratch = [0; rns_lite_core::crypto::MAX_ECIES_PLAINTEXT];
    let view = parse_opportunistic(
        &manager,
        &base[..n],
        node.public_key(),
        &mut scratch,
        &mut LxmfFieldScratch::new(),
    )
    .unwrap();
    assert_eq!(field_value(view.fields, FIELD_RESULTS), Some(results));
}

#[test]
fn ticket_and_pow_stamps_match_trusted_finalization() {
    let (node, manager) = (lite(&NODE), lite(&MANAGER));
    let results: &[u8] = &[0x81, 0x00, 0x01];
    let fields = [(FIELD_RESULTS, results)];
    let ticket = [0x5a; 16];
    let mut draft = trusted_draft("ok", &fields);
    draft.outbound_ticket = Some(ticket);
    let signed = draft.sign(&signing_key(&NODE)).unwrap();
    let stamp = signed.generate_recipient_stamp().unwrap();
    let reference = signed.finalize(stamp).unwrap();
    let (mut packed, id) = lite_link(b"ok", &fields).unwrap();
    let stamp = ticket_stamp(&ticket, &id);
    let n = packed.len();
    packed.resize(n + 18, 0);
    append_recipient_stamp(&mut packed, n, &stamp).unwrap();
    assert_eq!(packed, reference.pack().unwrap());
    let unpacked = LxMessage::unpack(&packed).unwrap();
    assert!(unpacked.validate_stamp_with_tickets(16, Some(&[ticket.to_vec()])));
    assert!(!unpacked.validate_stamp_with_tickets(16, Some(&[[0; 16].to_vec()])));

    // Stamped opportunistic: the signed region and message ID are unchanged.
    let packed_len = packed.len();
    packed.resize(rns_lite_core::constants::MDU, 0);
    let m = seal_opportunistic(
        &mut packed,
        packed_len,
        manager.public_key(),
        None,
        &[0x41; 32],
        &[0x42; 16],
    )
    .unwrap();
    let plaintext = trusted(&MANAGER)
        .decrypt(&packed[..m], None, false)
        .unwrap();
    assert_eq!(plaintext, reference.pack().unwrap()[16..]);
    let mut scratch = [0; rns_lite_core::crypto::MAX_ECIES_PLAINTEXT];
    let view = parse_opportunistic(
        &manager,
        &packed[..m],
        node.public_key(),
        &mut scratch,
        &mut LxmfFieldScratch::new(),
    )
    .unwrap();
    assert_eq!(view.message_id, id);

    // A resumable-search stamp is accepted by trusted validation and finalization.
    let mut search = StampSearch::new(id, StampKind::Message, 8, [0x24; 32], 1 << 20);
    let pow = loop {
        match search.step(u16::MAX, u32::MAX) {
            Progress::Complete { stamp, .. } => break stamp,
            Progress::Preparing { .. } | Progress::Searching { .. } => {}
            other => panic!("{other:?}"),
        }
    };
    let (mut packed, _) = lite_link(b"ok", &fields).unwrap();
    let n = packed.len();
    packed.resize(n + 34, 0);
    append_recipient_stamp(&mut packed, n, &pow).unwrap();
    let reference = trusted_draft("ok", &fields)
        .sign(&signing_key(&NODE))
        .unwrap()
        .finalize(Some(RecipientStamp::ProofOfWork(pow)))
        .unwrap();
    assert_eq!(packed, reference.pack().unwrap());
    let unpacked = LxMessage::unpack(&packed).unwrap();
    assert!(unpacked.validated_stamp_value(8, None).unwrap() >= 8);
}

#[test]
fn seal_rejects_oversize_foreign_and_short_buffers_without_damage() {
    let manager = lite(&MANAGER);
    let big = vec![b'x'; 300];
    let (mut packed, _) = lite_link(&big, &[]).unwrap();
    let n = packed.len();
    packed.resize(1000, 0);
    let original = packed.clone();
    let seal = |buffer: &mut [u8], len, key: &[u8; 64]| {
        seal_opportunistic(buffer, len, key, None, &[1; 32], &[2; 16])
    };
    assert_eq!(
        seal(&mut packed, n, manager.public_key()),
        Err(LxmfError::TooLong)
    );
    assert_eq!(
        seal(&mut packed, n, lite(&NODE).public_key()),
        Err(LxmfError::DestinationMismatch)
    );
    assert_eq!(
        seal(&mut packed, n - 1, manager.public_key()),
        Err(LxmfError::MalformedPayload)
    );
    assert_eq!(packed, original);
    let (mut small, _) = lite_link(b"ok", &[]).unwrap();
    let n = small.len();
    let original = small.clone();
    assert_eq!(
        seal(&mut small, n, manager.public_key()),
        Err(LxmfError::OutputTooSmall)
    );
    assert_eq!(small, original);
}

#[test]
fn ticket_field_reader_matches_trusted_decode_field() {
    let token = [0x61; 16];
    let bin = |len: usize| [&[0xc4, len as u8][..], &vec![0x61; len]].concat();
    let str16 = [&[0xb0][..], &[0x61; 16]].concat();
    let f64v = |v: f64| [&[0xcb][..], &v.to_be_bytes()].concat();
    let f32v = [&[0xca][..], &1500.5f32.to_be_bytes()].concat();
    let cases: Vec<Vec<u8>> = vec![
        [&[0x92][..], &f64v(2000.0), &bin(16)].concat(),
        [&[0x92][..], &f32v, &bin(16)].concat(),
        [&[0x92, 0xcd, 0x07, 0xd0][..], &bin(16)].concat(),
        [&[0x92, 0xcf][..], &u64::MAX.to_be_bytes(), &bin(16)].concat(),
        [&[0x92, 0xd1, 0xfc, 0x18][..], &bin(16)].concat(),
        [&[0x92, 0xd3][..], &(-5i64).to_be_bytes(), &bin(16)].concat(),
        [&[0x92, 0x7f][..], &bin(16)].concat(),
        [&[0x92][..], &f64v(2000.0), &str16].concat(),
        [&[0xdc, 0x00, 0x02][..], &f64v(2000.0), &bin(16)].concat(),
        [&[0x92][..], &f64v(999.0), &bin(16)].concat(),
        [&[0x92][..], &f64v(1000.0), &bin(16)].concat(),
        [&[0x92][..], &f64v(f64::NAN), &bin(16)].concat(),
        [&[0x92][..], &f64v(f64::INFINITY), &bin(16)].concat(),
        [&[0x92][..], &f64v(2000.0), &bin(15)].concat(),
        [&[0x92][..], &f64v(2000.0), &bin(17)].concat(),
        [&[0x93][..], &f64v(2000.0), &bin(16), &[0xc0]].concat(),
        [&[0x91][..], &f64v(2000.0)].concat(),
        [&[0x92, 0xc0][..], &bin(16)].concat(),
        [&[0x92, 0xa1, b'1'][..], &bin(16)].concat(),
        vec![0xc0],
    ];
    for value in cases {
        let fields = [&[0x81, FIELD_TICKET][..], &value].concat();
        let reference = Ticket::decode_field([0; 16], &value, 1000.0);
        let ours = ticket_field(&fields, 1000.0);
        assert_eq!(
            ours.map(|t| (t.expires.to_bits(), t.ticket)),
            reference.map(|t| (t.expires.to_bits(), t.token)),
            "{value:02x?}"
        );
        if let Some(t) = ours {
            assert_eq!(t.ticket, token);
        }
    }
    assert_eq!(ticket_field(&[0x80], 0.0), None);
    let encoded = Ticket::new(token, [0; 16], 1e9).encode_field().unwrap();
    let fields = [&[0x81, FIELD_TICKET][..], &encoded].concat();
    assert_eq!(
        ticket_field(&fields, 0.0),
        Some(TicketField {
            expires: 1e9,
            ticket: token
        })
    );
}

// Vectors from scripts/create-fields-fixture.py: upstream Python LXMF packed,
// parsed, signature-validated and stamp-validated each message.
#[test]
fn upstream_python_vectors_match_lite_builders_and_parsers() {
    let document: Value =
        serde_json::from_str(include_str!("fixtures/field-results.json")).unwrap();
    let (node, manager) = (lite(&NODE), lite(&MANAGER));
    assert_eq!(document["timestamp"].as_f64(), Some(TIMESTAMP));
    let ticket: [u8; 16] = hex(&document["ticket"]).try_into().unwrap();
    let ticket_expires = document["ticket_expires"].as_f64().unwrap();
    let ratchet_private: [u8; 32] = hex(&document["ratchet_private"]).try_into().unwrap();
    let ratchet = ratchet_public_bytes(&ratchet_private);
    let results = hex(&document["results_encoded"]);
    let extension_id = document["extension_field"].as_u64().unwrap() as u8;
    let extension = hex(&document["extension_encoded"]);
    let vectors = document["vectors"].as_array().unwrap();
    assert_eq!(vectors.len(), 9);
    let mut stamped = 0;
    for vector in vectors {
        let name = vector["name"].as_str().unwrap();
        assert_eq!(vector["python_signature_validated"], Value::Bool(true));
        let packed = hex(&vector["packed"]);
        let message_id: [u8; 32] = hex(&vector["message_id"]).try_into().unwrap();
        let content = vector["content"].as_str().unwrap().as_bytes();
        let opportunistic = vector["method"] == "opportunistic";
        let ratcheted = vector["ratchet"] == Value::Bool(true);
        let target = ratcheted.then_some(&ratchet);

        if name == "inbound_command_ticket" {
            // Manager -> node command: the node parses it and learns the ticket.
            let mut scratch = [0; rns_lite_core::crypto::MAX_ECIES_PLAINTEXT];
            let encrypted = hex(&vector["encrypted"]);
            let view = parse_opportunistic(
                &node,
                &encrypted,
                manager.public_key(),
                &mut scratch,
                &mut LxmfFieldScratch::new(),
            )
            .unwrap();
            assert_eq!(view.message_id, message_id);
            assert_eq!(view.content, b"/status");
            assert_eq!(view.source_hash, manager.lxmf_delivery_hash());
            let learned = ticket_field(view.fields, TIMESTAMP).unwrap();
            assert_eq!(
                learned,
                TicketField {
                    expires: ticket_expires,
                    ticket
                }
            );
            assert_eq!(ticket_field(view.fields, ticket_expires), None);
            // Rebuilding with the same encoded field reproduces Python's bytes.
            let value = field_value(view.fields, FIELD_TICKET).unwrap();
            let mut out = vec![0; packed.len()];
            let mut work = vec![0; packed.len()];
            build_link_with_fields(
                &manager,
                node.public_key(),
                TIMESTAMP,
                b"",
                b"/status",
                &[(FIELD_TICKET, value)],
                &mut out,
                &mut work,
                &mut [0; 16],
                &mut [0; 32],
            )
            .unwrap();
            assert_eq!(out, packed);
            continue;
        }

        let fields: Vec<EncodedField<'_>> = vector["fields"]
            .as_array()
            .unwrap()
            .iter()
            .rev()
            .map(|id| match id.as_u64().unwrap() as u8 {
                FIELD_RESULTS => (FIELD_RESULTS, results.as_slice()),
                id if id == extension_id => (id, extension.as_slice()),
                other => panic!("unexpected field {other}"),
            })
            .collect();
        let (mut built, id) = lite_link(content, &fields).unwrap();
        assert_eq!(id, message_id, "{name}");
        if let Some(stamp) = vector["stamp"].as_str().map(|_| hex(&vector["stamp"])) {
            assert_eq!(vector["python_stamp_validated"], Value::Bool(true));
            if stamp.len() == 16 {
                assert_eq!(ticket_stamp(&ticket, &id).as_slice(), stamp, "{name}");
            } else {
                let cost = vector["stamp_cost"].as_u64().unwrap() as u32;
                let mut workblock = Workblock::new(id, StampKind::Message);
                assert!(workblock.advance(u16::MAX));
                assert!(workblock.value(&stamp.clone().try_into().unwrap()).unwrap() >= cost);
            }
            let n = built.len();
            built.resize(n + 2 + stamp.len(), 0);
            append_recipient_stamp(&mut built, n, &stamp).unwrap();
            stamped += 1;
        }
        assert_eq!(built, packed, "{name}");

        let mut scratch = vec![0; packed.len()];
        let view = parse_link(
            &manager,
            &packed,
            node.public_key(),
            &mut scratch,
            &mut LxmfFieldScratch::new(),
        )
        .unwrap();
        assert_eq!(view.message_id, message_id);
        assert_eq!(
            field_value(view.fields, FIELD_RESULTS),
            Some(results.as_slice())
        );

        if opportunistic {
            let packed_len = built.len();
            built.resize(rns_lite_core::constants::MDU, 0);
            let n = seal_opportunistic(
                &mut built,
                packed_len,
                manager.public_key(),
                target,
                &[0x61; 32],
                &[0x62; 16],
            )
            .unwrap();
            let ring = [&ratchet_private];
            let plaintext = trusted(&MANAGER)
                .decrypt(&built[..n], ratcheted.then_some(&ring[..]), ratcheted)
                .unwrap();
            assert_eq!(plaintext, packed[16..], "{name}");

            let encrypted = hex(&vector["encrypted"]);
            let mut scratch = [0; rns_lite_core::crypto::MAX_ECIES_PLAINTEXT];
            let (view, index) = parse_opportunistic_ratchet(
                &manager,
                &[ratchet_private],
                &encrypted,
                node.public_key(),
                &mut scratch,
                &mut LxmfFieldScratch::new(),
            )
            .unwrap();
            assert_eq!(index, ratcheted.then_some(0), "{name}");
            assert_eq!(view.message_id, message_id);
            assert_eq!(view.content, content);
            assert_eq!(
                field_value(view.fields, FIELD_RESULTS),
                Some(results.as_slice())
            );
        }
    }
    assert_eq!(stamped, 4);
}
