//! Cross-checks the lite LXMF codec against the trusted full-Rust stack: `lxmf-core`
//! (message codec, audited byte-exact vs Python LXMF 1.0.1) and `rns-identity` (ECIES).
//! Both directions: lite-built messages must validate in the trusted stack, and
//! trusted-built (random-ephemeral) blobs must decrypt + verify in lite.

use lxmf_core::constants::DeliveryMethod;
use lxmf_core::message::{LxMessage, LxMessageDraft};
use lxmf_lite_core::lxmf::{
    build_opportunistic, build_opportunistic_ratchet, build_plaintext_for_parity,
    parse_opportunistic, parse_opportunistic_ratchet, parse_opportunistic_ratchet_hint,
    peek_source_opportunistic_ratchet,
};
use rns_lite_core::crypto::MAX_ECIES_PLAINTEXT;
use rns_lite_core::identity::LocalIdentity;
use rns_lite_core::ratchet::ratchet_public_bytes;

const SOURCE_PRV: [u8; 64] = {
    let mut k = [0u8; 64];
    let mut i = 0;
    while i < 64 {
        k[i] = i as u8;
        i += 1;
    }
    k
};
const RECIPIENT_PRV: [u8; 64] = {
    let mut k = [0u8; 64];
    let mut i = 0;
    while i < 64 {
        k[i] = (i as u8).wrapping_add(0x40);
        i += 1;
    }
    k
};
const TIMESTAMP: f64 = 1234567890.5;

fn trusted_identity(prv: &[u8; 64]) -> rns_identity::identity::Identity {
    rns_identity::identity::Identity::from_private_key(prv).unwrap()
}

fn trusted_delivery_hash(identity: &rns_identity::identity::Identity) -> [u8; 16] {
    rns_identity::destination::Destination::hash_from_name_and_identity(
        "lxmf.delivery",
        Some(&identity.hash),
    )
}

fn trusted_message() -> LxMessage {
    let source = trusted_identity(&SOURCE_PRV);
    let recipient = trusted_identity(&RECIPIENT_PRV);
    let mut msg = LxMessageDraft::new(
        trusted_delivery_hash(&recipient),
        trusted_delivery_hash(&source),
        "Hi",
        "hello world",
        DeliveryMethod::Opportunistic,
    )
    .unwrap();
    msg.set_timestamp(TIMESTAMP).unwrap();
    let seed: [u8; 32] = SOURCE_PRV[32..].try_into().unwrap();
    msg.sign(&rns_crypto::ed25519::Ed25519PrivateKey::from_bytes(&seed))
        .unwrap()
        .finalize(None)
        .unwrap()
}

#[test]
fn exact_size_and_direct_wire_match_trusted_encoder() {
    let source = LocalIdentity::from_private_key(&SOURCE_PRV);
    let recipient = LocalIdentity::from_private_key(&RECIPIENT_PRV);
    for length in [0, 1, 31, 32, 255, 256, 3546, 3547, 65535, 65536] {
        let title = "t".repeat(length);
        let content = "c".repeat(length / 2);
        let mut trusted = LxMessageDraft::new(
            recipient.lxmf_delivery_hash(),
            source.lxmf_delivery_hash(),
            &title,
            &content,
            DeliveryMethod::Direct,
        )
        .unwrap();
        trusted.set_timestamp(TIMESTAMP).unwrap();
        let seed: [u8; 32] = SOURCE_PRV[32..].try_into().unwrap();
        let trusted = trusted
            .sign(&rns_crypto::ed25519::Ed25519PrivateKey::from_bytes(&seed))
            .unwrap()
            .finalize(None)
            .unwrap();
        let size = lxmf_lite_core::packed_len(title.len(), content.len()).unwrap();
        assert_eq!(size, trusted.packed_len().unwrap());
        let mut packed = vec![0; size];
        let mut scratch = vec![0; size];
        let mut destination = [0; 16];
        let mut message_id = [0; 32];
        assert_eq!(
            lxmf_lite_core::build_link(
                &source,
                recipient.public_key(),
                TIMESTAMP,
                title.as_bytes(),
                content.as_bytes(),
                &mut packed,
                &mut scratch,
                &mut destination,
                &mut message_id
            )
            .unwrap(),
            size
        );
        assert_eq!(packed, trusted.pack().unwrap());
    }
}

// The single-frame capacity is LXMF 1.2.0's opportunistic limit (LXMessage.py:64-79): content the
// trusted router keeps opportunistic fits one packet, and one byte more falls back to direct.
#[test]
fn single_frame_capacity_is_the_trusted_opportunistic_limit() {
    use lxmf_core::constants::{ENCRYPTED_PACKET_MAX_CONTENT, STRUCT_OVERHEAD, TIMESTAMP_SIZE};
    use lxmf_lite_core::MAX_LXMF_PAYLOAD;

    assert_eq!(
        MAX_LXMF_PAYLOAD,
        ENCRYPTED_PACKET_MAX_CONTENT + TIMESTAMP_SIZE + STRUCT_OVERHEAD
    );
    let source = LocalIdentity::from_private_key(&SOURCE_PRV);
    let recipient = LocalIdentity::from_private_key(&RECIPIENT_PRV);
    for (content_size, fits) in [
        (ENCRYPTED_PACKET_MAX_CONTENT, true),
        (ENCRYPTED_PACKET_MAX_CONTENT + 1, false),
    ] {
        // With an empty title and no fields, Python's content size is the content length.
        let content = vec![b'x'; content_size];
        let mut out = [0u8; rns_lite_core::constants::MDU];
        let built = build_opportunistic(
            &source,
            recipient.public_key(),
            TIMESTAMP,
            b"",
            &content,
            &[0x31; 32],
            &[0x32; 16],
            &mut out,
            &mut [0; 16],
            &mut [0; 32],
        );
        assert_eq!(built.is_ok(), fits, "{content_size} bytes");
    }
}

// The lite plaintext builder must be byte-identical to the trusted lxmf-core pack()
// (same msgpack payload, hash, and deterministic Ed25519 signature).
#[test]
fn lite_plaintext_byte_exact_vs_trusted_lxmf_core() {
    let lite_source = LocalIdentity::from_private_key(&SOURCE_PRV);
    let lite_recipient = LocalIdentity::from_private_key(&RECIPIENT_PRV);
    let mut pt = [0u8; MAX_ECIES_PLAINTEXT];
    let mut dest = [0u8; 16];
    let mut mid = [0u8; 32];
    let n = build_plaintext_for_parity(
        &lite_source,
        lite_recipient.public_key(),
        TIMESTAMP,
        b"Hi",
        b"hello world",
        &mut pt,
        &mut dest,
        &mut mid,
    )
    .unwrap();

    let msg = trusted_message();
    let trusted_packed = msg.pack().unwrap();
    // trusted pack() = dest_hash || (lite plaintext: source_hash || signature || payload)
    assert_eq!(&trusted_packed[..16], &dest);
    assert_eq!(&trusted_packed[16..], &pt[..n]);
    assert_eq!(msg.message_id(), mid);
}

// A message packed + ECIES-encrypted by the trusted stack (random ephemeral) must
// decrypt and signature-validate in the lite parser.
#[test]
fn lite_parses_trusted_lxmf_core_opportunistic_blob() {
    let recipient_trusted = trusted_identity(&RECIPIENT_PRV);
    let msg = trusted_message();
    let blob = msg
        .pack_opportunistic_encrypted(|pt| {
            recipient_trusted
                .encrypt(pt, None)
                .map_err(|e| lxmf_core::message::MessageError::PackFailed(e.to_string()))
        })
        .unwrap();

    let lite_source = LocalIdentity::from_private_key(&SOURCE_PRV);
    let lite_recipient = LocalIdentity::from_private_key(&RECIPIENT_PRV);
    let mut scratch = [0u8; MAX_ECIES_PLAINTEXT];
    let view = parse_opportunistic(
        &lite_recipient,
        &blob,
        lite_source.public_key(),
        &mut scratch,
        &mut lxmf_lite_core::LxmfFieldScratch::new(),
    )
    .unwrap();
    assert_eq!(view.title, b"Hi");
    assert_eq!(view.content, b"hello world");
    assert_eq!(view.timestamp, TIMESTAMP);
    assert_eq!(view.message_id, msg.message_id());
    assert_eq!(view.source_hash, lite_source.lxmf_delivery_hash());
}

// A lite-built opportunistic blob must decrypt via the trusted rns-identity ECIES and
// unpack + signature-verify in the trusted lxmf-core.
#[test]
fn trusted_lxmf_core_validates_lite_built_message() {
    let lite_source = LocalIdentity::from_private_key(&SOURCE_PRV);
    let lite_recipient = LocalIdentity::from_private_key(&RECIPIENT_PRV);
    let mut out = [0u8; 600];
    let mut dest = [0u8; 16];
    let mut mid = [0u8; 32];
    let n = build_opportunistic(
        &lite_source,
        lite_recipient.public_key(),
        TIMESTAMP,
        b"Hi",
        b"hello world",
        &[0x33; 32],
        &[0x44; 16],
        &mut out,
        &mut dest,
        &mut mid,
    )
    .unwrap();

    let recipient_trusted = trusted_identity(&RECIPIENT_PRV);
    let plaintext = recipient_trusted.decrypt(&out[..n], None, false).unwrap();
    // Opportunistic strips the leading dest hash; re-prepend it for unpack().
    let mut packed = Vec::with_capacity(16 + plaintext.len());
    packed.extend_from_slice(&dest);
    packed.extend_from_slice(&plaintext);
    let msg = LxMessage::unpack(&packed).unwrap();

    let source_trusted = trusted_identity(&SOURCE_PRV);
    let ed_pub: [u8; 32] = source_trusted.get_public_key()[32..].try_into().unwrap();
    let verify_key = rns_crypto::ed25519::Ed25519PublicKey::from_bytes(&ed_pub).unwrap();
    assert!(msg.verify_signature(&verify_key));
    assert_eq!(msg.title_text(), "Hi");
    assert_eq!(msg.content_text(), "hello world");
    assert_eq!(msg.timestamp(), TIMESTAMP);
    assert_eq!(msg.message_id(), mid);
    assert_eq!(msg.source_hash(), lite_source.lxmf_delivery_hash());
    assert_eq!(
        msg.destination_hash(),
        trusted_delivery_hash(&recipient_trusted)
    );
}

// The lite link/resource builder (FULL packed, no ECIES) must be byte-identical to the
// trusted lxmf-core pack() — the DIRECT wire form Python sends over a link.
#[test]
fn lite_build_link_byte_exact_vs_trusted_pack() {
    let lite_source = LocalIdentity::from_private_key(&SOURCE_PRV);
    let lite_recipient = LocalIdentity::from_private_key(&RECIPIENT_PRV);
    let mut out = [0u8; 600];
    let mut scratch = [0u8; 600];
    let mut dest = [0u8; 16];
    let mut mid = [0u8; 32];
    let n = lxmf_lite_core::lxmf::build_link(
        &lite_source,
        lite_recipient.public_key(),
        TIMESTAMP,
        b"Hi",
        b"hello world",
        &mut out,
        &mut scratch,
        &mut dest,
        &mut mid,
    )
    .unwrap();

    let msg = trusted_message();
    let trusted_packed = msg.pack().unwrap();
    assert_eq!(&out[..n], &trusted_packed[..]);
    assert_eq!(msg.message_id(), mid);
}

// A trusted-built message with NON-EMPTY 1.0.1-standard fields (0x30 reply bin + 0x40
// reaction dict) must decrypt + signature-validate in lite, and the raw fields element
// must be lazily decodable via field_value/value_as_bytes.
#[test]
fn lite_parses_trusted_message_with_standard_fields() {
    use lxmf_lite_core::lxmf::{field_value, value_as_bytes};

    const FIELD_REPLY_TO: u8 = 0x30;
    const FIELD_REACTION: u8 = 0x40;
    let reply_to = [0xE7u8; 32];
    // msgpack {"e": "👍"} — a complete encoded value, as Python packs reaction dicts.
    let reaction: &[u8] = &[0x81, 0xa1, b'e', 0xa4, 0xf0, 0x9f, 0x91, 0x8d];

    let source = trusted_identity(&SOURCE_PRV);
    let recipient = trusted_identity(&RECIPIENT_PRV);
    let mut msg = LxMessageDraft::new(
        trusted_delivery_hash(&recipient),
        trusted_delivery_hash(&source),
        "Hi",
        "hello world",
        DeliveryMethod::Opportunistic,
    )
    .unwrap();
    msg.set_timestamp(TIMESTAMP).unwrap();
    msg.set_field(FIELD_REPLY_TO, reply_to.to_vec()).unwrap();
    msg.set_msgpack_field(FIELD_REACTION, reaction.to_vec())
        .unwrap();
    let seed: [u8; 32] = SOURCE_PRV[32..].try_into().unwrap();
    let msg = msg
        .sign(&rns_crypto::ed25519::Ed25519PrivateKey::from_bytes(&seed))
        .unwrap()
        .finalize(None)
        .unwrap();

    let recipient_trusted = trusted_identity(&RECIPIENT_PRV);
    let blob = msg
        .pack_opportunistic_encrypted(|pt| {
            recipient_trusted
                .encrypt(pt, None)
                .map_err(|e| lxmf_core::message::MessageError::PackFailed(e.to_string()))
        })
        .unwrap();

    let lite_source = LocalIdentity::from_private_key(&SOURCE_PRV);
    let lite_recipient = LocalIdentity::from_private_key(&RECIPIENT_PRV);
    let mut scratch = [0u8; MAX_ECIES_PLAINTEXT];
    let view = parse_opportunistic(
        &lite_recipient,
        &blob,
        lite_source.public_key(),
        &mut scratch,
        &mut lxmf_lite_core::LxmfFieldScratch::new(),
    )
    .unwrap();
    assert_eq!(view.title, b"Hi");
    assert_eq!(view.content, b"hello world");
    assert_eq!(view.message_id, msg.message_id());
    assert_eq!(
        field_value(view.fields, FIELD_REPLY_TO).and_then(value_as_bytes),
        Some(&reply_to[..])
    );
    assert_eq!(field_value(view.fields, FIELD_REACTION), Some(reaction));
    assert_eq!(field_value(view.fields, 0x31), None);

    // Same message over the DIRECT/link wire form.
    let trusted_packed = msg.pack().unwrap();
    let mut scratch2 = [0u8; 600];
    let view2 = lxmf_lite_core::lxmf::parse_link(
        &lite_recipient,
        &trusted_packed,
        lite_source.public_key(),
        &mut scratch2,
        &mut lxmf_lite_core::LxmfFieldScratch::new(),
    )
    .unwrap();
    assert_eq!(view2.message_id, msg.message_id());
    assert_eq!(field_value(view2.fields, FIELD_REACTION), Some(reaction));
}

// A trusted-packed (Python-parity) full message must validate in the lite link parser.
#[test]
fn lite_parse_link_validates_trusted_packed() {
    let msg = trusted_message();
    let trusted_packed = msg.pack().unwrap();

    let lite_source = LocalIdentity::from_private_key(&SOURCE_PRV);
    let lite_recipient = LocalIdentity::from_private_key(&RECIPIENT_PRV);
    let mut scratch = [0u8; 600];
    let view = lxmf_lite_core::lxmf::parse_link(
        &lite_recipient,
        &trusted_packed,
        lite_source.public_key(),
        &mut scratch,
        &mut lxmf_lite_core::LxmfFieldScratch::new(),
    )
    .unwrap();
    assert_eq!(view.title, b"Hi");
    assert_eq!(view.content, b"hello world");
    assert_eq!(view.timestamp, TIMESTAMP);
    assert_eq!(view.message_id, msg.message_id());
    assert_eq!(view.source_hash, lite_source.lxmf_delivery_hash());
}

// A trusted-side sender that learned our announced ratchet encrypts to it; the lite ring
// must decrypt (newest-first, correct index) and the peek path must work for source recall.
#[test]
fn lite_parses_trusted_ratcheted_opportunistic_blob() {
    let ratchet_priv = [0x77u8; 32];
    let newer_priv = [0x78u8; 32];
    // Ring: index 0 = newer key, index 1 = the one the peer knows (stale-but-retained).
    let ring = [newer_priv, ratchet_priv];
    let announced_pub = ratchet_public_bytes(&ratchet_priv);

    let recipient_trusted = trusted_identity(&RECIPIENT_PRV);
    let msg = trusted_message();
    let blob = msg
        .pack_opportunistic_encrypted(|pt| {
            recipient_trusted
                .encrypt(pt, Some(&announced_pub))
                .map_err(|e| lxmf_core::message::MessageError::PackFailed(e.to_string()))
        })
        .unwrap();

    let lite_source = LocalIdentity::from_private_key(&SOURCE_PRV);
    let lite_recipient = LocalIdentity::from_private_key(&RECIPIENT_PRV);

    let mut scratch = [0u8; MAX_ECIES_PLAINTEXT];
    let (peeked, peek_which) =
        peek_source_opportunistic_ratchet(&lite_recipient, &ring, &blob, &mut scratch).unwrap();
    assert_eq!(peeked, lite_source.lxmf_delivery_hash());
    assert_eq!(peek_which, Some(1));

    let view = parse_opportunistic_ratchet_hint(
        &lite_recipient,
        &ring,
        peek_which,
        &blob,
        lite_source.public_key(),
        &mut scratch,
        &mut lxmf_lite_core::LxmfFieldScratch::new(),
    )
    .unwrap();
    assert_eq!(view.title, b"Hi");
    assert_eq!(view.content, b"hello world");
    assert_eq!(view.message_id, msg.message_id());

    // A base-key blob still parses through the ratchet API with the fallback (never enforced).
    let base_blob = trusted_message()
        .pack_opportunistic_encrypted(|pt| {
            recipient_trusted
                .encrypt(pt, None)
                .map_err(|e| lxmf_core::message::MessageError::PackFailed(e.to_string()))
        })
        .unwrap();
    let (base_source, base_hint) =
        peek_source_opportunistic_ratchet(&lite_recipient, &ring, &base_blob, &mut scratch)
            .unwrap();
    assert_eq!(base_source, lite_source.lxmf_delivery_hash());
    assert_eq!(base_hint, None);
    let base_view = parse_opportunistic_ratchet_hint(
        &lite_recipient,
        &ring,
        base_hint,
        &base_blob,
        lite_source.public_key(),
        &mut scratch,
        &mut lxmf_lite_core::LxmfFieldScratch::new(),
    )
    .unwrap();
    assert_eq!(base_view.content, b"hello world");

    // The hint is authoritative: a wrong in-range index, a base-key hint for a
    // ratcheted frame, and an unchecked out-of-range value all fail without a
    // fallback scan that could hide a corrupt C/flash value.
    for bad_hint in [Some(0), None, Some(ring.len())] {
        assert_eq!(
            parse_opportunistic_ratchet_hint(
                &lite_recipient,
                &ring,
                bad_hint,
                &blob,
                lite_source.public_key(),
                &mut scratch,
                &mut lxmf_lite_core::LxmfFieldScratch::new()
            ),
            Err(lxmf_lite_core::lxmf::LxmfError::Crypto)
        );
    }
}

// A lite-built blob encrypted to a peer's announced ratchet must decrypt via the trusted
// rns-identity retained-ratchet path and unpack + signature-verify in the trusted lxmf-core.
#[test]
fn trusted_validates_lite_ratcheted_built_message() {
    let peer_ratchet_priv = [0x79u8; 32];
    let peer_ratchet_pub = ratchet_public_bytes(&peer_ratchet_priv);

    let lite_source = LocalIdentity::from_private_key(&SOURCE_PRV);
    let lite_recipient = LocalIdentity::from_private_key(&RECIPIENT_PRV);
    let mut out = [0u8; 600];
    let mut dest = [0u8; 16];
    let mut mid = [0u8; 32];
    let n = build_opportunistic_ratchet(
        &lite_source,
        lite_recipient.public_key(),
        Some(&peer_ratchet_pub),
        TIMESTAMP,
        b"Hi",
        b"hello world",
        &[0x33; 32],
        &[0x44; 16],
        &mut out,
        &mut dest,
        &mut mid,
    )
    .unwrap();

    let recipient_trusted = trusted_identity(&RECIPIENT_PRV);
    // Base-key decrypt must FAIL (it went to the ratchet), retained-ratchet decrypt succeeds.
    assert!(recipient_trusted.decrypt(&out[..n], None, false).is_err());
    let plaintext = recipient_trusted
        .decrypt(&out[..n], Some(&[&peer_ratchet_priv]), false)
        .unwrap();
    let mut packed = Vec::with_capacity(16 + plaintext.len());
    packed.extend_from_slice(&dest);
    packed.extend_from_slice(&plaintext);
    let msg = LxMessage::unpack(&packed).unwrap();

    let source_trusted = trusted_identity(&SOURCE_PRV);
    let ed_pub: [u8; 32] = source_trusted.get_public_key()[32..].try_into().unwrap();
    let verify_key = rns_crypto::ed25519::Ed25519PublicKey::from_bytes(&ed_pub).unwrap();
    assert!(msg.verify_signature(&verify_key));
    assert_eq!(msg.message_id(), mid);
    assert_eq!(msg.source_hash(), lite_source.lxmf_delivery_hash());
}

// In-crate ratcheted round-trip: build-to-ratchet -> ring parse; unknown-target fails closed.
#[test]
fn ratcheted_roundtrip_reports_ring_index_and_fails_closed_on_unknown() {
    let lite_source = LocalIdentity::from_private_key(&SOURCE_PRV);
    let lite_recipient = LocalIdentity::from_private_key(&RECIPIENT_PRV);
    let target_priv = [0x7Au8; 32];
    let ring = [target_priv];

    let mut out = [0u8; 600];
    let mut dest = [0u8; 16];
    let mut mid = [0u8; 32];
    let n = build_opportunistic_ratchet(
        &lite_source,
        lite_recipient.public_key(),
        Some(&ratchet_public_bytes(&target_priv)),
        TIMESTAMP,
        b"Hi",
        b"ring roundtrip",
        &[0x55; 32],
        &[0x66; 16],
        &mut out,
        &mut dest,
        &mut mid,
    )
    .unwrap();

    let mut scratch = [0u8; MAX_ECIES_PLAINTEXT];
    let (view, which) = parse_opportunistic_ratchet(
        &lite_recipient,
        &ring,
        &out[..n],
        lite_source.public_key(),
        &mut scratch,
        &mut lxmf_lite_core::LxmfFieldScratch::new(),
    )
    .unwrap();
    assert_eq!(which, Some(0));
    assert_eq!(view.content, b"ring roundtrip");

    // Encrypted to a ratchet the recipient never had: every key fails, error is uniform.
    let n = build_opportunistic_ratchet(
        &lite_source,
        lite_recipient.public_key(),
        Some(&ratchet_public_bytes(&[0x7Bu8; 32])),
        TIMESTAMP,
        b"Hi",
        b"lost key",
        &[0x57; 32],
        &[0x68; 16],
        &mut out,
        &mut dest,
        &mut mid,
    )
    .unwrap();
    assert!(
        parse_opportunistic_ratchet(
            &lite_recipient,
            &ring,
            &out[..n],
            lite_source.public_key(),
            &mut scratch,
            &mut lxmf_lite_core::LxmfFieldScratch::new()
        )
        .is_err()
    );
}

#[test]
fn full_width_fields_and_embedded_count_profile_match_trusted_donor() {
    use lxmf_lite_core::lxmf::{FieldId, field_value, field_value_id};
    use lxmf_lite_core::{LxmfError, LxmfFieldScratch};
    let source = LocalIdentity::from_private_key(&SOURCE_PRV);
    let recipient = LocalIdentity::from_private_key(&RECIPIENT_PRV);
    let key =
        rns_crypto::ed25519::Ed25519PrivateKey::from_bytes(&SOURCE_PRV[32..].try_into().unwrap());
    let make = || {
        let mut draft = LxMessageDraft::new(
            recipient.lxmf_delivery_hash(),
            source.lxmf_delivery_hash(),
            "",
            "",
            DeliveryMethod::Direct,
        )
        .unwrap();
        draft.set_timestamp(TIMESTAMP).unwrap();
        draft
    };
    let mut draft = make();
    let ids = [
        i128::from(i64::MIN),
        -1,
        0,
        255,
        256,
        0x105,
        0x10c,
        i128::from(i64::MAX),
        i128::from(i64::MAX) + 1,
        i128::from(u64::MAX),
    ];
    for id in ids {
        draft
            .set_field(
                lxmf_core::message::FieldId::try_from(id).unwrap(),
                vec![0x42],
            )
            .unwrap();
    }
    let frozen = draft.sign(&key).unwrap().finalize(None).unwrap();
    let mut scratch = vec![0; frozen.wire_bytes().len()];
    let mut fields = LxmfFieldScratch::new();
    let view = lxmf_lite_core::parse_link(
        &recipient,
        frozen.wire_bytes(),
        source.public_key(),
        &mut scratch,
        &mut fields,
    )
    .unwrap();
    for id in ids {
        assert_eq!(
            field_value_id(view.fields, FieldId::try_from(id).unwrap()),
            Some(&[0xc4, 1, 0x42][..])
        );
    }
    assert_eq!(field_value(view.fields, 5), None);
    assert_eq!(field_value(view.fields, 12), None);
    for count in [64u8, 65] {
        let mut draft = make();
        for key in 0..count {
            draft.set_msgpack_field(key, vec![0xc0]).unwrap();
        }
        let frozen = draft.sign(&key).unwrap().finalize(None).unwrap();
        // Host-valid; admission to the embedded profile is independent of wire validity.
        assert!(LxMessage::unpack(frozen.wire_bytes()).is_ok());
        let mut scratch = vec![0; frozen.wire_bytes().len()];
        let direct = lxmf_lite_core::parse_link(
            &recipient,
            frozen.wire_bytes(),
            source.public_key(),
            &mut scratch,
            &mut fields,
        );
        assert_eq!(
            direct.map(|_| ()),
            if count == 64 {
                Ok(())
            } else {
                Err(LxmfError::TooManyFields)
            }
        );
        let encrypted = trusted_identity(&RECIPIENT_PRV)
            .encrypt(&frozen.wire_bytes()[16..], None)
            .unwrap();
        let mut scratch = [0; MAX_ECIES_PLAINTEXT];
        let packet = parse_opportunistic(
            &recipient,
            &encrypted,
            source.public_key(),
            &mut scratch,
            &mut fields,
        );
        assert_eq!(
            packet.map(|_| ()),
            if count == 64 {
                Ok(())
            } else {
                Err(LxmfError::TooManyFields)
            }
        );
    }
}

#[test]
fn duplicate_full_width_ids_are_rejected_before_signature_at_both_entrypoints() {
    use lxmf_lite_core::{LxmfError, LxmfFieldScratch};
    let source = LocalIdentity::from_private_key(&SOURCE_PRV);
    let recipient = LocalIdentity::from_private_key(&RECIPIENT_PRV);
    // Raw signed fixture deliberately bypasses the donor's duplicate-preventing draft.
    let mut packed = trusted_message().wire_bytes().to_vec();
    assert_eq!(packed.pop(), Some(0x80));
    packed.extend_from_slice(&[0x82, 1, 0xc0, 0xd1, 0, 1, 0xc0]);
    let mut signed = packed[..32].to_vec();
    signed.extend_from_slice(&packed[96..]);
    let id = rns_crypto::sha::sha256(&signed);
    signed.extend_from_slice(&id);
    packed[32..96].copy_from_slice(&source.sign(&signed));
    let mut fields = LxmfFieldScratch::new();
    let mut scratch = vec![0; packed.len()];
    assert_eq!(
        lxmf_lite_core::parse_link(
            &recipient,
            &packed,
            source.public_key(),
            &mut scratch,
            &mut fields
        ),
        Err(LxmfError::DuplicateField)
    );
    let encrypted = trusted_identity(&RECIPIENT_PRV)
        .encrypt(&packed[16..], None)
        .unwrap();
    let mut scratch = [0; MAX_ECIES_PLAINTEXT];
    assert_eq!(
        parse_opportunistic(
            &recipient,
            &encrypted,
            source.public_key(),
            &mut scratch,
            &mut fields
        ),
        Err(LxmfError::DuplicateField)
    );
}
