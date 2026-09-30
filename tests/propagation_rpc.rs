use lxmf_lite_core::propagation::*;
use rmpv::Value;
use rns_link::link::Link;

fn pack(value: Value) -> Vec<u8> {
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &value).unwrap();
    out
}

#[test]
fn get_requests_have_trusted_typed_bodies_and_decimal_limits() {
    let id = [0x6A; 32];
    for (request, expected) in [
        (GetRequest::List, Value::Array(vec![Value::Nil, Value::Nil])),
        (
            GetRequest::Fetch {
                transient_id: &id,
                limit_bytes: 3500,
            },
            Value::Array(vec![
                Value::Array(vec![Value::Binary(id.to_vec())]),
                Value::Array(vec![]),
                Value::F64(3.5),
            ]),
        ),
        (
            GetRequest::Purge {
                durable_transient_id: &id,
            },
            Value::Array(vec![
                Value::Nil,
                Value::Array(vec![Value::Binary(id.to_vec())]),
            ]),
        ),
    ] {
        let mut out = [0; 96];
        let n = build_get_request(12345.25, request, &mut out).unwrap();
        let (_, path, timestamp, body) = Link::parse_request(&out[..n]).unwrap();
        assert_eq!(path, rns_crypto::sha::truncated_hash(b"/get"));
        assert_eq!(timestamp, 12345.25);
        assert_eq!(body, pack(expected));
        let mut short = [0xBB; 96];
        assert!(build_get_request(timestamp, request, &mut short[..n - 1]).is_err());
        assert_eq!(short, [0xBB; 96]);
    }
    for timestamp in [f64::NAN, f64::INFINITY, -1.0] {
        assert!(build_get_request(timestamp, GetRequest::List, &mut [0; 96]).is_err());
    }
    assert!(
        build_get_request(
            0.0,
            GetRequest::Fetch {
                transient_id: &id,
                limit_bytes: 0
            },
            &mut [0; 96]
        )
        .is_err()
    );
}

#[test]
fn matched_trusted_replies_are_borrowed_and_all_list_items_validated() {
    let request_id = [0x92; 16];
    let id = [0x51; 32];
    let list = pack(Value::Array(vec![Value::Binary(id.to_vec()); 106]));
    let envelope = Link::pack_response(&request_id, &list).unwrap();
    let data = response_data(&envelope, &request_id).unwrap();
    assert_eq!(data, list);
    assert_eq!(first_available(data).unwrap(), (Some(id), 106));
    assert!(response_data(&envelope, &[0; 16]).is_err());
    for n in 0..envelope.len() {
        assert!(response_data(&envelope[..n], &request_id).is_err());
    }
    let mut extra = envelope.clone();
    extra.push(0);
    assert!(response_data(&extra, &request_id).is_err());
    extra = envelope;
    extra[0] = 0x93;
    extra.push(0xc0);
    assert!(response_data(&extra, &request_id).is_err());
    let malformed_last = pack(Value::Array(vec![
        Value::Binary(id.to_vec()),
        Value::Binary(vec![0; 31]),
    ]));
    assert!(first_available(&malformed_last).is_err());
    assert!(first_available(&[0xF0]).is_err()); // node error is not an empty inbox
    assert_eq!(first_available(&[0x90]).unwrap(), (None, 0));
}

#[test]
fn fetch_accepts_only_one_entry_and_does_not_treat_node_errors_as_success() {
    let bytes = [0x73; 512];
    let data = pack(Value::Array(vec![Value::Binary(bytes.to_vec())]));
    let envelope = Link::pack_response(&[3; 16], &data).unwrap();
    assert_eq!(
        fetched_message(response_data(&envelope, &[3; 16]).unwrap()).unwrap(),
        Some(bytes.as_slice())
    );
    assert_eq!(fetched_message(&[0x90]).unwrap(), None);
    for invalid in [
        vec![0xc0],
        vec![0xf0],
        vec![0x91, 0xc0],
        pack(Value::Array(vec![Value::Binary(bytes.to_vec()); 2])),
    ] {
        assert!(fetched_message(&invalid).is_err());
    }
}
