//! Bounded LXMF message construction and validation for MCU firmware.
//!
//! This crate is unconditionally `no_std` and allocation-free. It owns the
//! message codec only; transport routing, Link sessions, timers, entropy,
//! persistence, and interface I/O remain responsibilities of the embedding
//! runtime and [`rns_lite_core`].

#![no_std]
#![forbid(unsafe_code)]
#![deny(rustdoc::broken_intra_doc_links)]

#[cfg(test)]
extern crate std;

pub mod lxmf;
pub mod propagation;
pub mod stamp;

pub use lxmf::{
    AM_CODEC2_700C, AudioField, EncodedField, FIELD_AUDIO, FIELD_RESULTS, FIELD_TICKET, FieldId,
    LXMF_DEST_LENGTH, LXMF_PACKED_PREFIX, LXMF_SIGNATURE_LENGTH, LxmfError, LxmfFieldScratch,
    LxmfView, MAX_FIELDS, MAX_LXMF_PAYLOAD, MESSAGE_ID_LENGTH, TicketField, audio_field,
    build_link, build_link_with_audio, build_link_with_fields, build_opportunistic,
    build_opportunistic_ratchet_with_fields, build_opportunistic_with_fields,
    build_plaintext_for_parity, packed_len, packed_len_with_audio, packed_len_with_fields,
    parse_link, parse_opportunistic, parse_opportunistic_ratchet_hint, peek_source_opportunistic,
    seal_opportunistic, ticket_field,
};
