# Codec scope and ownership

`lxmf-lite-core` constructs and validates bounded LXMF messages. It does not
run a router or own a delivery queue.

## Supported

- Opportunistic single-frame messages, including destination ratchets and
  retained-ratchet decryption.
- Packed Link/Resource messages after transport decryption or reassembly.
- Message IDs, signature checks and destination/source-key binding.
- Bounded MessagePack parsing with lazy field access.

The caller supplies identity, secure entropy, timestamp, output and scratch memory.
See the [Link-message example](../crates/lxmf-lite-core/examples/link_message.rs).

## Host responsibilities

Reticulum routing, interfaces, Link sessions, Resource scheduling and
persistent storage belong to the embedding runtime. This crate does not
implement propagation-node operation, stamp generation, compression,
allocation, clocks or random-number generation.

Builders currently emit empty fields; parsers accept supported bounded field
values. Supporting a new message shape requires explicit buffer limits and
compatibility tests, not only a parser change.
