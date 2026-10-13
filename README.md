# rsLXMFLite

[![CI](https://github.com/ratspeak/rsLXMFLite/actions/workflows/ci.yml/badge.svg)](https://github.com/ratspeak/rsLXMFLite/actions/workflows/ci.yml)
[![Rust 1.87+](https://img.shields.io/badge/rust-1.87%2B-orange.svg)](https://www.rust-lang.org)
[![License: AGPL-3.0-or-later](https://img.shields.io/badge/license-AGPL--3.0--or--later-blue.svg)](LICENSE)

**LXMF in Rust for microcontrollers.**

`lxmf-lite-core` constructs and validates LXMF messages without allocation or
`std`. It adapts the codec from [rsLXMF](https://github.com/ratspeak/rsLXMF)
and uses [rsReticulumLite](https://github.com/ratspeak/rsReticulumLite) for
Reticulum cryptography and identity handling.

## Scope

The codec builds messages for single-packet (opportunistic) delivery or delivery
over Links and Resources. It validates incoming messages against the sender's
key and intended recipient, and supports current and retained destination ratchets.
Client propagation codecs validate node announcements, append recipient stamps,
encrypt and wrap relay uploads, and decrypt retrieved entries for the ordinary
message validator. Relay selection and durable inbox acknowledgement remain
the firmware's responsibility.

Incoming message fields can be read without allocation. Full-width signed and
unsigned integer IDs are preserved; duplicate outer IDs are rejected. Parsers
require caller-owned `LxmfFieldScratch` (1 KiB), with a maximum of 64 outer
fields and the existing nesting limit of 8. Standard structured-map readers also
limit interpretation to 64 unique keys; malformed optional fields do not affect
the preserved message bytes. Host profiles can be larger, so a valid host message
is not automatically compatible with firmware. The Link/Resource audio
builder writes standard LXMF `[mode, binary]` audio fields covered by the message
signature; text and opportunistic builders retain empty fields. Audio framing is
separate from codec support, playback and application size/duration limits.
Your firmware supplies identities, entropy, timestamps and buffers, and handles
routing, Link sessions, Resource transfers, storage and retries. Resumable stamp
generation and validation stream workblock preparation without allocating the
large workblock. Firmware supplies fresh cryptographic entropy and enforces cost,
iteration and elapsed-time limits. This crate does not run a propagation node
and does not support compression.

## Build and test

Install Rust through `rustup`; the repository selects Rust 1.87 and the
bare-metal check targets for production. Install current stable Rust (1.89 or
newer) for host tests against the full Rust donor crates. The matrix explicitly
separates these toolchains. These repositories must be siblings:

```sh
git clone https://github.com/ratspeak/rsLXMFLite.git
git clone https://github.com/ratspeak/rsReticulumLite.git
git clone https://github.com/ratspeak/rsLXMF.git
git clone https://github.com/ratspeak/rsReticulum.git
cd rsLXMFLite
for refs in RNS_LITE_REF TRUSTED_REF; do
  while read -r repository revision; do
    git -C "../$repository" checkout --detach "$revision"
  done < "$refs"
done
./scripts/test-matrix.sh
```

The full Rust repositories are test references, not firmware dependencies.
The matrix runs host tests, ARM/RISC-V checks, Clippy, rustdoc and byte-level
compatibility tests against those references.

For a firmware project alongside the two Lite checkouts:

```toml
[dependencies]
rns-lite-core = { path = "../rsReticulumLite" }
lxmf-lite-core = { path = "../rsLXMFLite" }
```

Keep both source revisions pinned in your build.
[`RNS_LITE_REF`](RNS_LITE_REF) records the rsReticulumLite revision used here;
[`TRUSTED_REF`](TRUSTED_REF) records the test references.
The crates are distributed from source, not crates.io.

See the [Link-message example](examples/link_message.rs).
Build API documentation with `cargo doc --workspace --no-deps --open`.

## License

[AGPL-3.0-or-later](LICENSE).
