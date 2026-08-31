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

Incoming message fields can be read; builders currently emit empty fields.
Your firmware supplies identities, entropy, timestamps and buffers, and handles
routing, Link sessions, Resource transfers, storage and retries. This crate does
not run a propagation node or generate stamps, and does not support compression.

## Build and test

Install Rust through `rustup`; the repository selects Rust 1.87 and the
bare-metal check targets. These repositories must be siblings:

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
rns-lite-core = { path = "../rsReticulumLite/crates/rns-lite-core" }
lxmf-lite-core = { path = "../rsLXMFLite/crates/lxmf-lite-core" }
```

Keep both source revisions pinned in your build.
[`RNS_LITE_REF`](RNS_LITE_REF) records the rsReticulumLite revision used here;
[`TRUSTED_REF`](TRUSTED_REF) records the test references.
The crates are distributed from source, not crates.io.

See the [Link-message example](crates/lxmf-lite-core/examples/link_message.rs).
Build API documentation with `cargo doc --workspace --no-deps --open`.

## License

[AGPL-3.0-or-later](LICENSE).
