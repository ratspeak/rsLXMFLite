# Testing

Run `./scripts/test-matrix.sh` after the setup in the [README](../../README.md).

| Check | Coverage |
| --- | --- |
| Host tests | Plaintext, opportunistic, ratchet, Link, fields and malformed-input behavior. |
| Trusted compatibility | Byte-level packing and bidirectional validation against pinned rsLXMF/rsReticulum sources. |
| Bare-metal builds | `thumbv7em-none-eabihf` and `riscv32imc-unknown-none-elf`. |
| Dependency checks | No host runtime, compression, interface or OS entropy dependencies in the production graph. |
| API fixture | Representative downstream usage in a separate Cargo workspace. |
| Formatting, Clippy and rustdoc | Warnings denied and public documentation links checked. |
| Source checks | Package metadata, source pins, workflow permissions and repository hygiene. |

`./scripts/release-matrix.sh` runs the same checks and requires exact
`TRUSTED_REF` and `RNS_LITE_REF` checkouts. Ordinary development warns on
source drift; release checks fail.

Firmware integrations need their own tests for storage, radio and delivery
behavior.
