#!/usr/bin/env sh
set -eu

./scripts/check-trusted-ref.sh
./scripts/check-rns-lite-ref.sh
cargo metadata --format-version 1 --locked --no-deps >/dev/null
python3 scripts/ci/check_source_release_contract.py
cargo fmt --all --check
cargo fmt --manifest-path api/fixtures/Cargo.toml -- --check
cargo check --workspace --all-targets --locked
cargo check --workspace --target thumbv7em-none-eabihf --locked
cargo check --workspace --target riscv32imc-unknown-none-elf --locked
cargo tree -p lxmf-lite-core --target thumbv7em-none-eabihf -e=no-dev --locked > target/lxmf-lite-core-no-std-tree.txt
if grep -E "getrandom|tokio|bzip2|lxmf-core|rns-transport|rns-interface|serialport|socket2" target/lxmf-lite-core-no-std-tree.txt; then
  echo "forbidden host dependency found in production no_std tree" >&2
  exit 1
fi
cargo clippy --workspace --all-targets --locked -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
cargo test --workspace --locked
cargo check --manifest-path api/fixtures/Cargo.toml --locked
./scripts/check-trusted-ref.sh
./scripts/check-rns-lite-ref.sh
