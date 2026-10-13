#!/usr/bin/env sh
set -eu

./scripts/check-trusted-ref.sh
./scripts/check-rns-lite-ref.sh
cargo +stable metadata --format-version 1 --locked --no-deps >/dev/null
python3 scripts/check-source.py
cargo +1.87.0 check --lib --locked
cargo +stable fmt --all --check
cargo +stable fmt --manifest-path tests/api/Cargo.toml -- --check
cargo +stable check --workspace --all-targets --locked
cargo +1.87.0 check --workspace --target thumbv7em-none-eabihf --locked
cargo +1.87.0 check --workspace --target riscv32imc-unknown-none-elf --locked
cargo +1.87.0 tree -p lxmf-lite-core --target thumbv7em-none-eabihf -e=no-dev --locked > target/lxmf-lite-core-no-std-tree.txt
if grep -E "getrandom|tokio|bzip2|lxmf-core|rns-transport|rns-interface|serialport|socket2" target/lxmf-lite-core-no-std-tree.txt; then
  echo "forbidden host dependency found in production no_std tree" >&2
  exit 1
fi
cargo +stable clippy --workspace --all-targets --locked -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo +stable doc --workspace --no-deps --locked
cargo +stable test --workspace --locked
cargo +stable check --manifest-path tests/api/Cargo.toml --locked
./scripts/check-trusted-ref.sh
./scripts/check-rns-lite-ref.sh
