#!/usr/bin/env sh
set -eu

./scripts/check-trusted-ref.sh
./scripts/check-rns-lite-ref.sh
cargo +1.96.0 metadata --format-version 1 --locked --no-deps >/dev/null
python3 scripts/check-source.py
cargo +1.87.0 check --lib --locked
cargo +1.96.0 fmt --all --check
cargo +1.96.0 fmt --manifest-path tests/api/Cargo.toml -- --check
cargo +1.96.0 check --workspace --all-targets --locked
cargo +1.87.0 check --workspace --target thumbv7em-none-eabihf --locked
cargo +1.87.0 check --workspace --target riscv32imc-unknown-none-elf --locked
cargo +1.87.0 tree -p lxmf-lite-core --target thumbv7em-none-eabihf -e=no-dev --locked > target/lxmf-lite-core-no-std-tree.txt
if grep -E "getrandom|tokio|bzip2|lxmf-core|rns-transport|rns-interface|serialport|socket2" target/lxmf-lite-core-no-std-tree.txt; then
  echo "forbidden host dependency found in production no_std tree" >&2
  exit 1
fi
cargo +1.96.0 clippy --workspace --all-targets --locked -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo +1.96.0 doc --workspace --no-deps --locked
cargo +1.96.0 test --workspace --locked
cargo +1.96.0 check --manifest-path tests/api/Cargo.toml --locked
./scripts/check-trusted-ref.sh
./scripts/check-rns-lite-ref.sh
