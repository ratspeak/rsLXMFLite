#!/usr/bin/env sh
# Production-dependency tripwire. Warning mode is convenient for contributors;
# CI and release-readiness runs use --strict for reproducible source selection.
set -eu
cd "$(dirname "$0")/.."

strict=0
case "${1:-}" in
  "") ;;
  --strict) strict=1 ;;
  *) echo "usage: $0 [--strict]" >&2; exit 2 ;;
esac

read -r name ref < RNS_LITE_REF
head="$(git -C "../$name" rev-parse HEAD 2>/dev/null || echo MISSING)"
if [ "$head" = "$ref" ]; then
  echo "rns-lite dependency current (RNS_LITE_REF)"
  exit 0
fi

echo "!! RNS-LITE DRIFT: ../$name is at $head" >&2
echo "!!   dependency last qualified at $ref (RNS_LITE_REF)" >&2
echo "!!   review the changes and run the full matrix before updating the pin" >&2
[ "$strict" -eq 1 ] && exit 1
exit 0
