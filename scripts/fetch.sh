#!/usr/bin/env bash
# fetch.sh <url> <sha256|blake2b> <hex digest> <dest>
#
# Downloads a pinned test input. Nothing unverified is ever left at <dest>: the
# file is fetched to <dest>.part, hashed, and moved into place only if the
# digest matches. An existing <dest> with the right digest is kept as is, so a
# cached input costs one hash.
#
# Hashing goes through python3's hashlib, the same on Linux and macOS (macOS
# has no b2sum, and its LibreSSL has no BLAKE2b).
set -euo pipefail

if [ $# -ne 4 ]; then
  echo "usage: $0 <url> <sha256|blake2b> <hex digest> <dest>" >&2
  exit 2
fi
URL=$1 ALGO=$2 EXPECTED=$3 DEST=$4

digest() {
  python3 - "$ALGO" "$1" <<'PY'
import hashlib, sys
algo, path = sys.argv[1], sys.argv[2]
h = hashlib.blake2b(digest_size=64) if algo == "blake2b" else hashlib.new(algo)
with open(path, "rb") as f:
    for chunk in iter(lambda: f.read(1 << 20), b""):
        h.update(chunk)
print(h.hexdigest())
PY
}

if [ -f "$DEST" ] && [ "$(digest "$DEST")" = "$EXPECTED" ]; then
  echo "✓ $DEST (pinned $ALGO, cached)"
  exit 0
fi

mkdir -p "$(dirname "$DEST")"
PART="$DEST.part"
echo "↓ $URL"
curl -fL --retry 3 --progress-bar -o "$PART" "$URL"
ACTUAL=$(digest "$PART")
if [ "$ACTUAL" != "$EXPECTED" ]; then
  rm -f -- "$PART"
  echo "✗ $URL: $ALGO $ACTUAL, expected $EXPECTED" >&2
  exit 1
fi
mv -f -- "$PART" "$DEST"
echo "✓ $DEST (pinned $ALGO)"
