#!/bin/sh
set -e
EXPECTED="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
curl -L https://downloads.example.com/acme/formatter/releases/latest/download/formatter-linux -o formatter
ACTUAL=$(sha256sum formatter | cut -d' ' -f1)
if [ "$ACTUAL" != "$EXPECTED" ]; then
  echo "checksum mismatch" >&2
  exit 1
fi
chmod +x formatter
./formatter --init
