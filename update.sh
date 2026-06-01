#!/bin/bash
# Parameter: New libreSSL version, without a 'v' prefix
set -euo pipefail

VERSION=$1
URL="https://github.com/libressl/portable/releases/download/v$VERSION/libressl-$VERSION.tar.gz"

HASH=$(zig fetch $URL)
zig fetch --save=libressl $URL

cat zig-pkg/$HASH/{crypto,tls}/Makefile.am* | uv run generate.py | zig fmt --stdin > generated.zig
