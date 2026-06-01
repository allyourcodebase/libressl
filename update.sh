#!/bin/bash
# This script is for package maintainers to bump the upstream version
# Parameter: New LibreSSL version, without a 'v' prefix
set -euo pipefail

VERSION=$1
URL="https://cdn.openbsd.org/pub/OpenBSD/LibreSSL/libressl-$VERSION.tar.gz"
#URL="https://ftp.fr.openbsd.org/pub/OpenBSD/LibreSSL/libressl-$VERSION.tar.gz"
#URL="https://github.com/libressl/portable/releases/download/v$VERSION/libressl-$VERSION.tar.gz"

# 1. Fetch the new version
HASH=$(zig fetch $URL)
zig fetch --save=libressl $URL

# 2. Re-generate the file lists
cat zig-pkg/$HASH/{crypto,tls,ssl}/Makefile.am* | uv run generate.py | zig fmt --stdin > generated.zig

# 3. Bump the package version
sed "s|\([.]version *= *\).*|\1\"$VERSION\",|" build.zig.zon > tmp.zon
mv tmp.zon build.zig.zon
