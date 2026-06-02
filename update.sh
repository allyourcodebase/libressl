#!/bin/bash

# This script is for package maintainers to bump the upstream version
#
# 1st parameter: New LibreSSL version (without a 'v' prefix)
# 2nd parameter, optional: Python invocation command (e.g. 'python3', 'uv run', ...) defaults to 'python'
#
# Usage example:
# ./update.sh 4.1.2 "uv run"

set -euo pipefail

VERSION=$1
PYTHON=${2:-python}
URL="https://cdn.openbsd.org/pub/OpenBSD/LibreSSL/libressl-$VERSION.tar.gz"

# 1. Fetch the new version
HASH=$(zig fetch $URL)
zig fetch --save=libressl $URL

# 2. Re-generate the file lists
cat zig-pkg/$HASH/{crypto,tls,ssl}/Makefile.am* | $PYTHON generate.py | zig fmt --stdin > generated.zig

# 3. Bump the package version
sed "s|\([.]version *= *\).*|\1\"$VERSION\",|" build.zig.zon > tmp.zon
mv tmp.zon build.zig.zon
