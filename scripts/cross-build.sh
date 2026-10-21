#!/bin/sh
# Compile only: foreign target binaries are never executed by this script.
set -eu
cd "$(dirname "$0")/.."
mkdir -p dist
for os in darwin linux windows; do
  for arch in amd64 arm64; do
    suffix=
    if [ "$os" = windows ]; then suffix=.exe; fi
    output="dist/nscope-$os-$arch$suffix"
    CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath -o "$output" ./cmd/nscope
    echo "Built $output"
  done
done
