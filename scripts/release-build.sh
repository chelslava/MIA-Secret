#!/usr/bin/env bash
set -euo pipefail

TARGET="${1:-}"
OUT_DIR="${2:-dist}"

version="$(grep -E '^version\s*=' Cargo.toml | head -n1 | sed -E 's/version\s*=\s*"([^"]+)"/\1/')"
if [[ -z "$version" ]]; then
  echo "Unable to resolve version from Cargo.toml" >&2
  exit 1
fi

target_suffix=""
target_args=()
if [[ -n "$TARGET" ]]; then
  target_args+=(--target "$TARGET")
  target_suffix="-$TARGET"
fi

echo "Building release binary (version=$version target=${TARGET:-native})"
cargo build --release "${target_args[@]}"

if [[ -n "$TARGET" ]]; then
  release_dir="target/$TARGET/release"
else
  release_dir="target/release"
fi

binary_path="$release_dir/mia-secret"
if [[ ! -f "$binary_path" ]]; then
  echo "Binary not found: $binary_path" >&2
  exit 1
fi

artifact_base="mia-secret-v${version}${target_suffix}-linux-x64"
artifact_dir="$OUT_DIR/$artifact_base"
mkdir -p "$artifact_dir"

cp "$binary_path" "$artifact_dir/mia-secret"
cp README.md "$artifact_dir/README.md"
cp docs/release.md "$artifact_dir/RELEASE.md"
cp docs/api.md "$artifact_dir/API.md"
cp docs/cli.md "$artifact_dir/CLI.md"

tarball="$OUT_DIR/$artifact_base.tar.gz"
tar -C "$OUT_DIR" -czf "$tarball" "$artifact_base"

sha_file="$tarball.sha256"
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum "$tarball" > "$sha_file"
else
  shasum -a 256 "$tarball" > "$sha_file"
fi

echo "Release artifact created:"
echo "  $tarball"
echo "  $sha_file"
