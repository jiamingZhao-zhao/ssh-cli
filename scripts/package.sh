#!/bin/sh
# Build ssh-cli release archives and checksums.txt.
# Names match internal/update.AssetName: ssh-cli_<version>_<os>_<arch>.tar.gz
# (Windows: .zip containing ssh-cli.exe). Unix archives contain ssh-cli.
#
# Usage: scripts/package.sh [version] [commit] [date] [outdir]
# version defaults to dev. Do not include a leading v.
set -eu

version="${1:-dev}"
commit="${2:-}"
date="${3:-}"
out="${4:-dist}"

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
cd "$root"
mkdir -p "$out"
out=$(CDPATH= cd -- "$out" && pwd)

if ! command -v zip >/dev/null 2>&1; then
  echo "zip is required to pack Windows archives" >&2
  exit 1
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  echo "sha256sum is required" >&2
  exit 1
fi

module="github.com/jiamingZhao-zhao/ssh-cli"
ldflags="-s -w -X ${module}/internal/version.Version=${version} -X ${module}/internal/version.Commit=${commit} -X ${module}/internal/version.Date=${date}"

rm -f "$out"/ssh-cli_"${version}"_* "$out"/checksums.txt

for pair in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64; do
  os=${pair%/*}
  arch=${pair#*/}
  stage=$(mktemp -d)
  if [ "$os" = "windows" ]; then
    bin="ssh-cli.exe"
    archive="$out/ssh-cli_${version}_${os}_${arch}.zip"
  else
    bin="ssh-cli"
    archive="$out/ssh-cli_${version}_${os}_${arch}.tar.gz"
  fi
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -ldflags "$ldflags" -o "$stage/$bin" ./cmd/ssh-cli
  if [ "$os" = "windows" ]; then
    (cd "$stage" && zip -q -X "$archive" "$bin")
  else
    tar -C "$stage" -czf "$archive" "$bin"
  fi
  rm -rf "$stage"
  echo "packed $archive"
done

(
  cd "$out"
  # shellcheck disable=SC2086
  sha256sum ssh-cli_"${version}"_* > checksums.txt
)
echo "wrote $out/checksums.txt"
