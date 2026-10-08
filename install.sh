#!/bin/sh
# Install the latest ssh-cli release into a user-writable directory.
# Default destination: ~/.local/bin (override with SSH_CLI_BIN).
# Default repo: jiamingZhao-zhao/ssh-cli (override with SSH_CLI_REPO=owner/name).
set -eu

repo="${SSH_CLI_REPO:-jiamingZhao-zhao/ssh-cli}"
dest="${SSH_CLI_BIN:-$HOME/.local/bin}"

case "$(uname -s)" in
  Linux) goos=linux ;;
  Darwin) goos=darwin ;;
  *)
    echo "unsupported OS $(uname -s); on Windows run install.ps1" >&2
    exit 1
    ;;
esac
case "$(uname -m)" in
  x86_64|amd64) arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *)
    echo "unsupported architecture $(uname -m)" >&2
    exit 1
    ;;
esac

if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required" >&2
  exit 1
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

curl -fsSL -A ssh-cli-install -H "Accept: application/vnd.github+json" \
  -o "$tmp/release.json" "https://api.github.com/repos/${repo}/releases/latest"

tag=$(sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$tmp/release.json" | head -n 1)
ver=${tag#v}
ver=${ver#V}
if [ -z "$ver" ]; then
  echo "could not read tag_name from the latest release" >&2
  exit 1
fi

asset="ssh-cli_${ver}_${goos}_${arch}.tar.gz"
url=$(sed -n "s/.*\"browser_download_url\"[[:space:]]*:[[:space:]]*\"\\([^\"]*\\/${asset}\\)\".*/\\1/p" "$tmp/release.json" | head -n 1)
if [ -z "$url" ]; then
  echo "latest release has no ${asset}" >&2
  exit 1
fi

curl -fsSL -A ssh-cli-install -o "$tmp/$asset" "$url"

sums=$(sed -n 's/.*"browser_download_url"[[:space:]]*:[[:space:]]*"\([^"]*checksums\.txt\)".*/\1/p' "$tmp/release.json" | head -n 1)
if [ -n "$sums" ]; then
  curl -fsSL -A ssh-cli-install -o "$tmp/checksums.txt" "$sums"
  want=$(awk -v f="$asset" '
    {
      name = $NF
      sub(/^\*/, "", name)
      if (name == f) { print $1; exit }
    }
  ' "$tmp/checksums.txt")
  if [ -z "$want" ]; then
    echo "checksums.txt has no entry for ${asset}" >&2
    exit 1
  fi
  if command -v sha256sum >/dev/null 2>&1; then
    got=$(sha256sum "$tmp/$asset" | awk '{print $1}')
  elif command -v shasum >/dev/null 2>&1; then
    got=$(shasum -a 256 "$tmp/$asset" | awk '{print $1}')
  else
    echo "sha256sum or shasum is required to verify checksums.txt" >&2
    exit 1
  fi
  if [ "$want" != "$got" ]; then
    echo "checksum mismatch for ${asset}" >&2
    exit 1
  fi
else
  echo "warning: release has no checksums.txt; the download was not verified" >&2
fi

mkdir -p "$tmp/out" "$dest"
tar -xzf "$tmp/$asset" -C "$tmp/out"
src="$tmp/out/ssh-cli"
if [ ! -f "$src" ]; then
  src=$(find "$tmp/out" -type f -name ssh-cli | head -n 1)
fi
if [ -z "$src" ] || [ ! -f "$src" ]; then
  echo "archive did not contain ssh-cli" >&2
  exit 1
fi
cp "$src" "$dest/ssh-cli"
chmod 755 "$dest/ssh-cli"
echo "installed $dest/ssh-cli ($ver)"
case ":$PATH:" in
  *":$dest:"*) ;;
  *) echo "Add $dest to PATH, then run: ssh-cli version" ;;
esac
