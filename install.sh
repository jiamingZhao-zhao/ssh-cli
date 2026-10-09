#!/bin/sh
# Install the latest ssh-cli release into a user-writable directory.
# Default destination: ~/.local/bin (override with SSH_CLI_BIN).
# Default repo: jiamingZhao-zhao/ssh-cli (override with SSH_CLI_REPO=owner/name).
# The tag comes from the releases/latest redirect, not api.github.com.
set -eu

repo="${SSH_CLI_REPO:-jiamingZhao-zhao/ssh-cli}"
dest="${SSH_CLI_BIN:-$HOME/.local/bin}"

case "$(uname -s)" in
  Linux) goos=linux ;;
  Darwin) goos=darwin ;;
  *)
    echo "unsupported OS $(uname -s); on Windows, from cmd.exe run install.cmd" >&2
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

owner=${repo%%/*}
name=${repo#*/}
case "$owner" in
  ""|*"/"*|*[!A-Za-z0-9_.-]*)
    echo "invalid repo ${repo} (want owner/name)" >&2
    exit 1
    ;;
esac
case "$name" in
  ""|*"/"*|*[!A-Za-z0-9_.-]*)
    echo "invalid repo ${repo} (want owner/name)" >&2
    exit 1
    ;;
esac

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# Resolve the tag from the releases/latest redirect. Do not call api.github.com.
lookup=$(curl -sS -A ssh-cli-install -D "$tmp/headers" -o "$tmp/latest.html" -w '%{http_code}' \
  "https://github.com/${repo}/releases/latest" || true)
location=$(awk 'tolower($1)=="location:" {print $2}' "$tmp/headers" | tail -n 1 | tr -d '\r')
tag=$(printf '%s\n' "$location" | sed -n 's#.*/releases/tag/\([A-Za-z0-9._+-][A-Za-z0-9._+-]*\).*#\1#p' | head -n 1)
if [ -z "$tag" ]; then
  tag=$(sed -n 's#.*rel="canonical"[^>]*href="[^"]*/releases/tag/\([A-Za-z0-9._+-][A-Za-z0-9._+-]*\)".*#\1#p' "$tmp/latest.html" | head -n 1)
fi
case "$tag" in
  ""|*[!A-Za-z0-9._+-]*)
    echo "could not read the latest release tag (HTTP ${lookup})" >&2
    exit 1
    ;;
esac
ver=$tag
case "$ver" in
  v*|V*) ver=${ver#?} ;;
esac
if [ -z "$ver" ]; then
  echo "could not read the latest release tag (HTTP ${lookup})" >&2
  exit 1
fi

asset="ssh-cli_${ver}_${goos}_${arch}.tar.gz"
url="https://github.com/${repo}/releases/download/${tag}/${asset}"
sums="https://github.com/${repo}/releases/download/${tag}/checksums.txt"

curl -fsSL -A ssh-cli-install -o "$tmp/$asset" "$url"

sum_code=$(curl -sS -A ssh-cli-install -o "$tmp/checksums.txt" -w '%{http_code}' "$sums" || true)
if [ "$sum_code" = "200" ]; then
  :
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
elif [ "$sum_code" = "404" ]; then
  if [ "${SSH_CLI_ALLOW_MISSING_CHECKSUM:-}" = "1" ]; then
    echo "warning: release has no checksums.txt; the download was not verified" >&2
  else
    echo "refusing to install without checksums.txt (set SSH_CLI_ALLOW_MISSING_CHECKSUM=1 to override)" >&2
    exit 1
  fi
else
  echo "checksum download failed (HTTP ${sum_code})" >&2
  exit 1
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
