package update

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode"
)

// ChecksumsName is the optional sha256 manifest published next to the archives.
const ChecksumsName = "checksums.txt"

// AssetName is the published archive for one target.
// Unix archives are tar.gz and contain a file named ssh-cli.
// Windows archives are zip and contain ssh-cli.exe.
// version is the release tag without a leading v.
func AssetName(ver, goos, goarch string) string {
	ver = strings.TrimPrefix(strings.TrimPrefix(ver, "v"), "V")
	if goos == "windows" {
		return fmt.Sprintf("ssh-cli_%s_%s_%s.zip", ver, goos, goarch)
	}
	return fmt.Sprintf("ssh-cli_%s_%s_%s.tar.gz", ver, goos, goarch)
}

// BinaryName is the file stored inside the archive.
func BinaryName(goos string) string {
	if goos == "windows" {
		return "ssh-cli.exe"
	}
	return "ssh-cli"
}

type asset struct {
	name string
	url  string
}

func selectAsset(assets []asset, ver, goos, goarch string) (asset, error) {
	want := AssetName(ver, goos, goarch)
	for _, a := range assets {
		if a.name == want {
			if a.url == "" {
				return asset{}, errUsage("asset %s has no download URL", want)
			}
			return a, nil
		}
	}
	return asset{}, errUsage("no release asset %s", want)
}

func findAsset(assets []asset, name string) (asset, bool) {
	for _, a := range assets {
		if a.name == name && a.url != "" {
			return a, true
		}
	}
	return asset{}, false
}

// ParseChecksums reads sha256sum lines: "<hex>  <name>" or "<hex> *<name>".
func ParseChecksums(b []byte) (map[string]string, error) {
	out := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return nil, errUsage("invalid checksums line %q", line)
		}
		sum := strings.ToLower(fields[0])
		name := fields[len(fields)-1]
		name = strings.TrimPrefix(name, "*")
		if len(sum) != sha256.Size*2 || !isHex(sum) {
			return nil, errUsage("invalid checksums line %q", line)
		}
		out[name] = sum
	}
	if err := sc.Err(); err != nil {
		return nil, errUsage("read checksums: %s", err.Error())
	}
	return out, nil
}

func verifyChecksum(name string, data []byte, sums map[string]string) error {
	want, ok := sums[name]
	if !ok {
		return errUsage("checksums.txt has no entry for %s", name)
	}
	got := sha256.Sum256(data)
	if !strings.EqualFold(want, hex.EncodeToString(got[:])) {
		return errUsage("checksum mismatch for %s", name)
	}
	return nil
}

func isHex(s string) bool {
	for _, c := range s {
		if !unicode.Is(unicode.ASCII_Hex_Digit, c) {
			return false
		}
	}
	return true
}
