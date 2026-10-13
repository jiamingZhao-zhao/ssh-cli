package transfer

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"regexp"
	"strings"

	"golang.org/x/crypto/ssh"
)

// RelayResult is the streamed copy and the checksum that matched.
type RelayResult struct {
	Bytes int64  `json:"bytes"`
	Algo  string `json:"algo"`
	Sum   string `json:"sum"`
}

// Relay copies one remote file to another SSH host through this process.
// It hashes the stream and checks sha256sum on the destination, falling back
// to md5sum. Paths are quoted for the remote checksum command.
func Relay(src, dst *ssh.Client, srcPath, dstPath string) (RelayResult, error) {
	return RelayWithOptions(src, dst, srcPath, dstPath, UploadOptions{})
}

// RelayWithOptions stages and verifies a remote copy before replacing its target.
// Cancellation owns both connections, as with UploadWithOptions.
func RelayWithOptions(src, dst *ssh.Client, srcPath, dstPath string, opt UploadOptions) (RelayResult, error) {
	ctx := opt.Context
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return RelayResult{}, err
	}
	stop := context.AfterFunc(ctx, func() { _ = src.Close(); _ = dst.Close() })
	defer stop()
	srcPath = RestoreRemotePath(srcPath)
	dstPath = RestoreRemotePath(dstPath)
	sfSrc, err := Client(src)
	if err != nil {
		return RelayResult{}, err
	}
	defer sfSrc.Close()
	sfDst, err := Client(dst)
	if err != nil {
		return RelayResult{}, err
	}
	defer sfDst.Close()
	in, err := sfSrc.Open(srcPath)
	if err != nil {
		return RelayResult{}, err
	}
	defer in.Close()
	info, err := in.Stat()
	if err != nil {
		return RelayResult{}, err
	}
	if !info.Mode().IsRegular() {
		return RelayResult{}, fmt.Errorf("relay source must be a regular file")
	}
	// A relay destination is an explicit file path, never a directory shorthand.
	dest, check, err := streamDestination(sfDst, dstPath, "", opt)
	if err != nil {
		return RelayResult{}, err
	}
	mode := info.Mode().Perm()
	if existing, err := sfDst.Lstat(dest); err == nil {
		mode = existing.Mode().Perm()
	}
	sha := sha256.New()
	md := md5.New()
	result := RelayResult{}
	prog := &byteProgress{fn: func(done, _ int64) { result.Bytes = done }}
	verify := func(tmp string) error {
		result.Algo, result.Sum = "sha256", hex.EncodeToString(sha.Sum(nil))
		remote, err := remoteSum(dst, result.Algo+"sum", tmp)
		if err != nil {
			result.Algo, result.Sum = "md5", hex.EncodeToString(md.Sum(nil))
			remote, err = remoteSum(dst, "md5sum", tmp)
		}
		if err != nil {
			return fmt.Errorf("relay checksum: %w", err)
		}
		if !strings.EqualFold(remote, result.Sum) {
			return fmt.Errorf("relay checksum mismatch")
		}
		return nil
	}
	err = uploadReader(sfDst, io.TeeReader(in, io.MultiWriter(sha, md)), dest, mode, nil, opt.RejectOverwrite, check, prog, verify)
	prog.report(true)
	if err != nil {
		return RelayResult{}, err
	}
	return result, nil
}

func pathDir(p string) string {
	i := strings.LastIndex(p, "/")
	if i <= 0 {
		return ""
	}
	return p[:i]
}

func remoteSum(client *ssh.Client, bin, path string) (string, error) {
	sess, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()
	var stdout, stderr bytes.Buffer
	sess.Stdout = &stdout
	sess.Stderr = &stderr
	if err := sess.Run(bin + " " + shellQuote(path)); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return "", fmt.Errorf("%s: %s", bin, msg)
	}
	sum, err := parseSumOutput(stdout.String())
	if err != nil {
		return "", fmt.Errorf("%s: %w", bin, err)
	}
	return sum, nil
}

var (
	sum64 = regexp.MustCompile(`(?i)[a-f0-9]{64}`)
	sum32 = regexp.MustCompile(`(?i)[a-f0-9]{32}`)
)

// parseSumOutput pulls a sha256 or md5 hex digest out of checksum command output.
// GNU sha256sum on MSYS may prefix the digest with a backslash, so the first
// whitespace field is not always the digest.
func parseSumOutput(out string) (string, error) {
	if m := sum64.FindString(out); m != "" {
		return strings.ToLower(m), nil
	}
	if m := sum32.FindString(out); m != "" {
		return strings.ToLower(m), nil
	}
	return "", fmt.Errorf("empty output")
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
