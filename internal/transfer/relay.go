package transfer

import (
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"github.com/pkg/sftp"
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
	srcPath = RestoreRemotePath(srcPath)
	dstPath = RestoreRemotePath(dstPath)
	sfSrc, err := sftp.NewClient(src)
	if err != nil {
		return RelayResult{}, err
	}
	defer sfSrc.Close()
	sfDst, err := sftp.NewClient(dst)
	if err != nil {
		return RelayResult{}, err
	}
	defer sfDst.Close()
	in, err := sfSrc.Open(srcPath)
	if err != nil {
		return RelayResult{}, err
	}
	defer in.Close()
	if dir := pathDir(dstPath); dir != "" && dir != "." && dir != "/" {
		if err := sfDst.MkdirAll(dir); err != nil {
			return RelayResult{}, err
		}
	}
	out, err := sfDst.Create(dstPath)
	if err != nil {
		return RelayResult{}, err
	}
	sha := sha256.New()
	md := md5.New()
	n, copyErr := io.Copy(out, io.TeeReader(in, io.MultiWriter(sha, md)))
	closeErr := out.Close()
	if copyErr != nil {
		return RelayResult{}, copyErr
	}
	if closeErr != nil {
		return RelayResult{}, closeErr
	}
	localSHA := hex.EncodeToString(sha.Sum(nil))
	localMD5 := hex.EncodeToString(md.Sum(nil))
	if remote, err := remoteSum(dst, "sha256sum", dstPath); err == nil {
		if !strings.EqualFold(remote, localSHA) {
			return RelayResult{}, fmt.Errorf("relay checksum mismatch")
		}
		return RelayResult{Bytes: n, Algo: "sha256", Sum: localSHA}, nil
	}
	remote, err := remoteSum(dst, "md5sum", dstPath)
	if err != nil {
		return RelayResult{}, fmt.Errorf("relay checksum: %w", err)
	}
	if !strings.EqualFold(remote, localMD5) {
		return RelayResult{}, fmt.Errorf("relay checksum mismatch")
	}
	return RelayResult{Bytes: n, Algo: "md5", Sum: localMD5}, nil
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
	fields := strings.Fields(stdout.String())
	if len(fields) == 0 {
		return "", fmt.Errorf("%s: empty output", bin)
	}
	return fields[0], nil
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
