package transfer

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"unicode/utf8"

	"github.com/pkg/sftp"
)

const MaxTextBytes = 5 << 20

var ErrTextChanged = errors.New("文件已被其他操作修改，请重新打开后核对内容")

type TextSnapshot struct {
	Content  string `json:"content"`
	Version  string `json:"version"`
	mode     os.FileMode
	uid, gid uint32
}

func ValidateText(content string) error {
	if len(content) > MaxTextBytes {
		return fmt.Errorf("文本文件不能超过 5 MiB")
	}
	if !utf8.ValidString(content) {
		return fmt.Errorf("仅支持 UTF-8 文本")
	}
	for _, value := range content {
		if value < 32 && value != '\t' && value != '\n' && value != '\r' || value == 127 {
			return fmt.Errorf("文件含有二进制字符，不能直接编辑")
		}
	}
	return nil
}

func TextPath(remote string) (string, error) {
	if !path.IsAbs(remote) || path.Clean(remote) != remote || remote == "/" || strings.ContainsAny(remote, "\\\x00\r\n") {
		return "", fmt.Errorf("文本编辑需要有效的绝对文件路径")
	}
	return remote, nil
}

func CheckTextPath(sf *sftp.Client, remote string, protected []string, check func(string, []string) error) error {
	if err := rejectUploadSymlinks(sf, remote); err != nil {
		return err
	}
	home, err := sf.RealPath(".")
	if err != nil {
		return err
	}
	return check(remote, expandProtected(sf, home, protected))
}

func ReadText(sf *sftp.Client, remote string) (TextSnapshot, error) {
	var snapshot TextSnapshot
	if err := rejectUploadSymlinks(sf, remote); err != nil {
		return snapshot, err
	}
	info, err := sf.Lstat(remote)
	if err != nil {
		return snapshot, err
	}
	if !info.Mode().IsRegular() || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return snapshot, fmt.Errorf("仅支持普通文本文件")
	}
	if info.Size() > MaxTextBytes {
		return snapshot, fmt.Errorf("文本文件不能超过 5 MiB")
	}
	file, err := sf.Open(remote)
	if err != nil {
		return snapshot, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, MaxTextBytes+1))
	if err != nil {
		return snapshot, err
	}
	content := string(data)
	if err := ValidateText(content); err != nil {
		return snapshot, err
	}
	mode := info.Mode().Perm()
	owner, ok := info.Sys().(*sftp.FileStat)
	if !ok {
		return snapshot, fmt.Errorf("无法读取文件权限和所有者")
	}
	hash := sha256.New()
	_, _ = fmt.Fprintf(hash, "%s\x00%o\x00%d\x00%d\x00%d\x00", remote, mode, owner.UID, owner.GID, info.ModTime().Unix())
	_, _ = hash.Write(data)
	return TextSnapshot{Content: content, Version: fmt.Sprintf("%x", hash.Sum(nil)), mode: mode, uid: owner.UID, gid: owner.GID}, nil
}

func SaveText(sf *sftp.Client, remote, version, content string, check func() error) error {
	if err := ValidateText(content); err != nil {
		return err
	}
	if err := check(); err != nil {
		return err
	}
	before, err := ReadText(sf, remote)
	if err != nil {
		return err
	}
	if before.Version != version {
		return ErrTextChanged
	}
	if before.Content == content {
		return nil
	}
	if _, supported := sf.HasExtension("posix-rename@openssh.com"); !supported {
		return fmt.Errorf("远端 SFTP 不支持安全替换，原文件未修改")
	}
	return uploadReader(sf, strings.NewReader(content), remote, before.mode, nil, false, true, func(string) error {
		if err := check(); err != nil {
			return err
		}
		current, err := ReadText(sf, remote)
		if err != nil || current.Version != version {
			return ErrTextChanged
		}
		return nil
	}, nil, func(staged string) error {
		info, err := sf.Stat(staged)
		if err != nil {
			return err
		}
		if owner, ok := info.Sys().(*sftp.FileStat); !ok || owner.UID != before.uid || owner.GID != before.gid {
			if err := sf.Chown(staged, int(before.uid), int(before.gid)); err != nil {
				return fmt.Errorf("无法保留原文件所有者，未保存: %w", err)
			}
		}
		return nil
	}, nil)
}
