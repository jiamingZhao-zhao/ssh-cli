package update

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"io"
	"path"
	"strings"
)

const maxArchive = 32 << 20

func extractBinary(archiveName, goos string, data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errUsage("empty archive %s", archiveName)
	}
	if len(data) > maxArchive {
		return nil, errUsage("archive %s exceeds %d bytes", archiveName, maxArchive)
	}
	want := BinaryName(goos)
	switch {
	case strings.HasSuffix(archiveName, ".tar.gz"), strings.HasSuffix(archiveName, ".tgz"):
		return extractTarGz(data, want)
	case strings.HasSuffix(archiveName, ".zip"):
		return extractZip(data, want)
	default:
		return nil, errUsage("unsupported archive %s", archiveName)
	}
}

func extractTarGz(data []byte, want string) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, errUsage("read tar.gz: %s", err.Error())
	}
	defer zr.Close()
	tr := tar.NewReader(zr)
	var found []byte
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, errUsage("read tar.gz: %s", err.Error())
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA && hdr.Typeflag != 0 {
			continue
		}
		if !safeArchivePath(hdr.Name, want) {
			if strings.Contains(hdr.Name, "..") || path.IsAbs(hdr.Name) {
				return nil, errUsage("archive path %q is not allowed", hdr.Name)
			}
			continue
		}
		if found != nil {
			return nil, errUsage("archive contains more than one %s", want)
		}
		if hdr.Size < 0 || hdr.Size > maxArchive {
			return nil, errUsage("archive member %s is too large", hdr.Name)
		}
		found, err = readLimited(tr, int(hdr.Size))
		if err != nil {
			return nil, err
		}
	}
	if found == nil {
		return nil, errUsage("archive does not contain %s", want)
	}
	return found, nil
}

func extractZip(data []byte, want string) ([]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, errUsage("read zip: %s", err.Error())
	}
	var found []byte
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		if !safeArchivePath(f.Name, want) {
			if strings.Contains(f.Name, "..") || path.IsAbs(f.Name) {
				return nil, errUsage("archive path %q is not allowed", f.Name)
			}
			continue
		}
		if found != nil {
			return nil, errUsage("archive contains more than one %s", want)
		}
		if f.UncompressedSize64 > maxArchive {
			return nil, errUsage("archive member %s is too large", f.Name)
		}
		rc, err := f.Open()
		if err != nil {
			return nil, errUsage("read zip: %s", err.Error())
		}
		found, err = readLimited(rc, int(f.UncompressedSize64))
		rc.Close()
		if err != nil {
			return nil, err
		}
	}
	if found == nil {
		return nil, errUsage("archive does not contain %s", want)
	}
	return found, nil
}

func safeArchivePath(name, want string) bool {
	name = path.Clean(strings.ReplaceAll(name, "\\", "/"))
	if name == "." || name == ".." || strings.HasPrefix(name, "../") || path.IsAbs(name) {
		return false
	}
	return path.Base(name) == want
}

func readLimited(r io.Reader, n int) ([]byte, error) {
	if n < 0 || n > maxArchive {
		return nil, errUsage("archive member is too large")
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, errUsage("read archive member: %s", err.Error())
	}
	extra := make([]byte, 1)
	n, err := r.Read(extra)
	if n > 0 {
		return nil, errUsage("archive member is larger than declared")
	}
	if err != nil && err != io.EOF {
		return nil, errUsage("read archive member: %s", err.Error())
	}
	return buf, nil
}
