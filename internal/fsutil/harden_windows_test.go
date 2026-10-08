//go:build windows

package fsutil

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Linux CI cannot execute these tests. They need a Windows process token and
// advapi32 (GetTokenInformation / SetNamedSecurityInfo). `go test ./...` on
// Linux skips this file via the build tag. Compile it in CI with:
//
//	GOOS=windows GOARCH=amd64 go test -c -o /tmp/fsutil.test.exe ./internal/fsutil

func TestHardenGrantsOnlyCurrentUser(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.json")
	payload := []byte("secret\n")
	if err := WriteAtomic(path, payload, 0o600); err != nil {
		t.Fatalf("WriteAtomic: %v", err)
	}
	if err := WriteAtomic(path, payload, 0o600); err != nil {
		t.Fatalf("WriteAtomic overwrite: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("content = %q", got)
	}

	want, err := currentUserSID()
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	if sd == nil || !sd.IsValid() {
		t.Fatal("security descriptor is invalid")
	}
	control, _, err := sd.Control()
	if err != nil {
		t.Fatal(err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		t.Fatalf("DACL is not protected: control=%#x", control)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if dacl == nil || dacl.AceCount != 1 {
		count := uint16(0)
		if dacl != nil {
			count = dacl.AceCount
		}
		t.Fatalf("AceCount = %d, want 1", count)
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(dacl, 0, &ace); err != nil {
		t.Fatal(err)
	}
	if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
		t.Fatalf("ACE type = %d, want ACCESS_ALLOWED", ace.Header.AceType)
	}
	if ace.Mask != fileAllAccess {
		t.Fatalf("ACE mask = %#x, want FILE_ALL_ACCESS %#x", ace.Mask, fileAllAccess)
	}
	gotSID := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
	if !gotSID.IsValid() {
		t.Fatal("ACE SID is invalid")
	}
	if !want.Equals(gotSID) {
		t.Fatalf("ACE SID = %s, want current user %s", gotSID.String(), want.String())
	}
	runtime.KeepAlive(sd)
}

func TestCurrentUserSIDIsValid(t *testing.T) {
	sid, err := currentUserSID()
	if err != nil {
		t.Fatal(err)
	}
	if sid == nil || !sid.IsValid() || sid.String() == "" {
		t.Fatal("current user SID is empty or invalid")
	}
	if _, err := windows.StringToSid(sid.String()); err != nil {
		t.Fatal(err)
	}
}

func TestSDDLAliasCUIsRejected(t *testing.T) {
	_, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;CU)")
	if err == nil {
		t.Fatal(`SDDL "D:P(A;;FA;;;CU)" was accepted; CU is not a well-known SID`)
	}
	if !errors.Is(err, windows.ERROR_INVALID_SID) {
		t.Fatalf("CU SDDL error = %v, want ERROR_INVALID_SID", err)
	}
}

func TestHardenMissingFileDoesNotPanic(t *testing.T) {
	err := harden(filepath.Join(t.TempDir(), "missing"))
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "set protected DACL") {
		t.Fatalf("error = %v, want the SetNamedSecurityInfo failure", err)
	}
}
