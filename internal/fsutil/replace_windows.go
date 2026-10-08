//go:build windows

package fsutil

import (
	"errors"
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// fileAllAccess is FILE_ALL_ACCESS, the SDDL access right "FA":
// STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x1FF.
const fileAllAccess windows.ACCESS_MASK = windows.STANDARD_RIGHTS_REQUIRED | windows.SYNCHRONIZE | 0x1FF

func replaceFile(tmp, dest string) error {
	return windows.Rename(tmp, dest)
}

// harden replaces the file DACL with a protected ACL that grants only the
// current user full access. That is the Windows equivalent of mode 0600.
//
// SDDL has no current-user alias. "D:P(A;;FA;;;CU)" is rejected by
// SecurityDescriptorFromString with ERROR_INVALID_SID ("The security ID
// structure is invalid"). The SID is read from the process token instead.
// SID lookup and DACL construction failures return before
// SetNamedSecurityInfo, so an invalid descriptor is never applied.
// WriteAtomic then deletes the temp file and leaves the destination unchanged.
func harden(path string) error {
	sid, err := currentUserSID()
	if err != nil {
		return fmt.Errorf("harden %s: resolve current user SID: %w", path, err)
	}
	dacl, err := userFullAccessDACL(sid)
	if err != nil {
		return fmt.Errorf("harden %s: build DACL: %w", path, err)
	}
	err = windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil,
	)
	if err != nil {
		return fmt.Errorf("harden %s: set protected DACL: %w", path, err)
	}
	return nil
}

// currentUserSID returns a copy of the user SID on the process token.
// OpenCurrentProcessToken is the TOKEN_QUERY handle; the SID bytes are
// copied while the token-information buffer is still referenced.
func currentUserSID() (*windows.SID, error) {
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return nil, err
	}
	defer token.Close()

	buf := make([]byte, 256)
	var needed uint32
	for {
		err = windows.GetTokenInformation(token, windows.TokenUser, &buf[0], uint32(len(buf)), &needed)
		if err == nil {
			break
		}
		if !errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) || needed <= uint32(len(buf)) {
			return nil, err
		}
		buf = make([]byte, needed)
	}
	user := (*windows.Tokenuser)(unsafe.Pointer(&buf[0]))
	if user.User.Sid == nil || !user.User.Sid.IsValid() {
		runtime.KeepAlive(buf)
		return nil, errors.New("token user SID is invalid")
	}
	sid, err := user.User.Sid.Copy()
	runtime.KeepAlive(buf)
	if err != nil {
		return nil, err
	}
	if sid == nil || !sid.IsValid() {
		return nil, errors.New("copied token user SID is invalid")
	}
	return sid, nil
}

// userFullAccessDACL builds a one-ACE ACL granting sid FILE_ALL_ACCESS.
// It refuses to return an ACL that is not exactly that grant.
func userFullAccessDACL(sid *windows.SID) (*windows.ACL, error) {
	if sid == nil || !sid.IsValid() {
		return nil, errors.New("refusing to build a DACL for an invalid SID")
	}
	entries := []windows.EXPLICIT_ACCESS{{
		AccessPermissions: fileAllAccess,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       windows.NO_INHERITANCE,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_USER,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}}
	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		return nil, err
	}
	if acl == nil || acl.AceCount != 1 {
		return nil, errors.New("DACL was not built with a single ACE")
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(acl, 0, &ace); err != nil {
		return nil, err
	}
	if ace == nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Mask != fileAllAccess {
		return nil, errors.New("DACL ACE is not a full-access allow for the current user")
	}
	aceSID := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
	if aceSID == nil || !aceSID.IsValid() || !sid.Equals(aceSID) {
		runtime.KeepAlive(acl)
		return nil, errors.New("DACL ACE SID does not match the current user")
	}
	runtime.KeepAlive(acl)
	return acl, nil
}
