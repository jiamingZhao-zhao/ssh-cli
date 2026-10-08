//go:build windows

package fsutil

import "golang.org/x/sys/windows"

func replaceFile(tmp, dest string) error {
	return windows.Rename(tmp, dest)
}

func harden(path string) error {
	// D:P(A;;FA;;;CU) is a protected DACL granting the current user full access
	// and nobody else. This is the Windows equivalent of mode 0600.
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;CU)")
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil,
	)
}
