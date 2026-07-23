//go:build windows

package srvgovctx

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

type testTokenOwner struct {
	owner *windows.SID
}

func configureTestProcessSecurity() error {
	var token windows.Token
	if err := windows.OpenProcessToken(
		windows.CurrentProcess(),
		windows.TOKEN_QUERY|windows.TOKEN_ADJUST_DEFAULT,
		&token,
	); err != nil {
		return err
	}
	defer func() { _ = token.Close() }()

	user, err := token.GetTokenUser()
	if err != nil {
		return err
	}
	owner := testTokenOwner{owner: user.User.Sid}
	return windows.SetTokenInformation(
		token,
		windows.TokenOwner,
		(*byte)(unsafe.Pointer(&owner)),
		uint32(unsafe.Sizeof(owner)),
	)
}

func secureTestHome(path string) error {
	userSID, systemSID, adminSID, err := trustedTestSIDs()
	if err != nil {
		return err
	}
	descriptor, err := windows.SecurityDescriptorFromString(fmt.Sprintf(
		"O:%sD:P(A;OICI;FA;;;%s)(A;OICI;FA;;;%s)(A;OICI;FA;;;%s)",
		userSID,
		userSID,
		systemSID,
		adminSID,
	))
	if err != nil {
		return err
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return err
	}
	if dacl == nil {
		return fmt.Errorf("test home security descriptor has no DACL")
	}
	return windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|
			windows.DACL_SECURITY_INFORMATION|
			windows.PROTECTED_DACL_SECURITY_INFORMATION,
		userSID,
		nil,
		dacl,
		nil,
	)
}

func trustedTestSIDs() (*windows.SID, *windows.SID, *windows.SID, error) {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		return nil, nil, nil, err
	}
	defer func() { _ = token.Close() }()
	user, err := token.GetTokenUser()
	if err != nil {
		return nil, nil, nil, err
	}
	userSID, err := user.User.Sid.Copy()
	if err != nil {
		return nil, nil, nil, err
	}
	systemSID, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return nil, nil, nil, err
	}
	adminSID, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return nil, nil, nil, err
	}
	return userSID, systemSID, adminSID, nil
}
