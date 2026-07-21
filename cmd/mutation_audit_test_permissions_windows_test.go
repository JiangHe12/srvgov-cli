//go:build windows

package cmd

import (
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestEnsureMutationSpoolDirectoryDoesNotRewriteUnsafeExistingParent(t *testing.T) {
	parent := t.TempDir()
	userSID, systemSID, adminSID, err := trustedMutationSpoolSIDs()
	if err != nil {
		t.Fatal(err)
	}
	usersSID, err := windows.CreateWellKnownSid(windows.WinBuiltinUsersSid)
	if err != nil {
		t.Fatal(err)
	}
	fullControl := windows.ACCESS_MASK(
		windows.STANDARD_RIGHTS_ALL |
			windows.FILE_GENERIC_READ |
			windows.FILE_GENERIC_WRITE |
			windows.FILE_GENERIC_EXECUTE |
			windows.DELETE,
	)
	entries := []windows.EXPLICIT_ACCESS{
		mutationSpoolExplicitAccess(userSID, windows.TRUSTEE_IS_USER, fullControl, windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT),
		mutationSpoolExplicitAccess(systemSID, windows.TRUSTEE_IS_WELL_KNOWN_GROUP, fullControl, windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT),
		mutationSpoolExplicitAccess(adminSID, windows.TRUSTEE_IS_GROUP, fullControl, windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT),
		mutationSpoolExplicitAccess(usersSID, windows.TRUSTEE_IS_GROUP, windows.FILE_GENERIC_WRITE, windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT),
	}
	dacl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(
		parent,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		dacl,
		nil,
	); err != nil {
		t.Fatal(err)
	}
	if err := verifyMutationSpoolParent(parent); err == nil {
		t.Fatal("unsafe parent unexpectedly passed validation before initialization")
	}
	spool := filepath.Join(parent, "audit.log"+mutationAuditSpoolSuffix)
	if err := ensureMutationSpoolDirectory(spool); err == nil {
		t.Fatal("ensureMutationSpoolDirectory() error = nil for unsafe existing parent")
	}
	if err := verifyMutationSpoolParent(parent); err == nil {
		t.Fatal("initialization silently rewrote the unsafe existing parent ACL")
	}
}

func secureMutationAuditTestParent(t *testing.T, path string) {
	t.Helper()
	if err := setMutationSpoolACL(path, windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT); err != nil {
		t.Fatalf("setMutationSpoolACL(test parent) error = %v", err)
	}
}
