//go:build !windows

package sshexec

func configureTestProcessSecurity() error {
	return nil
}

func secureTestHome(string) error {
	return nil
}
