//go:build !windows

package cmd

func configureTestProcessSecurity() error {
	return nil
}

func secureTestHome(string) error {
	return nil
}
