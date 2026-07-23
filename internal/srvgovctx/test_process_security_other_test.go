//go:build !windows

package srvgovctx

func configureTestProcessSecurity() error {
	return nil
}

func secureTestHome(string) error {
	return nil
}
