package main

import "embed"

// skillEmbedFS holds the bundled SKILL.md for `srvgov install <agent> --skills`.
//
//go:embed skills/srvgov-cli
var skillEmbedFS embed.FS
