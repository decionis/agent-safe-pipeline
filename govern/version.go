// Package govern carries the version the binary answers to and every build,
// package and User-Agent names; the release job reads the same file.
package govern

import (
	_ "embed"
	"strings"
)

//go:embed VERSION
var embeddedVersion string

// Version is this binary's version, a semantic version with no leading "v".
var Version = strings.TrimSpace(embeddedVersion)
