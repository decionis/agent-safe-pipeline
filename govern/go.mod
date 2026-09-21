module github.com/decionis/agent-safe-pipeline/govern/v2

go 1.22

// The exact toolchain every build of a release uses, so the archives are
// reproducible from any machine and any runner: `go` fetches it when the
// installed one differs, and the CI job installs the same.
toolchain go1.26.4

require github.com/gowebpki/jcs v1.0.1
