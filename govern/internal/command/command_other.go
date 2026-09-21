//go:build !windows

package command

import "os/exec"

// rawCommandLine is Windows' concern: every shell here takes an argument vector.
func rawCommandLine(*exec.Cmd, []string) {}
