//go:build windows

package command

import (
	"os/exec"
	"syscall"
)

// rawCommandLine hands cmd.exe its line as typed. Windows passes a process
// one command line, not an argument vector; Go builds that line by quoting
// each argument the way C programs parse it, which cmd.exe does not: it reads
// the text after /c itself, and with /s strips one pair of quotes around the
// whole of it. So the line goes in as `cmd /d /s /c "<line>"`, the quotes
// inside it untouched. The other shells parse an argument vector and take
// what Go builds.
func rawCommandLine(cmd *exec.Cmd, argv []string) {
	if argv[0] != "cmd" {
		return
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{CmdLine: `cmd /d /s /c "` + argv[len(argv)-1] + `"`}
}
