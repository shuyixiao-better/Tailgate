package sshpool

import (
	"fmt"
	"strings"
)

// ShellQuote quotes one POSIX shell argument. Never apply it to a whole command.
func ShellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

// RewriteSudo injects no password into the command: the caller supplies stdin.
func RewriteSudo(command string, enabled bool) (string, bool) {
	if enabled && strings.HasPrefix(command, "sudo ") {
		return "sudo -S -p '' " + strings.TrimPrefix(command, "sudo "), true
	}
	return command, false
}

func prepareCommand(command, workdir string) (string, error) {
	if strings.TrimSpace(command) == "" {
		return "", fmt.Errorf("command must not be empty")
	}
	if strings.ContainsRune(command, 0) || strings.ContainsRune(workdir, 0) {
		return "", fmt.Errorf("command and workdir must not contain NUL")
	}
	prefix := "export LANG=C.UTF-8 TERM=dumb PAGER=cat SYSTEMD_PAGER=cat; "
	if workdir != "" {
		prefix += "cd -- " + ShellQuote(workdir) + " && "
	}
	// A separate shell preserves grouping, precedence, and user commands verbatim.
	return prefix + "exec /bin/sh -c " + ShellQuote(command), nil
}
