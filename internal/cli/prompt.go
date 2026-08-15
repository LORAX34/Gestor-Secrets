package cli

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"
)

var stdinReader = bufio.NewReader(os.Stdin)

// promptPassword reads a password without echoing. Falls back to a line read
// when stdin is not a terminal (piped input).
func promptPassword(label string) (string, error) {
	fmt.Fprint(os.Stderr, label)
	if term.IsTerminal(int(os.Stdin.Fd())) {
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", err
		}
		return string(b), nil
	}
	line, err := stdinReader.ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// newMasterPassword resolves the NEW master password for rotate-master.
// It never reuses SEC_MASTER; scripts can use SEC_MASTER_NEW.
func newMasterPassword() (string, error) {
	if p := os.Getenv("SEC_MASTER_NEW"); p != "" {
		return p, nil
	}
	pass, err := promptPassword("New master password: ")
	if err != nil {
		return "", err
	}
	if pass == "" {
		return "", fmt.Errorf("password cannot be empty")
	}
	again, err := promptPassword("Confirm new master password: ")
	if err != nil {
		return "", err
	}
	if pass != again {
		return "", fmt.Errorf("passwords do not match")
	}
	return pass, nil
}

func masterPassword(confirm bool) (string, error) {
	if p := os.Getenv("SEC_MASTER"); p != "" {
		return p, nil
	}
	pass, err := promptPassword("Master password: ")
	if err != nil {
		return "", err
	}
	if pass == "" {
		return "", fmt.Errorf("password cannot be empty")
	}
	if confirm {
		again, err := promptPassword("Confirm master password: ")
		if err != nil {
			return "", err
		}
		if pass != again {
			return "", fmt.Errorf("passwords do not match")
		}
	}
	return pass, nil
}
