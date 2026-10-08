package cli

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/exitcode"
)

func confirmAlias(alias string, yes bool) error {
	if yes {
		if !ttyCheck() {
			return exitcode.New(exitcode.Denied, "--yes is only valid on an interactive TTY")
		}
		return nil
	}
	if !ttyCheck() {
		return exitcode.New(exitcode.Denied, "host %s requires confirmation; non-interactive callers are refused", alias)
	}
	f, err := os.OpenFile(devTTY(), os.O_RDWR, 0)
	if err != nil {
		return exitcode.New(exitcode.Denied, "host %s requires confirmation on an interactive TTY", alias)
	}
	defer f.Close()
	return confirmFrom(alias, f, f)
}

func confirmFrom(alias string, in io.Reader, out io.Writer) error {
	return confirmTyped(alias, "host alias", in, out)
}

func confirmTyped(expect, noun string, in io.Reader, out io.Writer) error {
	fmt.Fprintf(out, "type %s %q to confirm: ", noun, expect)
	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && line == "" {
		return exitcode.New(exitcode.Denied, "confirmation failed for %s %s", noun, expect)
	}
	if strings.TrimSpace(line) != expect {
		return exitcode.New(exitcode.Denied, "confirmation did not match %s %q", noun, expect)
	}
	return nil
}

func readPassword(in io.Reader, errw io.Writer, fromStdin bool) (string, error) {
	if fromStdin {
		b, err := io.ReadAll(io.LimitReader(in, 1<<20))
		if err != nil {
			return "", err
		}
		s := strings.TrimRight(string(b), "\r\n")
		if s == "" {
			return "", exitcode.New(exitcode.Usage, "empty password on stdin")
		}
		return s, nil
	}
	if !ttyCheck() {
		return "", exitcode.New(exitcode.Usage, "password prompt requires a TTY; use --password-stdin")
	}
	f, err := os.OpenFile(devTTY(), os.O_RDWR, 0)
	if err != nil {
		return "", exitcode.New(exitcode.Usage, "password prompt requires a TTY; use --password-stdin")
	}
	defer f.Close()
	fmt.Fprint(errw, "Password: ")
	b, err := term.ReadPassword(int(f.Fd()))
	fmt.Fprintln(errw)
	if err != nil {
		return "", err
	}
	if len(b) == 0 {
		return "", exitcode.New(exitcode.Usage, "empty password")
	}
	return string(b), nil
}
