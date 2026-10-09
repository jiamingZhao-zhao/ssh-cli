package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/confirmgate"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/exitcode"
)

// withConfirm runs op once. If it returns a confirmgate error, the phrase is
// collected (--yes on a TTY, or a typed prompt) and op runs again.
func (a *App) withConfirm(op func(phrase string) error) error {
	err := op("")
	var ce *confirmgate.Error
	if !errors.As(err, &ce) {
		return catalogErr(err)
	}
	phrase, cerr := a.supplyPhrase(ce.Phrase)
	if cerr != nil {
		return cerr
	}
	return catalogErr(op(phrase))
}

func (a *App) supplyPhrase(expect string) (string, error) {
	if a.Yes {
		if !ttyCheck() {
			return "", exitcode.New(exitcode.Denied, "--yes is only valid on an interactive TTY")
		}
		return expect, nil
	}
	if !ttyCheck() {
		return "", exitcode.New(exitcode.Denied, "type %q to confirm; non-interactive callers are refused", expect)
	}
	f, err := os.OpenFile(devTTY(), os.O_RDWR, 0)
	if err != nil {
		return "", exitcode.New(exitcode.Denied, "confirmation requires an interactive TTY")
	}
	defer f.Close()
	if err := confirmTyped(expect, "confirmation", f, f); err != nil {
		return "", err
	}
	return expect, nil
}

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
