package main

import (
	"os"

	"github.com/jiamingZhao-zhao/ssh-cli/internal/cli"
	"github.com/jiamingZhao-zhao/ssh-cli/internal/output"
)

func main() {
	output.EnableUTF8()
	os.Exit(cli.Execute(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
