package cmd

import (
	"errors"
	"fmt"
	"os"
)

func Execute() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) < 2 {
		return errors.New("no subcommand specified")
	}

	switch os.Args[1] {
	case "login":
		return runLogin(os.Args[2:])
	case "cce":
		return runCCE(os.Args[2:])
	default:
		return fmt.Errorf("unknown subcommand: %s", os.Args[1])
	}
}
