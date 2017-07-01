package main

import (
	"os"

	"github.com/GrantSeltzer/karn/cli"
)

func main() {
	karn := cli.NewRootCmd(os.Args, os.Stdout)
	if err := karn.Execute(); err != nil {
		os.Exit(1)
	}
}
