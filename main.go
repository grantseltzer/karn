package main

import (
	"os"

	"github.com/GrantSeltzer/karn/cli"
)

const declarationDirectory = "declarations/"

func main() {
	karn := cli.NewRootCmd(os.Args, os.Stdout, declarationDirectory)
	if err := karn.Execute(); err != nil {
		os.Exit(1)
	}
}
