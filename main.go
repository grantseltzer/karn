package main

import (
	"os"

	"github.com/GrantSeltzer/karn/karn"
)

func main() {
	karn := karn.NewRootCmd(os.Args, os.Stdout)
	if err := karn.Execute(); err != nil {
		os.Exit(1)
	}
}
