package main

import (
	"os"
)

func main() {
	karn := NewRootCmd(os.Args, os.Stdout)
	if err := karn.Execute(); err != nil {
		os.Exit(1)
	}
}
