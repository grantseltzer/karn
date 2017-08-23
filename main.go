package main

import (
	"fmt"
	"os"

	"github.com/GrantSeltzer/karn/cli"
)

func main() {
	karn := cli.NewRootCmd(os.Args, os.Stdout)
	if err := karn.Execute(); err != nil {
		fmt.Println("Error: ", err)
		os.Exit(1)
	}
}
