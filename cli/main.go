package main

import (
	"fmt"
	"os"
)

func main() {
	karn := NewRootCmd(os.Args, os.Stdout)
	if err := karn.Execute(); err != nil {
		fmt.Println("Error: ", err)
		os.Exit(1)
	}
}
