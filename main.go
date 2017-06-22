package main

import (
	"fmt"
	"log"

	"github.com/GrantSeltzer/karn/parse"
)

const declarationDirectory = "/home/grant/karn/declarations/"

func main() {
	Declarations, err := karn.ReadDeclarationFiles(declarationDirectory)
	if err != nil {
		log.Fatal(err)
	}

	Seccomps := []karn.Seccomp{}

	for _, d := range Declarations {
		Seccomps = append(Seccomps, d.Seccomp)
	}

	seccompDefault := karn.DetermineSeccompDefault(Seccomps)
	fmt.Println(seccompDefault)
}
