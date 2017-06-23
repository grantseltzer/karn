package main

import (
	"encoding/json"
	"fmt"
	"log"

	parse "github.com/GrantSeltzer/karn/parse"
)

const declarationDirectory = "declarations/"

func main() {

	x, err := parse.BuildSeccompConfig("prof.toml", declarationDirectory)
	if err != nil {
		log.Fatal(err)
	}

	asJson, _ := json.Marshal(x)
	fmt.Println(string(asJson))
}
