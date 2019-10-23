package main

import (
	"fmt"

	e "github.com/grantseltzer/karn/pkg/entitlements"
)

import "C"

//export ApplyEntitlementsByName
func ApplyEntitlementsByName(names []string) (errorCode int) {
	es, err := e.GetEntitlementsFromNames(names)
	if err != nil {
		fmt.Println(err)
		return -1
	}
	err = e.ApplyEntitlements(es)
	if err != nil {
		fmt.Println(err)
		return -1
	}

	return 0
}

func main() {}
