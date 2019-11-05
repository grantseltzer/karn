package main

import (
	"log"
	"os"

	en "github.com/grantseltzer/karn/pkg/entitlements"
)

//
// This is an example of using the chown entitlement to grant
//     the running program access to the chown family of
//     system calls. In this case, chowning to root still requires
//     running as root. If you remove the chown entitlment and
//     compile/run as root it still wouldn't work.
//

func main() {

	entitlements := []en.Entitlement{
		en.Chown, // remove to test
	}

	err := en.ApplyEntitlements(entitlements)
	if err != nil {
		log.Fatal(err)
	}

	err = os.Chown("./testfile.txt", 1001, 1001)
	if err != nil {
		log.Fatal(err)
	}
}
