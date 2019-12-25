package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"

	libentitlements "github.com/grantseltzer/karn/pkg/entitlements"
	"github.com/spf13/cobra"
)

func main() {
	var list bool

	var karnCommand = &cobra.Command{
		Use:   "karn ['--' FLAGS] [Entitlements]",
		Short: "A simple generator of OCI-compliant seccomp profiles based on entitlements",
		Args:  verifyEntitlementArgs,
		RunE: func(cmd *cobra.Command, args []string) error {

			if list {
				listOfEntitlements := libentitlements.ListEntitlements()
				for i := range listOfEntitlements {
					fmt.Println(listOfEntitlements[i])
				}
				return nil
			}

			entitlements, err := libentitlements.GetEntitlementsFromNames(args)
			if err != nil {
				return err
			}
			spec := libentitlements.CreateOCIProfileFromEntitlements(entitlements)

			jsonSpec, err := json.MarshalIndent(spec, "", " ")
			if err != nil {
				return errors.New("error preparing JSON seccomp profile")
			}

			fmt.Printf("%s\n", jsonSpec)
			return nil
		},
	}

	k := karnCommand.PersistentFlags()

	k.BoolVarP(&list, "list", "l", false, "list available entitlements")

	err := karnCommand.Execute()
	if err != nil {
		log.Fatal(err)
	}
}

// verifyEntitlementArgs accumulates all invalid entitlement args into a single error message
func verifyEntitlementArgs(cmd *cobra.Command, args []string) error {

	invalidEntitlements := []string{}
	for _, arg := range args {
		if !libentitlements.ValidEntitlement(arg) {
			invalidEntitlements = append(invalidEntitlements, arg)
		}
	}

	if len(invalidEntitlements) != 0 {
		return fmt.Errorf("invalid entitlement names: %v", invalidEntitlements)
	}

	return nil
}
