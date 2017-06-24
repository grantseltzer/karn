package main

import (
	"fmt"
	"io"
	"log"
	"os"

	parse "github.com/GrantSeltzer/karn/parse"
	"github.com/spf13/cobra"
)

const declarationDirectory = "declarations/"

func newRootCmd(rguments []string, out io.Writer) *cobra.Command {

	var karnRootCommand = &cobra.Command{
		Use:   "capsule8 [OPTIONS] <Profile_Name.toml>",
		Short: "command-line client to capsule8 API",
		Run: func(cmd *cobra.Command, args []string) {

			if len(args) == 0 {
				fmt.Fprintf(os.Stderr, "not enough arguments, please specify a profile location")
				fmt.Fprintf(os.Stderr, "Use `karn --help` for more info\n")
				os.Exit(1)
			}

			x, err := parse.BuildSeccompConfig(args[0], declarationDirectory)
			if err != nil {
				log.Fatal(err)
			}

			out.Write([]byte(fmt.Sprintf("%+v\n", x)))
		},
	}

	// Uncomment to add flags/subcommands
	// rootFlags := karnRootCommand.PersistentFlags()
	// karnRootCommand.AddCommand()

	return karnRootCommand
}

func main() {
	k := newRootCmd(os.Args, os.Stdout)
	if err := k.Execute(); err != nil {
		os.Exit(1)
	}
}
