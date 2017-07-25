package cli

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
)

func NewRootCmd(arguments []string, out io.Writer) *cobra.Command {

	var karnRootCommand = &cobra.Command{
		Use:   "karn [OPTIONS] <Profile_Name.toml>",
		Short: "A simple and easy to use linux security profile generator",
		Run: func(cmd *cobra.Command, args []string) {
			// TODO: verify sub commands
		},
	}

	// Uncomment to add flags/subcommands
	// rootFlags := karnRootCommand.PersistentFlags()

	karnRootCommand.AddCommand(
		NewGenerateCmd(out),
		NewVerifyCmd(),
	)

	if len(os.Args) == 1 {
		fmt.Fprintf(os.Stderr, "not enough arguments, please specify a profile location\n\n")
		karnRootCommand.Help()
		os.Exit(1)
	}

	return karnRootCommand
}
