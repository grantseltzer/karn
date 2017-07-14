package cli

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
)

func NewRootCmd(arguments []string, out io.Writer) *cobra.Command {

	var karnRootCommand = &cobra.Command{
		Use:   "capsule8 [OPTIONS] <Profile_Name.toml>",
		Short: "command-line client to capsule8 API",
		Run: func(cmd *cobra.Command, args []string) {

			if len(args) == 0 {
				fmt.Fprintf(os.Stderr, "not enough arguments, please specify a profile location")
				fmt.Fprintf(os.Stderr, "Use `karn --help` for more info\n")
				os.Exit(1)
			}
			// TODO: verify sub commands
		},
	}

	// Uncomment to add flags/subcommands
	// rootFlags := karnRootCommand.PersistentFlags()

	karnRootCommand.AddCommand(
		NewGenerateCmd(out),
		NewVerifyCmd(),
	)

	return karnRootCommand
}
