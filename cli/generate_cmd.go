package cli

import (
	"fmt"
	"io"
	"log"

	parse "github.com/GrantSeltzer/karn/parse"
	"github.com/spf13/cobra"
)

type GenerateOptions struct{}

func NewGenerateCmd(out io.Writer, declarationDirectory string) *cobra.Command {

	genOpts := GenerateOptions{}

	generateCmd := &cobra.Command{
		Use:   "generate [options] <PROFILE_NAME>",
		Short: "generate seccomp and apparmor profiles from a karn profile",
		RunE: func(cmd *cobra.Command, args []string) error {
			// TODO: verify arguments
			return genOpts.Run(out, declarationDirectory, args[0])
		},
	}

	// Template for adding flags:
	// g := generateCmd.PersistentFlags()
	// g.StringVar(&genOpts.____, "flagName", "defaultValue", "description")
	// ...

	return generateCmd
}

func (genOpts *GenerateOptions) Run(out io.Writer, declarationDirectory string, pathToProfile string) error {

	x, err := parse.BuildSeccompConfig(pathToProfile, declarationDirectory)
	if err != nil {
		log.Fatal(err)
	}

	out.Write([]byte(fmt.Sprintf("%+v\n", x)))
	return nil
}
