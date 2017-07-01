package cli

import (
	"fmt"
	"io"
	"log"

	parse "github.com/GrantSeltzer/karn/parse"
	"github.com/spf13/cobra"
)

type GenerateOptions struct {
	DeclarationDirectory string
}

func NewGenerateCmd(out io.Writer, arguments []string) *cobra.Command {

	genOpts := GenerateOptions{}

	generateCmd := &cobra.Command{
		Use:   "generate [options] <PROFILE_NAME>",
		Short: "generate seccomp and apparmor profiles from a karn profile",
		RunE: func(cmd *cobra.Command, args []string) error {
			// TODO: verify arguments
			return genOpts.Run(out, arguments)
		},
	}

	g := generateCmd.PersistentFlags()
	g.StringVarP(&genOpts.DeclarationDirectory, "declarations", "d", "~/.karn/declarations", "directory of declaration definitions")

	return generateCmd
}

func (genOpts *GenerateOptions) Run(out io.Writer, args []string) error {

	x, err := parse.BuildSeccompConfig(args[len(args)-1], genOpts.DeclarationDirectory)
	if err != nil {
		log.Fatal(err)
	}

	out.Write([]byte(fmt.Sprintf("%+v\n", x)))
	return nil
}
