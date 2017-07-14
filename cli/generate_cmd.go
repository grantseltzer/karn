package cli

import (
	"io"
	"os"

	"encoding/json"

	parse "github.com/GrantSeltzer/karn/parse"
	"github.com/spf13/cobra"
)

type GenerateOptions struct {
	declarationDirectory string
}

func NewGenerateCmd(out io.Writer) *cobra.Command {

	genOpts := GenerateOptions{}

	generateCmd := &cobra.Command{
		Use:   "generate [<DECLARATION>,...]",
		Short: "generate seccomp and apparmor profiles from a karn profile",
		RunE: func(cmd *cobra.Command, args []string) error {
			// TODO: verify arguments
			return genOpts.Run(out, args)
		},
	}

	homedir := os.Getenv("HOME")

	g := generateCmd.PersistentFlags()
	g.StringVarP(&genOpts.declarationDirectory, "declarations", "d", homedir+"/.karn/declarations", "directory of declaration definitions")

	return generateCmd
}

func (genOpts *GenerateOptions) Run(out io.Writer, args []string) error {

	x, err := parse.BuildSeccompConfig(args, genOpts.declarationDirectory)
	if err != nil {
		return err
	}

	seccompJSONProfile, err := json.MarshalIndent(x, "", " ")
	if err != nil {
		return err
	}

	out.Write(seccompJSONProfile)

	return nil
}
