package main

import (
	"io"
	"os"

	"github.com/GrantSeltzer/karn/karn"
	"github.com/spf13/cobra"
)

var global_verbose bool

type GenerateOptions struct {
	declarationDirectory string
	seccomp              bool
	apparmor             bool
	outputDirectory      string
}

func NewGenerateCmd(out io.Writer) *cobra.Command {

	genOpts := GenerateOptions{}

	generateCmd := &cobra.Command{
		Use:   "generate [--seccomp/--apparmor] [options] [permissions]",
		Short: "generate seccomp and apparmor profiles from a karn profile",
		RunE: func(cmd *cobra.Command, args []string) error {
			// TODO: verify arguments
			return genOpts.Run(out, args)
		},
	}

	homedir := os.Getenv("HOME")

	g := generateCmd.PersistentFlags()
	g.StringVarP(&genOpts.declarationDirectory, "declarations", "d", homedir+"/.karn/declarations", "directory of declaration definitions")
	g.BoolVar(&genOpts.seccomp, "seccomp", false, "output seccomp profile")
	g.BoolVar(&genOpts.apparmor, "apparmor", false, "output apparmor profile")
	g.BoolVarP(&global_verbose, "verbose", "v", false, "turn on logs for computation")
	return generateCmd
}

func (genOpts *GenerateOptions) Run(out io.Writer, args []string) error {

	if genOpts.seccomp {
		err := karn.WriteSeccompProfile(out, args, genOpts.declarationDirectory)
		if err != nil {
			return err
		}
	}

	if genOpts.apparmor {
		err := karn.WriteAppArmorProfile(out, args, genOpts.declarationDirectory)
		if err != nil {
			return err
		}
	}

	if !genOpts.seccomp && !genOpts.apparmor {
		out.Write([]byte("Please specify profile output type with --seccomp or --apparmor"))
	}

	return nil
}
