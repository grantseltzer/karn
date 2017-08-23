package generate

import (
	"io"
)

// WriteAppArmorProfile takes the specified declarations and writes an apparmor profile to out
func WriteAppArmorProfile(out io.Writer, specifiedDeclarations []string, declarationsDirectory string) error {
	Declarations, err := readDeclarationFiles(specifiedDeclarations, declarationsDirectory)
	if err != nil {
		return err
	}

	_, apparmorProfile, err := createProfiles(Declarations)
	if err != nil {
		return err
	}

	err = apparmorProfile.Generate(out)
	if err != nil {
		return err
	}

	return nil
}
