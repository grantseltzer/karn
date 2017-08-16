package karn

import (
	"errors"
	"io"
)

// WriteAppArmorProfile takes the specified declarations and writes an apparmor profile to out
func WriteAppArmorProfile(out io.Writer, specifiedDeclarations []string, declarationsDirectory string) error {
	Declarations, err := readDeclarationFiles(specifiedDeclarations, declarationsDirectory)
	if err != nil {
		return err
	}

	_, apparmorProfile, err := createProfiles(Declarations)

	written, err := out.Write(apparmorProfile)
	if err != nil {
		return err
	}

	if written != len(apparmorProfile) {
		return errors.New("Incomplete apparmor profile written")
	}
	return nil
}
