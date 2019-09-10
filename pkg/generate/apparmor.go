package generate

import (
	"html/template"
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

// Generate uses the baseTemplate to generate an apparmor profile
// for the ProfileConfig passed.
func (profile *AppArmorProfileConfig) Generate(out io.Writer) error {
	compiled, err := template.New("apparmor_profile").Parse(baseTemplate)
	if err != nil {
		return err
	}

	err = compiled.Execute(out, profile)
	if err != nil {
		return err
	}

	return nil
}
