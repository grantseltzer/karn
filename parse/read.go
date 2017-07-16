package parse

import (
	"io/ioutil"

	"github.com/BurntSushi/toml"
)

func ReadDeclarationString(tomlBlob string) (Declaration, error) {
	d := Declaration{}
	_, err := toml.Decode(tomlBlob, &d)
	return d, err
}

func ReadDeclarationFromFile(path string) (Declaration, error) {
	blob, err := ioutil.ReadFile(path)
	if err != nil {
		return Declaration{}, err
	}
	return ReadDeclarationString(string(blob))
}

func ReadDeclarationFiles(specifiedDeclarations []string, directory string) (map[string]*Declaration, error) {
	decs := map[string]*Declaration{}
	for _, specifiedDeclaration := range specifiedDeclarations {
		x, err := ReadDeclarationFromFile(directory + "/" + specifiedDeclaration + "_declaration.toml")
		if err != nil {
			return decs, err
		}
		decs[specifiedDeclaration] = &x
	}

	return decs, nil
}
