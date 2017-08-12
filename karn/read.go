package karn

import (
	"io/ioutil"

	"github.com/BurntSushi/toml"
)

func readDeclarationString(tomlBlob string) (Declaration, error) {
	d := Declaration{}
	_, err := toml.Decode(tomlBlob, &d)
	return d, err
}

func readDeclarationFromFile(path string) (Declaration, error) {
	blob, err := ioutil.ReadFile(path)
	if err != nil {
		return Declaration{}, err
	}
	return readDeclarationString(string(blob))
}

func readDeclarationFiles(specifiedDeclarations []string, directory string) ([]Declaration, error) {
	decs := []Declaration{}
	for i := range specifiedDeclarations {
		x, err := readDeclarationFromFile(directory + "/" + specifiedDeclarations[i] + "_declaration.toml")
		if err != nil {
			return decs, err
		}
		decs[i] = &x
	}

	return decs, nil
}
