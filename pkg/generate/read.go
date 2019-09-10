package generate

import (
	"io/ioutil"
	"strings"

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

func getInAssets(declaration string) (decl string, ok bool) {
	for _, asset := range AssetNames() {
		if strings.Contains(asset, declaration) {
			return asset, true
		}
	}
	return "", false
}

func readDeclarationFiles(specifiedDeclarations []string, directory string) ([]Declaration, error) {
	decs := []Declaration{}
	for i := range specifiedDeclarations {

		// check specified declarations in embedded assets first
		asset, ok := getInAssets(specifiedDeclarations[i])
		if ok {
			dec, err := readDeclarationString(string(MustAsset(asset)))
			if err != nil {
				return decs, err
			}
			decs = append(decs, dec)
			continue
		}

		x, err := readDeclarationFromFile(directory + "/" + specifiedDeclarations[i] + "_declaration.toml")
		if err != nil {
			return decs, err
		}
		decs = append(decs, x)
	}

	return decs, nil
}
