package karn

import (
	"fmt"
	"io/ioutil"

	"github.com/BurntSushi/toml"
)

func ReadDeclarationString(tomlBlob string) (Declaration, error) {
	d := Declaration{}
	_, err := toml.Decode(tomlBlob, &d)
	return d, err
}

func ReadSeccompString(tomlBlob string) (Seccomp, error) {
	s := Seccomp{}
	_, err := toml.Decode(tomlBlob, &s)
	return s, err
}

func ReadAppArmorString(tomlBlob string) (AppArmor, error) {
	a := AppArmor{}
	_, err := toml.Decode(tomlBlob, &a)
	return a, err
}

func ReadDeclarationFromFile(path string) (Declaration, error) {
	blob, err := ioutil.ReadFile(path)
	if err != nil {
		return Declaration{}, err
	}
	return ReadDeclarationString(string(blob))
}

func ReadDeclarationFiles(directory string) ([]Declaration, error) {
	decs := []Declaration{}
	files, err := ioutil.ReadDir(directory)
	if err != nil {
		return decs, err
	}

	for _, file := range files {
		fmt.Println(file.Name())
		x, err := ReadDeclarationFromFile(directory + "/" + file.Name())
		if err != nil {
			return decs, err
		}
		decs = append(decs, x)
	}
	return decs, nil
}

func ReadProfileString(tomlBlob string) (Profile, error) {
	p := Profile{}
	_, err := toml.Decode(tomlBlob, &p)
	return p, err
}

func ReadProfileFromFile(path string) (Profile, error) {
	prof := Profile{}
	blob, err := ioutil.ReadFile(path)
	if err != nil {
		return prof, err
	}
	return ReadProfileString(string(blob))
}
