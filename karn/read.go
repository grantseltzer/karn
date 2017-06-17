package karn

import "github.com/BurntSushi/toml"

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
