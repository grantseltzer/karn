package karn

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// TODO: Should be part of main
// WriteSeccompProfile takes the specified declarations and writes a seccomp profile
func WriteSeccompProfile(out io.Writer, specifiedDeclarations []string, declarationsDirectory string) error {
	Declarations, err := readDeclarationFiles(specifiedDeclarations, declarationsDirectory)
	if err != nil {
		return err
	}

	seccompProfile, _, err := createProfiles(Declarations)
	jsonSeccompProfile, err := json.MarshalIndent(seccompProfile, "", " ")
	if err != nil {
		return err
	}

	written, err := out.Write(jsonSeccompProfile)
	if err != nil {
		return err
	}

	if written != len(jsonSeccompProfile) {
		return errors.New("Incomplete seccomp profile written")
	}
	return nil
}

// Take passes arch, return the oci spec version of it
func ociArchitecture(arch string) (specs.Arch, error) {

	var arches = map[string]specs.Arch{
		"x86":       specs.ArchX86,
		"x86_64":    specs.ArchX86_64,
		"x32":       specs.ArchX32,
		"arm":       specs.ArchARM,
		"aarch64":   specs.ArchAARCH64,
		"mips":      specs.ArchMIPS,
		"mips64":    specs.ArchMIPS64,
		"mips64n32": specs.ArchMIPS64N32,
		"ppc":       specs.ArchPPC,
		"ppc64":     specs.ArchPPC64,
		"ppc64LE":   specs.ArchPPC64LE,
		"s390":      specs.ArchS390,
		"s390x":     specs.ArchS390X,
		"parisc":    specs.ArchPARISC,
		"parsic64":  specs.ArchPARISC64,
	}

	a, ok := arches[arch]
	if !ok {
		return "", fmt.Errorf("unrecognized architecture: %s", arch)
	}
	return a, nil
}

// Take passed action, return the oci spec version of it
func ociSeccompAction(action string) (specs.LinuxSeccompAction, error) {

	var actions = map[string]specs.LinuxSeccompAction{
		"allow": specs.ActAllow,
		"errno": specs.ActErrno,
		"kill":  specs.ActKill,
		"trace": specs.ActTrace,
		"trap":  specs.ActTrap,
	}

	a, ok := actions[action]
	if !ok {
		return a, fmt.Errorf("unrecognized action: %s")
	}
	return a, nil
}

// collectArguments
func collectArguments(syscall string) (syscallName string, arguments specs.LinuxSeccompArg, err error) {
	// Split syscall from arguments
	brokenByArgs := strings.Split(syscall, ":")

	if len(brokenByArgs) == 1 {
		return brokenByArgs[0], specs.LinuxSeccompArg{}, nil
	}

	// Validate proper arguments
	if len(brokenByArgs) != 5 {
		return brokenByArgs[0],
			specs.LinuxSeccompArg{},
			fmt.Errorf("malformed syscall arguments: %+v", brokenByArgs)
	}

	// Check type assertions work properly
	index, err := strconv.ParseUint(brokenByArgs[1], 10, 64)
	if err != nil {
		return brokenByArgs[0], specs.LinuxSeccompArg{}, err
	}

	value, err := strconv.ParseUint(brokenByArgs[2], 10, 64)
	if err != nil {
		return brokenByArgs[0], specs.LinuxSeccompArg{}, err
	}

	valueTwo, err := strconv.ParseUint(brokenByArgs[3], 10, 64)
	if err != nil {
		return brokenByArgs[0], specs.LinuxSeccompArg{}, err
	}

	op, err := ociSeccompOperator(brokenByArgs[4])
	if err != nil {
		return brokenByArgs[0], specs.LinuxSeccompArg{}, err
	}
	arg := specs.LinuxSeccompArg{uint(index), value, valueTwo, op}

	return brokenByArgs[0], arg, nil
}

func ociSeccompOperator(operator string) (specs.LinuxSeccompOperator, error) {
	operators := map[string]specs.LinuxSeccompOperator{
		"NE": specs.OpNotEqual,
		"LT": specs.OpLessThan,
		"LE": specs.OpLessEqual,
		"EQ": specs.OpEqualTo,
		"GE": specs.OpGreaterEqual,
		"GT": specs.OpGreaterThan,
		"ME": specs.OpMaskedEqual,
	}
	o, ok := operators[operator]
	if !ok {
		return "", fmt.Errorf("unrecognized operator: %s", operator)
	}
	return o, nil
}
