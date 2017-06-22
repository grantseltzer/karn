package karn

import (
	"errors"
	"fmt"

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

func BuildSeccompConfig(profilePath string, declarationsDirectory string) error {
	Profile, err := ReadProfileFromFile(profilePath)
	if err != nil {
		return err
	}

	Declarations, err := ReadDeclarationFiles(declarationsDirectory)
	if err != nil {
		return err
	}

	seccompSlice := []Seccomp{}
	for _, v := range Declarations {
		seccompSlice = append(seccompSlice, v.Seccomp)
	}
	defaultAction := DetermineSeccompDefault(seccompSlice)
	architecture := DetermineSeccompArchitectures(seccompSlice)

	for _, i := range Profile.FileSystem {
		dec := Declarations[i]
		if dec == nil {
			// Handle DECLARATION NOT FOUND, should probably be fatal
			return errors.New("")
		}
		actions, err := CollectSeccompActions(dec.Seccomp)
		if err != nil {
			return err
		}
	}

	// Create specs.Seccomp profile, add actions 1 by 1 using runtime-tools/generate package, use defaultAction and architecture

	return nil
}

func CollectSeccompActions(s Seccomp) ([]specs.LinuxSyscall, error) {

	actions := map[string][]string{
		"allow": s.Allow,
		"trap":  s.Trap,
		"trace": s.Trace,
		"kill":  s.Kill,
		"errno": s.Errno,
	}

	syscalls := []specs.LinuxSyscall{}

	for k, v := range actions {
		syscall := specs.LinuxSyscall{}
		syscall.Names = v
		parsedAction, err := parseAction(k)
		if err != nil {
			return syscalls, err
		}
		syscall.Action = parsedAction
		syscalls = append(syscalls, syscall)
	}

	return syscalls, nil
}

func DetermineSeccompDefault(seccomps []Seccomp) string {
	precedence := map[string]int{
		"Allow": 0,
		"Trap":  1,
		"Trace": 2,
		"Errno": 3,
		"Kill":  4,
	}

	currentDefault := "Allow"

	for _, s := range seccomps {
		if precedence[s.Default] > precedence[currentDefault] {
			currentDefault = s.Default
		}
	}
	return currentDefault
}

func DetermineSeccompArchitectures(seccomps []Seccomp) []string {
	architectures := []string{}
	for _, s := range seccomps {
		for _, a := range s.Architectures {
			appendIfMissing(&architectures, a)
		}
	}
	return architectures
}

func appendIfMissing(arches *[]string, newArch string) {
	for _, arch := range *arches {
		if arch == newArch {
			return
		}
	}
	*arches = append(*arches, newArch)
}

// Take passed action, return the SCMP_ACT_<ACTION> version of it
func parseAction(action string) (specs.LinuxSeccompAction, error) {

	var actions = map[string]specs.LinuxSeccompAction{
		"allow": specs.ActAllow,
		"errno": specs.ActErrno,
		"kill":  specs.ActKill,
		"trace": specs.ActTrace,
		"trap":  specs.ActTrap,
	}

	a, ok := actions[action]
	if !ok {
		return "", fmt.Errorf("unrecognized action: %s", action)
	}
	return a, nil
}
