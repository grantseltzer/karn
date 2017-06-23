package karn

import (
	"errors"
	"fmt"

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

func BuildSeccompConfig(profilePath string, declarationsDirectory string) (specs.LinuxSeccomp, error) {
	seccompSpec := specs.LinuxSeccomp{}
	Profile, err := ReadProfileFromFile(profilePath)
	if err != nil {
		return seccompSpec, err
	}

	Declarations, err := ReadDeclarationFiles(declarationsDirectory)
	if err != nil {
		return seccompSpec, err
	}

	seccompSlice := []Seccomp{}
	for _, v := range Declarations {
		seccompSlice = append(seccompSlice, v.Seccomp)
	}
	defaultAction := DetermineSeccompDefault(seccompSlice)
	architectures := DetermineSeccompArchitectures(seccompSlice)

	syscalls := []specs.LinuxSyscall{}
	for _, i := range Profile.FileSystem {
		dec := Declarations[i]
		if dec == nil {
			return seccompSpec, errors.New("declaration not found")
		}
		syscalls, err = CollectSeccompActions(dec.Seccomp)
		if err != nil {
			return seccompSpec, err
		}
	}

	// Create specs.Seccomp profile, add actions 1 by 1 using runtime-tools/generate package, use defaultAction and architecture
	seccompSpec.DefaultAction = specs.LinuxSeccompAction(defaultAction)
	for _, a := range architectures {
		seccompSpec.Architectures = append(seccompSpec.Architectures, specs.Arch(a))
	}
	seccompSpec.Syscalls = syscalls

	return seccompSpec, nil
}

func CollectSeccompActions(s Seccomp) ([]specs.LinuxSyscall, error) {

	actions := map[string][]string{
		"Allow": s.Allow,
		"Trap":  s.Trap,
		"Trace": s.Trace,
		"Kill":  s.Kill,
		"Errno": s.Errno,
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
		"SCMP_ACT_ALLOW": 0,
		"SCMP_ACT_TRAP":  1,
		"SCMP_ACT_TRACE": 2,
		"SCMP_ACT_ERRNO": 3,
		"SCMP_ACT_KILL":  4,
	}

	currentDefault := "SCMP_ACT_ALLOW"

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
		"Allow": specs.ActAllow,
		"Errno": specs.ActErrno,
		"Kill":  specs.ActKill,
		"Trace": specs.ActTrace,
		"Trap":  specs.ActTrap,
	}

	a, ok := actions[action]
	if !ok {
		return "", fmt.Errorf("unrecognized action: %s", action)
	}
	return a, nil
}
