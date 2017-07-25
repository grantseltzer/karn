package parse

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// BuildSeccompConfig takes the user specified declarations and creates the seccomp output
func BuildSeccompConfig(specifiedDeclarations []string, declarationsDirectory string) (specs.LinuxSeccomp, error) {
	seccompSpec := specs.LinuxSeccomp{}

	// Read declarations into memory from declaration directory
	Declarations, err := readDeclarationFiles(specifiedDeclarations, declarationsDirectory)
	if err != nil {
		return seccompSpec, err
	}

	// Parse specified declarations for seccomp default action
	defaultAction, err := parseAction(determineSeccompDefault(Declarations))
	if err != nil {
		return seccompSpec, err
	}

	// Parse specified declarations for system architectures
	architectures, err := determineSeccompArchitectures(Declarations)
	if err != nil {
		return seccompSpec, err
	}

	// Parse specified declarations for syscall filters
	syscalls := []specs.LinuxSyscall{}
	for _, i := range specifiedDeclarations {
		dec := Declarations[i]
		if dec == nil {
			return seccompSpec, errors.New("declaration not found")
		}
		syscalls, err = collectSeccompActions(dec.SystemCalls, syscalls)
		if err != nil {
			return seccompSpec, err
		}
	}

	// Create runtime-spec Seccomp profile, add actions 1 by 1 using runtime-tools/generate package, use defaultAction and architecture
	seccompSpec.DefaultAction = specs.LinuxSeccompAction(defaultAction)
	for _, a := range architectures {
		seccompSpec.Architectures = append(seccompSpec.Architectures, specs.Arch(a))
	}
	seccompSpec.Syscalls = syscalls

	return seccompSpec, nil
}

// WriteSeccompProfile takes the specified declarations and writes a seccomp profile
func WriteSeccompProfile(out io.Writer, specifiedDeclarations []string, declarationsDirectory string) error {
	x, err := BuildSeccompConfig(specifiedDeclarations, declarationsDirectory)
	if err != nil {
		return err
	}

	seccompJSONProfile, err := json.MarshalIndent(x, "", " ")
	if err != nil {
		return err
	}
	out.Write(seccompJSONProfile)
	return nil
}

// collectSeccompActions takes a SystemCalls struct from a declaration and appends it to the outputted spec
func collectSeccompActions(s SystemCalls, existingSyscalls []specs.LinuxSyscall) ([]specs.LinuxSyscall, error) {

	actions := map[string][]string{
		"allow": s.Allow,
		"trap":  s.Trap,
		"trace": s.Trace,
		"kill":  s.Kill,
		"errno": s.Errno,
	}

	appended := false

	// Iterate through new syscalls actions
	for k, v := range actions {

		// Skip when no actions are specified
		if v == nil {
			continue
		}

		action, _ := parseAction(k)

		// Check if there's already a matching rule TODO: check arguments
		for i := range existingSyscalls {
			// Traverse to action
			if existingSyscalls[i].Action == action {
				// Append new syscall rule if it doesn't already exist
				for _, syscallName := range v {
					appendIfMissing(&existingSyscalls[i].Names, syscallName)
					appended = true
				}
			}
		}

		// Create new rule
		if !appended {
			syscall := specs.LinuxSyscall{}
			syscall.Names = v
			syscall.Action = action
			existingSyscalls = append(existingSyscalls, syscall)
			appended = false
		}
	}

	return existingSyscalls, nil
}

// determineSeccompDefault takes the mapping of specified declarations and returns the default action
func determineSeccompDefault(specifiedDeclarations map[string]*Declaration) string {

	// Arbitrary rule for precedences of actions to be set as default,
	// should explore other mechanism for determining this
	precedence := map[string]int{
		"allow": 0,
		"trap":  1,
		"trace": 2,
		"errno": 3,
		"kill":  4,
	}

	currentDefault := "allow"

	for _, s := range specifiedDeclarations {
		if precedence[s.System.DefaultSyscallAction] > precedence[currentDefault] {
			currentDefault = s.System.DefaultSyscallAction
		}
	}
	return currentDefault
}

// determineSeccompArchitectures takes the mapping of specified delarations and returns the specified architectures
func determineSeccompArchitectures(specifiedDeclarations map[string]*Declaration) ([]string, error) {
	architectures := []string{}
	for _, s := range specifiedDeclarations {
		for _, a := range s.System.Architectures {
			arch, err := parseArchitecture(a)
			if err != nil {
				return architectures, err
			}
			appendIfMissing(&architectures, string(arch))
		}
	}
	return architectures, nil
}

// safe append
func appendIfMissing(existing *[]string, new string) {
	for _, element := range *existing {
		if element == new {
			return
		}
	}
	*existing = append(*existing, new)
}

// Take passed action, return the oci spec version of it
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

// Take passes arch, return the oci spec version of it
func parseArchitecture(arch string) (specs.Arch, error) {

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
