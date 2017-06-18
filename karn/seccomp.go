package karn

import (
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

func AddAllows(s Seccomp) specs.LinuxSyscall {
	syscalls := specs.LinuxSyscall{}
	Names := []string{}
	for _, a := range s.Allow {
		Names = append(Names, a)
	}
	syscalls.Names = Names
	syscalls.Action = specs.ActAllow
	return syscalls
}

func DetermineDefault(seccomps []Seccomp) string {
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
