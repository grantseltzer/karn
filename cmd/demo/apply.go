package main

import (
	"errors"

	seccomp "github.com/seccomp/libseccomp-golang"
)

func ApplyEntitlements(entitlementNames []string) error {

	syscallNames := []string{}

	if len(entitlementNames) == 1 {
		syscallNames = append(syscallNames, "execve")
		syscallNames = append(syscallNames, "execveat")
	}

	filter, err := seccomp.NewFilter(seccomp.ActAllow)
	if err != nil {
		return err
	}

	err = filter.AddArch(seccomp.ArchAMD64)
	if err != nil {
		return err
	}

	for _, name := range syscallNames {
		syscall, err := seccomp.GetSyscallFromName(name)
		if err != nil {
			return err
		}

		err = filter.AddRule(syscall, seccomp.ActKill)
		if err != nil {
			return err
		}
	}

	valid := filter.IsValid()
	if valid != true {
		return errors.New("INVALID!")
	}

	err = filter.Load()
	if err != nil {
		return err
	}

	return nil
}
