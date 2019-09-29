package entitlements

import (
	"github.com/pkg/errors"
	libseccomp "github.com/seccomp/libseccomp-golang"
	seccomp "github.com/seccomp/libseccomp-golang"
)

func ApplyEntitlements(entitlements []Entitlement) error {
	filter, err := libseccomp.NewFilter(libseccomp.ActErrno)
	if err != nil {
		return err
	}

	arch, err := seccomp.GetNativeArch()
	if err != nil {
		return errors.Wrap(err, "could not detect architecture for seccomp filter")
	}

	err = filter.AddArch(arch)
	if err != nil {
		return errors.Wrap(err, "could not add architecture to seccomp filter")
	}

	for _, e := range entitlements {
		for _, s := range e.Allowed {

			syscall, err := seccomp.GetSyscallFromNameByArch(s, arch)
			if err != nil {
				return errors.Wrap(err, "could not detect syscall name")
			}

			err = filter.AddRule(syscall, seccomp.ActAllow)
			if err != nil {
				return errors.Wrap(err, "could not apply syscall rule")
			}
		}
	}

	if !filter.IsValid() {
		return errors.New("invalid seccomp filter")
	}

	err = filter.Load()
	if err != nil {
		return errors.Wrap(err, "could not load seccomp filter into kernel")
	}

	return nil
}
