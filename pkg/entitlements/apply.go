package entitlements

import (
	"github.com/pkg/errors"
	libseccomp "github.com/seccomp/libseccomp-golang"
	seccomp "github.com/seccomp/libseccomp-golang"
)

// BlacklistEntitlements will disallow the capabilities described by the entitlements
// that are passed. Any system call not included in the entitlements will be allowed by default
func BlacklistEntitlements(entitlements []Entitlement) error {
	return applyEntitlements(entitlements, libseccomp.ActAllow, libseccomp.ActErrno)
}

// WhitelistEntitlements will allow the capabilities described by the entitlements
// that are passed. Any system call not included in the entitlements will be disallowed by default
func WhitelistEntitlements(entitlements []Entitlement) error {
	return applyEntitlements(entitlements, libseccomp.ActErrno, libseccomp.ActAllow)
}

// applyEntitlements can be used to whitelist or blacklist a set of entitlements
func applyEntitlements(entitlements []Entitlement, defaultAction, entitlementAction libseccomp.ScmpAction) error {

	filter, err := libseccomp.NewFilter(defaultAction)
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
		for _, s := range e.Syscalls {

			syscall, err := seccomp.GetSyscallFromNameByArch(s, arch)
			if err != nil {
				return errors.Wrap(err, "could not detect syscall name")
			}

			err = filter.AddRule(syscall, entitlementAction)
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
