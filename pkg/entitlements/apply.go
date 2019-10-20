package entitlements

import (
	"github.com/pkg/errors"
	libseccomp "github.com/seccomp/libseccomp-golang"
)

// ApplyEntitlements will allow the syscalls described by the entitlements
// that are passed.
func ApplyEntitlements(entitlements []Entitlement) error {
	entitlementsToDeny := removeEntitlementsFromDefaultDeny(entitlements)
	return applyEntitlements(entitlementsToDeny, libseccomp.ActAllow, libseccomp.ActErrno)
}

var alreadyInstalledFilter = false

// applyEntitlements can be used to allow or deny a set of entitlements
func applyEntitlements(entitlements []Entitlement, defaultAction, entitlementAction libseccomp.ScmpAction) error {
	if alreadyInstalledFilter {
		return errors.New("you may only apply entitlements once")
	}

	filter, err := libseccomp.NewFilter(defaultAction)
	if err != nil {
		return err
	}

	arch, err := libseccomp.GetNativeArch()
	if err != nil {
		return errors.Wrap(err, "could not detect architecture for seccomp filter")
	}

	err = filter.AddArch(arch)
	if err != nil {
		return errors.Wrap(err, "could not add architecture to seccomp filter")
	}

	for _, e := range entitlements {
		for _, s := range e.Syscalls {

			syscall, err := libseccomp.GetSyscallFromNameByArch(s, arch)
			if err != nil {
				return errors.Wrap(err, "could not detect syscall name")
			}

			logIfEnabled("\tapplying policy: %s for: %v\n", entitlementAction, syscall)
			err = filter.AddRule(syscall, entitlementAction)
			if err != nil {
				return errors.Wrap(err, "could not apply syscall rule")
			}
		}
	}

	if !filter.IsValid() {
		return errors.New("invalid seccomp filter")
	}

	logIfEnabled("loading seccomp filter into kernel")
	alreadyInstalledFilter = true
	err = filter.Load()
	if err != nil {
		return errors.Wrap(err, "could not load seccomp filter into kernel")
	}

	return nil
}

// removeEntitlementsFromDefaultDeny returns a slice of entitlements created
// by removing the specified entitlements from the default ones
func removeEntitlementsFromDefaultDeny(entitlements []Entitlement) []Entitlement {

	defaultDenyCopy := copyOfDefaultDeny()

	for _, e := range entitlements {
		logIfEnabled("allowing entitlement: %s\n", e.Name)
		delete(defaultDenyCopy, e.Name)
	}

	deny := []Entitlement{}
	for _, v := range defaultDenyCopy {
		logIfEnabled("denying entitlement: %s\n", v.Name)
		deny = append(deny, v)
	}
	return deny
}

func copyOfDefaultDeny() map[string]Entitlement {
	x := map[string]Entitlement{}
	for k, v := range defaultDeny {
		x[k] = *v
	}
	return x
}
