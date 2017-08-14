package karn

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

func combineDeclarations(declarations []Declaration) (specs.LinuxSeccomp,  ,error) {

	var (
		secAllows []string
		secTraps  []string
		secTraces []string
		secKills  []string
		secErrnos []string

		capAllows []string
		capDenies []string

		fsReadOnlies    []string
		fsLogPaths      []string
		fsWritablePaths []string
		fsAllowExecs    []string
		fsDenyExecs     []string

		netRaw       bool
		netPacket    bool
		netProtocols []string

		sysArches        []string
		sysDefaultAction string
	)

	// Combine declaration fields
	for _, dec := range declarations {

		// System calls
		secAllows = append(secAllows, dec.SystemCalls.Allow...)
		secTraps = append(secTraps, dec.SystemCalls.Trap...)
		secTraces = append(secTraces, dec.SystemCalls.Trace...)
		secKills = append(secKills, dec.SystemCalls.Kill...)
		secErrnos = append(secErrnos, dec.SystemCalls.Errno...)

		// Capabilities
		capAllows = append(capAllows, dec.Capabilities.Allow...)
		capDenies = append(capDenies, dec.Capabilities.Deny...)

		// File system rules
		fsReadOnlies = append(fsReadOnlies, dec.Filesystem.ReadOnlyPaths...)
		fsLogPaths = append(fsLogPaths, dec.Filesystem.LogOnWritePaths...)
		fsWritablePaths = append(fsWritablePaths, dec.Filesystem.WritablePaths...)
		fsAllowExecs = append(fsAllowExecs, dec.Filesystem.AllowExec...)
		fsDenyExecs = append(fsDenyExecs, dec.Filesystem.DenyExec...)

		// Network Configurations
		netRaw = netRaw && dec.Network.Raw
		netPacket = netPacket && dec.Network.Packet
		netProtocols = append(netProtocols, dec.Network.Protocols...)

		// System Configurations
		sysArches = append(sysArches, dec.System.Architectures...)

		if dec.System.DefaultSyscallAction != "" {
			sysDefaultAction = dec.System.DefaultSyscallAction
		}
	}

	// Determine the action for each syscall rule based on precedence
	// explained here: https://www.kernel.org/doc/Documentation/prctl/seccomp_filter.txt
	syscallRules := make(map[string]specs.LinuxSeccompAction)

	for _, syscall := range secAllows {
		syscallRules[syscall] = specs.ActAllow
	}

	for _, syscall := range secTraces {
		syscallRules[syscall] = specs.ActTrace
	}

	for _, syscall := range secTraps {
		syscallRules[syscall] = specs.ActTrap
	}

	for _, syscall := range secErrnos {
		syscallRules[syscall] = specs.ActErrno
	}

	for _, syscall := range secKills {
		syscallRules[syscall] = specs.ActKill
	}

	seccompProfile := specs.LinuxSeccomp{}

	allowRule := specs.LinuxSyscall{Action: specs.ActAllow}
	trapRule := specs.LinuxSyscall{Action: specs.ActTrap}
	traceRule := specs.LinuxSyscall{Action: specs.ActTrace}
	errnoRule := specs.LinuxSyscall{Action: specs.ActErrno}
	killRule := specs.LinuxSyscall{Action: specs.ActKill}

	// Create seccomp rules
	for syscall, seccompAction := range syscallRules {

		// If syscall arguments were specified, build and append unique filter
		if strings.Contains(syscall, ":") {

			name, args, err := collectArguments(syscall)
			if err != nil {
				return seccompProfile, err
			}

			new := specs.LinuxSyscall{
				Names:  []string{name},
				Action: seccompAction,
				Args:   []specs.LinuxSeccompArg{args},
			}

			seccompProfile.Syscalls = append(seccompProfile.Syscalls, new)
			continue
		}

		// Add to argument-less rules
		switch seccompAction {
		case specs.ActAllow:
			allowRule.Names = append(allowRule.Names, syscall)
		case specs.ActTrap:
			trapRule.Names = append(trapRule.Names, syscall)
		case specs.ActTrace:
			traceRule.Names = append(traceRule.Names, syscall)
		case specs.ActErrno:
			errnoRule.Names = append(errnoRule.Names, syscall)
		case specs.ActKill:
			killRule.Names = append(killRule.Names, syscall)
		default:
			return seccompProfile, errors.New("unrecognized seccomp action")
		}
	}

	// Add argument-less rules
	if len(allowRule.Names) > 0 {
		seccompProfile.Syscalls = append(seccompProfile.Syscalls, allowRule)
	}

	if len(trapRule.Names) > 0 {
		seccompProfile.Syscalls = append(seccompProfile.Syscalls, trapRule)
	}

	if len(traceRule.Names) > 0 {
		seccompProfile.Syscalls = append(seccompProfile.Syscalls, traceRule)
	}

	if len(errnoRule.Names) > 0 {
		seccompProfile.Syscalls = append(seccompProfile.Syscalls, errnoRule)
	}

	if len(killRule.Names) > 0 {
		seccompProfile.Syscalls = append(seccompProfile.Syscalls, killRule)
	}

	// Determine seccomp architectures
	for _, i := range sysArches {
		ociArch, err := ociArchitecture(i)
		if err != nil {
			return seccompProfile, fmt.Errorf("unrecognized architecture: ", i)
		}
		seccompProfile.Architectures = append(seccompProfile.Architectures, ociArch)
	}

	// Set seccomp default action
	def, err := ociSeccompAction(sysDefaultAction)
	if err != nil {
		return seccompProfile, err
	}

	seccompProfile.DefaultAction = def

	return seccompProfile, apparmorProfile, nil
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
