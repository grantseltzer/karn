package karn

import (
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

func CreateSeccompProfile(declarations []Declaration) (specs.LinuxSeccomp, error) {

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

	/* Combine declaration fields */
	for _, dec := range declarations {

		// System calls
		secAllows = append(secAllows, dec.SystemCalls.Allow)
		secTraps = append(secTraps, dec.SystemCalls.Trap)
		secTraces = append(secTraces, dec.SystemCalls.Trace)
		secKills = append(secKills, dec.SystemCalls.Kill)
		secErrnos = append(secErrnos, dec.SystemCalls.Errno)

		// Capabilities
		capAllows = append(capAllows, dec.Capabilities.Allow)
		capDenies = append(capDenies, dec.Capabilities.Deny)

		// File system rules
		fsReadOnlies = append(fsReadOnlies, dec.Filesystem.ReadOnlyPaths)
		fsLogPaths = append(fsLogPaths, dec.Filesystem.LogOnWritePaths)
		fsWritablePaths = append(fsWritablePaths, dec.Filesystem.WritablePaths)
		fsAllowExecs = append(fsAllowExecs, dec.Filesystem.AllowExec)
		fsDenyExecs = append(fsDenyExecs, dec.Filesystem.DenyExec)

		// Network Configurations
		netRaw = netRaw && dec.Network.Raw
		netPacket = netPacket && dec.Network.Packet
		netProtocols = append(netProtocols, dec.Network.Protocols)

		// System Configurations
		sysArches = append(sysArches, dec.System.Architectures)
		sysDefaultAction = dec.System.DefaultSyscallAction
	}

}
