package karn

import (
	bane "github.com/jessfraz/bane/apparmor"
)

// Declaration holds all the data from karn declaration files
type Declaration struct {
	SystemCalls  SystemCalls  `toml:"System-Calls,omitempty"`
	Capabilities Capabilities `toml:"Capabilities,omitempty"`
	Filesystem   FileSystem   `toml:"Filesystem,omitempty"`
	Network      Network      `toml:"Network,omitempty"`
	System       System       `toml:"System,omitempty"`
}

// System holds OS/Arch specific arguments
type System struct {
	Architectures        []string `toml:"Architectures,omitempty"`
	DefaultSyscallAction string   `toml:"DefaultSyscallAction,omitempty"`
}

// Syscalls to handle with each supported action
type SystemCalls struct {
	Allow []string `toml:"Allow,omitempty"`
	Trap  []string `toml:"Trap,omitempty"`
	Trace []string `toml:"Trace,omitempty"`
	Kill  []string `toml:"Kill,omitempty"`
	Errno []string `toml:"Errno,omitempty"`
}

// Type aliases for use from bane 

type AppArmorProfileConfig = bane.ProfileConfig
type FileSystem            = bane.FsConfig
type Network               = bane.NetConfig
type Capabilities          = bane.CapConfig
