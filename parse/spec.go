package parse

import (
	bane "github.com/jessfraz/bane/apparmor"
)

type Declaration struct {
	SystemCalls  SystemCalls  `toml:"System-Calls,omitempty"`
	Capabilities Capabilities `toml:"Capabilities,omitempty"`
	Filesystem   FileSystem   `toml:"Filesystem,omitempty"`
	Network      Network      `toml:"Network,omitempty"`
	System       System       `toml:"System,omitempty"`
}

type System struct {
	Architectures        []string `toml:"Architectures,omitempty"`
	DefaultSyscallAction string   `toml:"DefaultSyscallAction,omitempty"`
}

type SystemCalls struct {
	Allow []string `toml:"Allow,omitempty"`
	Trap  []string `toml:"Trap,omitempty"`
	Trace []string `toml:"Trace,omitempty"`
	Kill  []string `toml:"Kill,omitempty"`
	Errno []string `toml:"Errno,omitempty"`
}

type AppArmorProfileConfig = bane.ProfileConfig
type FileSystem = bane.FsConfig
type Network = bane.NetConfig
type Capabilities = bane.CapConfig
