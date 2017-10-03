package generate

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

// SystemCalls to handle with each supported action
type SystemCalls struct {
	Allow []string `toml:"Allow,omitempty"`
	Trap  []string `toml:"Trap,omitempty"`
	Trace []string `toml:"Trace,omitempty"`
	Kill  []string `toml:"Kill,omitempty"`
	Errno []string `toml:"Errno,omitempty"`
}

// AppArmorProfileConfig defines the options for an apparmor profile
type AppArmorProfileConfig struct {
	Name         string
	Filesystem   FileSystem
	Network      Network
	Capabilities Capabilities
}

// FileSystem defines the filesystem options for a profile.
type FileSystem struct {
	ReadOnlyPaths   []string
	LogOnWritePaths []string
	WritablePaths   []string
	AllowExec       []string
	DenyExec        []string
}

// Network defines the network options for a profile.
// For example you probably don't need NetworkRaw if your
// application doesn't `ping`.
// Currently limited to AppArmor 2.3-2.6 rules.
type Network struct {
	Raw       bool
	Packet    bool
	Protocols []string
}

// Capabilities defines the allowed or denied kernel capabilities
// for a profile.
type Capabilities struct {
	Allow []string
	Deny  []string
}
