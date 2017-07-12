package karn

type Declaration struct {
	SystemCalls  SystemCalls  `toml:"System-Calls,omitempty"`
	Capabilities Capabilities `toml:"Capabilities,omitempty"`
	Files        Files        `toml:"File,omitemptys"`
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

type Capabilities struct {
	Allow []string `toml:"Allow,omitempty"`
	Deny  []string `toml:"Deny,omitempty"`
}

type Files struct {
	ReadOnly   []string `toml:"ReadOnly,omitempty"`
	Writeable  []string `toml:"Writeable,omitempty"`
	LogOnWrite []string `toml:"LogOnWrite,omitempty"`
	AllowExec  []string `toml:"AllowExec,omitempty"`
	DenyExec   []string `toml:"DenyExec,omitempty"`
}

type Network struct {
	Raw       bool     `toml:"Raw,omitempty"`
	Packet    bool     `toml:"Packet,omitempty"`
	Protocols []string `toml:"Protocols,omitempty"`
}
