package karn

type Profile struct {
	// x map[string][]string
	Network    []string `toml:"Network,omitempty"`
	FileSystem []string `toml:"FileSystem,omitempty"`
	Runtime    []string `toml:"Runtime,omitempty"`
	User       []string `toml:"User,omitempty"`
}

type Declaration struct {
	Seccomp  Seccomp  `toml:"Seccomp,omitempty"`
	AppArmor AppArmor `toml:"AppArmor,omitempty"`
}

type Seccomp struct {
	Default       string   `toml:"default"`
	Architectures []string `toml:"architectures"`
	Allow         []string `toml:"allow"`
	Trap          []string `toml:"trap"`
	Trace         []string `toml:"trace"`
	Kill          []string `toml:"kill"`
	Errno         []string `toml:"errno"`
}

type AppArmor struct {
	Capabilities []string `toml:"capabilities"`
}
