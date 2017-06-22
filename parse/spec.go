package karn

type Profile struct {
	Network    []string `toml:"Network"`
	FileSystem []string `toml:"FileSystem"`
	Runtime    []string `toml:"Runtime"`
	User       []string `toml:"User"`
}

type Declaration struct {
	Seccomp  Seccomp  `toml:"Seccomp"`
	AppArmor AppArmor `toml:"AppArmor"`
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
