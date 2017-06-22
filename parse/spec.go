package karn

type Profile struct {
	Network    []Declaration `toml:"Network"`
	FileSystem []Declaration `toml:"FileSystem"`
	Runtime    []Declaration `toml:"Runtime"`
	User       []Declaration `toml:"User"`
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
