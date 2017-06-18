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
	Default string   `toml:"Default"`
	Allow   []string `toml:"Allow"`
	Trap    []string `toml:"Trap"`
	Trace   []string `toml:"Trace"`
	Kill    []string `toml:"Kill"`
	Errno   []string `toml:"Errno"`
}

type AppArmor struct {
	Capabilities []string `toml:"Capabilities"`
}
