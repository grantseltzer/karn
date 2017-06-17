package karn

type Declaration struct {
	Seccomp  Seccomp
	AppArmor AppArmor
}

type Seccomp struct {
	Default string
	Allow   []string
	Trap    []string
	Trace   []string
	Kill    []string
	Errno   []string
}

type AppArmor struct {
	Capabilities []string
}
