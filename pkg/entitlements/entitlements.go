package entitlements

// Entitlement represents a grouping of system call rules
type Entitlement struct {
	Name    string   `toml:"Name,omitempty"`
	Allowed []string `toml:"Allow,omitempty"`
}

var Chown = Entitlement{
	Name: "chown",
	Allowed: []string{
		"chown",
		"chown32",
		"fchown",
		"fchown32",
		"fchownat",
		"lchown",
		"lchown32",
	},
}

var Admin = Entitlement{
	Name: "admin",
	Allowed: []string{
		"bpf",
		"clone",
		"lookup_dcookie",
		"mount",
		"quotactl",
		"setns",
		"swapon",
		"swapoff",
		"umount",
		"umount2",
		"unshare",
		"vm86",
		"vm86old",
	},
}

var Proc = Entitlement{
	Name: "proc",
	Allowed: []string{
		"fork",
		"vfork",
		"kill",
		"getpriority",
		"setpriority",
		"setrlimit",
		"getrlimit",
		"prlimit",
		"setpgid",
		"getpgid",
		"setpgrp",
		"getpgrp",
		"setsid",
	},
}

//TODO: Add rest of entitlements
