package entitlements

// Entitlement represents a grouping of system call rules
type Entitlement struct {
	Name     string   `toml:"Name,omitempty"`
	Syscalls []string `toml:"Syscalls,omitempty"`
}

// SpecialFiles describes the creation of FIFOs and special files
var SpecialFiles = Entitlement{
	Name: "special_files",
	Syscalls: []string{
		"mknod",
	},
}

// Chown describes the ability to change ownership of files
var Chown = Entitlement{
	Name: "chown",
	Syscalls: []string{
		"chown",
		"fchown",
		"fchownat",
		"lchown",
	},
}

// Exec includes the exec, fork, and clone syscalls.
var Exec = Entitlement{
	Name: "exec",
	Syscalls: []string{
		"execve",
		"execveat",
		"fork",
		"vfork",
	},
}

// NetworkConnection describes the system calls needed for using any network functionality
// This includes creating and using sockets, and sending/receving messages over them
var NetworkConnection = Entitlement{
	Name: "network_connection",
	Syscalls: []string{
		"socket",
		"getsockopt",
		"setsockopt",
		"getsockname",
		"socketpair",
		"socket",
		"socketcall",
		"bind",
		"listen",
		"sendto",
		"send",
		"sendmsg",
		"recv",
		"recvfrom",
		"recvmsg",
	},
}

// Mount describes the system calls for mounting and unmounting file systems
var Mount = Entitlement{
	Name: "mount",
	Syscalls: []string{
		"mount",
		"umount",
		"umount2",
	},
}

// SetTime describes the system calls for dealing with the systems clock
var SetTime = Entitlement{
	Name: "set_time",
	Syscalls: []string{
		"adjtimex",
		"clock_adjtime",
		"clock_settime",
		"settimeofday",
		"stime",
	},
}

// Tracing describes the system calls for dealing with the tracing
// facilities of the kernel - this includes ptrace and bpf
var Tracing = Entitlement{
	Name: "tracing",
	Syscalls: []string{
		"acct",
		"ptrace",
		"lookup_dcookie",
		"bpf",
		"perf_event_open",
		"process_vm_readv",
		"process_vm_writev",
	},
}

// KernelKeyring includes the system calls needed for interacting
// with the kernel management facility
var KernelKeyring = Entitlement{
	Name: "kernel_keyring",
	Syscalls: []string{
		"add_key",
		"request_key",
		"keyctl",
	},
}

// Modules includes the system cals for creating, deleting,
// and interacting with kernel modules
var Modules = Entitlement{
	Name: "modules",
	Syscalls: []string{
		"create_module",
		"delete_module",
		"finit_module",
		"get_kernel_syms",
		"init_module",
		"query_module",
	},
}

// LoadNewKernel includes the system calls used for loading
// a new kernel into memory
var LoadNewKernel = Entitlement{
	Name: "load_new_kernel",
	Syscalls: []string{
		"kexec_file_load",
		"kexec_load",
	},
}

// KernelMemory describes system calls that modify kernel memory
// and NUMA settings
var KernelMemory = Entitlement{
	Name: "kernel_memory",
	Syscalls: []string{
		"get_mempolicy",
		"set_mempolicy",
		"move_pages",
		"mbind",
	},
}

// KernelIO includes system calls that modify kernel I/O privleges
var KernelIO = Entitlement{
	Name: "kernel_io",
	Syscalls: []string{
		"ioperm",
		"iopl",
	},
}

// RootFS describes the system call for modifying the root filesystem
var RootFS = Entitlement{
	Name: "rootfs",
	Syscalls: []string{
		"pivot_root",
	},
}

// Namespaces describes the system calls for changing the namespaces
// of a process
var Namespaces = Entitlement{
	Name: "namespaces",
	Syscalls: []string{
		"unshare",
		"setns",
	},
}

// SwapMemory describes system calls for
var SwapMemory = Entitlement{
	Name: "swap_memory",
	Syscalls: []string{
		"swapon",
		"swapoff",
	},
}

// Reboot contains the system call for allowing a program
// to restart the system
var Reboot = Entitlement{
	Name: "reboot",
	Syscalls: []string{
		"reboot",
	},
}

// ResourceQuota contains the system call for interacting with the
// per-user, per-group, and per-project disk quota
var ResourceQuota = Entitlement{
	Name: "resource_quota",
	Syscalls: []string{
		"quotactl",
	},
}

// obsolete contains the system calls that are not used and probably
// have no business being allowed
var obsolete = Entitlement{
	Name: "obsolete",
	Syscalls: []string{
		"sysfs",
		"_sysctl",
		"personality",
		"ustat",
		"nfsservctl",
		"vm86",
		"uselib",
		"vm86old",
	},
}
