# Karn CLI Usage

`karn` takes a space seperated list of entitlement names as arguments. You can use the `--list` flag to list the available entitlements.

### Listing entitlements 

```
[*] karn --list
modules
kernel_io
reboot
resource_quota
network_connection
mount
load_new_kernel
kernel_memory
swap_memory
exec
kernel_keyring
rootfs
namespaces
chown
set_time
tracing
obsolete
special_files
```

### Specifying entitlements

```
[*] karn mount chown special_files                                            
{
 "defaultAction": "SCMP_ACT_ALLOW",
 "architectures": [
  "SCMP_ARCH_X86",
  "SCMP_ARCH_X86_64"
 ],
 "syscalls": [
  {
   "names": [
    "execve",
    "execveat",
    "fork",
    "vfork",
    "add_key",
    "request_key",
    "keyctl",
    "get_mempolicy",
    "set_mempolicy",
    "move_pages",
    "mbind",
    "pivot_root",
    "ioperm",
    "iopl",
    "swapon",
    "swapoff",
    "acct",
    "ptrace",
    "lookup_dcookie",
    "bpf",
    "perf_event_open",
    "process_vm_readv",
    "process_vm_writev",
    "adjtimex",
    "clock_adjtime",
    "clock_settime",
    "settimeofday",
    "stime",
    "unshare",
    "setns",
    "sysfs",
    "_sysctl",
    "personality",
    "ustat",
    "nfsservctl",
    "vm86",
    "uselib",
    "vm86old",
    "create_module",
    "delete_module",
    "finit_module",
    "get_kernel_syms",
    "init_module",
    "query_module",
    "quotactl",
    "socket",
    "getsockopt",
    "setsockopt",
    "getsockname",
    "socketpair",
    "socket",
    "socketcall",
    "bind",
    "listen",
    "kexec_file_load",
    "kexec_load",
    "reboot"
   ],
   "action": "SCMP_ACT_ERRNO"
  }
 ]
}
```

### Using a seccomp profile

```
[*] karn mount chown special_files > seccomp_profile.json
[*] docker run --security-opt seccomp=./seccomp_profile.json my_app
```