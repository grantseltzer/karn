# Karn

<p align="center">
    <b>Use Karn to enforce seccomp rules in your code. Select the entitlements that your application needs and not the ones it doesn't need!</b>
</p>

<p align="center">
    <img src="karn.jpg" alt="karn" width="800"/>
</p>

## Table of Contents
* [How it Works](#how-it-works)
* [Entitlements](#entitlements)
* [Dependencies](#dependencies)
* [Quick Start](#quick-start)
    * [Library](#library)
    * [Containers](#containers)

## How it works

<i>Seccomp</i> is a security facility of the Linux kernel. It allows you to create filters for system calls on a process by process basis. For example, you can create a seccomp filter that would allow all system calls except for [chmod](http://man7.org/linux/man-pages/man2/fchmod.2.html). You can then load that filter into a running process. If the `chmod` system call is then used the kernel would return an error to your process which can handle it however it's programmed to.

Despite the power that seccomp provides, it's very difficult to use in practice. You must have deep knowledge of all system calls, and even then the task is daunting. This is where Karn comes in.

<i>Karn</i> uses entitlements to abstract away the need to know all the system calls your application will need. Getting started is as simple as familiarizing yourself with the entitlements Karn offers.

Karn's entitlements aren't quite allow or deny lists. The installed seccomp filter has a default action of 'Allow'. Meaning any unspecified system call in the filter will be allowed. On top of that, any Karn entitlement that is not specified will be Denied. This is to avoid superfluous blocking of obscure/harmless system calls.

Karn can be used for generating profiles for containers, or can be used as a library in your non-containerized application. See the quickstart guide below for more.

## Entitlements

See godoc [here](https://godoc.org/github.com/grantseltzer/karn/go/pkg/entitlements)

## Dependencies

If you are using Karn as a library for enforcing seccomp you must have:

- libseccomp-dev [debian-like](https://launchpad.net/ubuntu/+source/libseccomp) / [centos-like](https://rpmfind.net/linux/rpm2html/search.php?query=libseccomp-devel)

If you are using Karn to generate OCI compliant seccomp profiles to pass to containers, there are no external dependencies.

## Quick Start

* [Library](#library)
* [Containers](#containers)

#### Library
Let's say you're writing a simple HTTP webserver in go:

```
package main

import (
    "fmt"
    "net/http"
)

func main() {
    http.HandleFunc("/", HelloServer)
    http.ListenAndServe(":8080", nil)
}

func HelloServer(w http.ResponseWriter, r *http.Request) {
    fmt.Fprintf(w, "I can modprobe if you exploit me, %s!", r.URL.Path[1:])
}
```

This program just handles incoming HTTP requests on a network sockets. I didn't include anything exploitable here for simplicity but try to imagine the possibility of an application vulnerablity. 

The only relevant sounding entitlement is `NetworkConnection`. Let's apply it:


```go
package main

import (
    "fmt"
    "net/http"
    Karn "github.com/grantseltzer/Karn/go/pkg/entitlements"
)

func main() {

    neededEntitlements := []Karn.Entitlement{
        "NetworkConnection"
    }

    err := Karn.ApplyEntitlements(neededEntitlements)
    if err != nil {
        log.Fatal(err)
    }

    http.HandleFunc("/", HelloServer)
    http.ListenAndServe(":8080", nil)
}

func HelloServer(w http.ResponseWriter, r *http.Request) {
    fmt.Fprintf(w, "I can modprobe if you exploit me, %s!", r.URL.Path[1:])
}
```

From here you wouldn't notice any difference in your applications runtime, except now it has a lot less system calls that it can use!

#### Containers

Let's use the same example as above. This time, we're running the application inside a container. In that case it's better to pass a seccomp profile to the container runtime instead of inside the application. This way the seccomp rules will be applied to every process inside the container.

We can build the karn CLI with a simple `make`. 

From there, we're going to create the profile and then pass it with the container when we start it.

```bash
[*] ./bin/karn network_connection > seccomp_profile.json

[*] cat seccomp_profile
{
 "defaultAction": "SCMP_ACT_ALLOW",
 "architectures": [
  "SCMP_ARCH_X86",
  "SCMP_ARCH_X86_64"
 ],
 "syscalls": [
  {
   "names": [
    "adjtimex",
    "clock_adjtime",
    "clock_settime",
    "settimeofday",
    "stime",
    "pivot_root",
    "kexec_file_load",
    "kexec_load",
    "ioperm",
    "iopl",
    "quotactl",
    "execve",
    "execveat",
    "fork",
    "vfork",
    "swapon",
    "swapoff",
    "mount",
    "umount",
    "umount2",
    "sysfs",
    "_sysctl",
    "personality",
    "ustat",
    "nfsservctl",
    "vm86",
    "uselib",
    "vm86old",
    "reboot",
    "add_key",
    "request_key",
    "keyctl",
    "unshare",
    "setns",
    "mknod",
    "get_mempolicy",
    "set_mempolicy",
    "move_pages",
    "mbind",
    "acct",
    "ptrace",
    "lookup_dcookie",
    "bpf",
    "perf_event_open",
    "process_vm_readv",
    "process_vm_writev",
    "create_module",
    "delete_module",
    "finit_module",
    "get_kernel_syms",
    "init_module",
    "query_module",
    "chown",
    "fchown",
    "fchownat",
    "lchown"
   ],
   "action": "SCMP_ACT_ERRNO"
  }
 ]
}

[*] docker build # (building your container with your application)

[*] docker run --rm -d --security-opt seccomp=./seccomp_profile.json <your_image> <you_app_command_line>
```