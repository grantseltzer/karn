# Karn


<p align="center">
    <b>Use Karn to enforce seccomp rules in your code. Select the entitlements that your application needs and not the ones it doesn't need!</b>
</p>

<p align="center">
    <img src="karn.jpg" alt="karn" width="800"/>
</p>

See [associated blog post](https://www.grant.pizza/blog/karn/)

<a href="https://godoc.org/github.com/grantseltzer/karn/pkg/entitlements"><img src="https://godoc.org/github.com/grantseltzer/karn/pkg/entitlements?status.svg" alt="GoDoc"></a>

## Table of Contents
* [How it Works](#how-it-works)
* [Entitlements](#entitlements)
* [Dependencies](#dependencies)
* [Quick Start](#quick-start)

## How it works

<i>Seccomp</i> is a security facility of the Linux kernel. It allows you to create filters for system calls on a process by process basis. For example, you can create a seccomp filter that would allow all system calls except for [chmod](http://man7.org/linux/man-pages/man2/fchmod.2.html). You can then load that filter into a running process. If the `chmod` system call is then used the kernel would return an error to your process which can handle it however it's programmed to.

Despite the power that seccomp provides, it's very difficult to use in practice. You must have deep knowledge of all system calls, and even then the task is daunting. This is where Karn comes in.

<i>Karn</i> uses entitlements to abstract away the need to know all the system calls your application will need. Getting started is as simple as familiarizing yourself with the entitlements Karn offers.

Karn's entitlements aren't quite allow or deny lists. The installed seccomp filter has a default action of 'Allow'. Meaning any unspecified system call in the filter will be allowed. On top of that, any Karn entitlement that is not specified will be Denied. This is to avoid superfluous blocking of obscure/harmless system calls.

Karn can be used for generating profiles for containers, or can be used as a library in your non-containerized application. See the quickstart guide below for more.

## Entitlements

See godoc [here](https://godoc.org/github.com/grantseltzer/karn/go/pkg/entitlements)

## Dependencies

See [docs/dependencies.md](./docs/dependencies.md)

## Quickstart

See [docs/quickstart.md](./docs/quickstart.md)
