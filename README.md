# KARN

#### STATUS: non-existant

----

Karn is an admin-friendly tool for creating [seccomp](https://en.wikipedia.org/wiki/Seccomp) and [apparmor](https://en.wikipedia.org/wiki/AppArmor) profiles. Originally proposed [here](https://gist.github.com/jessfraz/3a84023ff85471696ee33a20031b9e7b) as part of the [Linux Container Hardening](https://containerhardening.org/) project.

----

## Goal 

Make it very easy for system admins of any level to correctly configure linux security modules in their containers. Configuring seccomp and apparmor involve writing very long configuration files. In practice most people just use [default ones](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json) that people with more experience have written. Or they just don't use anything....


## How it works

There are two TOML specifications that make this work.

1) **Declarations** - You can think of these as rule definitions. You define a declaration as corresponding to particular system calls and capabilities. Each file will correspond to just a single declaration. Declartions must follow the naming convention of "<name>_declaration.toml" Here's a couple examples of what a declaration looks like:
 
_dns\_declaration.toml_
 ```
 [Seccomp]

 default = "trap" 
 architectures = [
	 "x86"
 ]
 allow = [
         "sendto",
         "recvfrom",
         "socket",
         "connect"
]

 [Apparmor]
 caps = []
 ```

_chown_declaration.toml_
 ```
 [Seccomp]
 allow = [
         "chown",
         "chown32",
         "fchown",
         "fchown32",
         "fchownat",
         "lchown",
         "lchown32"
 ]

 [Apparmor]
 caps = [
         "CAP_CHOWN'
 ]

 ```

 2) **Profiles** - This is a collection of references to declarations. Karn takes these and combines all the declarations into single individual seccomp and apparmor profiles. Here's an example of what a profile looks like:

_my_karn_profile.toml_
 ```
 [Network]
 declarations = ["dns"]

 [Filesystem]
 declarations = ["chown"]
 ```

 This, when passed through Karn, would generate a seccomp whitelist and apparmor profile corresponding to the declarations above.

## Important Design Principles

1) Profiles need to be simple to read and write. 
2) All functionality of seccomp and apparmor need to be able to be expressed between the declarations and profiles.
3) Karn should be `go get`'able. This means if someone wanted to embed the parsing into their container runtime, they'd easily be able to
4) The community around Karn should promote sharing of declaration files. 

## Resources

- [system calls](http://man7.org/linux/man-pages/man2/syscalls.2.html) - the 'API' of the kernel
- [capabilities](http://man7.org/linux/man-pages/man7/capabilities.7.html) - a way of granting permissions
- [seccomp](http://man7.org/linux/man-pages/man2/seccomp.2.html) -  a system call filtering facility 
- [apparmor](http://wiki.apparmor.net/index.php/Main_Page) - like seccomp for capabilities
- [containers](https://www.docker.com/what-container) - why we're all here 
- [toml](https://github.com/toml-lang/toml) - the language of Karn
- [contained.af](https://contained.af/) - a CTF game meant to teach you about syscalls and caps

Questions/Concerns? Open an issue or email me - grant at capsule8.com