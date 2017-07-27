# KARN
----

Karn is an admin-friendly tool for creating OCI compliant [seccomp](https://en.wikipedia.org/wiki/Seccomp) and [apparmor](https://en.wikipedia.org/wiki/AppArmor) profiles. Originally proposed [here](https://gist.github.com/jessfraz/3a84023ff85471696ee33a20031b9e7b) as part of the [Linux Container Hardening](https://containerhardening.org/) project.

----

#### STATUS: alpha

Baseline functionality exists. Support for specific seccomp arguments is also not yet supported (but will be soon).

Check out the issues for things that are not yet implemented. 

----

## Goal 

Create a simple permission scheme for easily securing containers. Developers can just specify what their container will need permission to do and this tool will output the corresponding seccomp and apparmor configurations. This can be thought of as [iOS entitlements](https://developer.apple.com/library/content/documentation/Miscellaneous/Reference/EntitlementKeyReference/Chapters/AboutEntitlements.html) for containers! 

## How it works

**Declarations** - You can think of these as rule definitions. You define a declaration as corresponding to particular system calls, capabilities, FileSystem rules, Networking, and other security related rules. Each file will correspond to just a single declaration. Declartions should follow the naming convention of "<name>_declaration.toml". Declarations are combined to generate seccomp and apparmor profiles. Here's a couple examples of what a declaration looks like:
 
_dns\_declaration.toml_
 ```
[System-Calls]
Allow = [
        "sendto",
        "recvfrom",
        "socket",
        "connect"
]
 ```

_chown_declaration.toml_
 ```
[System-Calls]
Allow = [
        "chown",
        "chown32",
        "fchown",
        "fchown32",
        "fchownat",
        "lchown",
        "lchown32"
]

[Capabilities]
Allow = ["chown"] # CAP_CHOWN
```

These declarations should be stored in `~/.karn/declarations`. To take these two declarations to form seccomp and apparmor profiles, one would simply enter `karn generate chown dns`. You can also pass a different declaration directory with the `-d`/`--declarations` flag.

## Resources

- [system calls](http://man7.org/linux/man-pages/man2/syscalls.2.html) - the 'API' of the kernel
- [capabilities](http://man7.org/linux/man-pages/man7/capabilities.7.html) - a way of granting permissions
- [seccomp](http://man7.org/linux/man-pages/man2/seccomp.2.html) -  a system call filtering facility 
- [apparmor](http://wiki.apparmor.net/index.php/Main_Page) - a security facility for specifying various security rules such as capabilities
- [containers](https://www.docker.com/what-container) - linux processes that karn output can protect
- [toml](https://github.com/toml-lang/toml) - the language karn uses
- [contained.af](https://contained.af/) - a CTF game meant to teach you about syscalls and capabilities

Questions/Concerns? Open an issue or email me - grant at capsule8.com
