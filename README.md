# KARN
----

Karn is a system for high level entitlements for seccomp and apparmor. It can be used to generate OCI compliant profiles that you can pass to your container runtime. 

`Coming Soon: Go library for applying entitlements`

----

## Table of contents
  
  * [Goal](#user-content-goal)
  * [How it works](#how-it-works)
  * [Additional resources](#additional-resources)
  * [Contact developer](#contact-developer)

### Goal 

Create a simple permission scheme for easily securing applications. Developers can just specify what their application will need permission to do and this tool will output the corresponding seccomp and apparmor configurations. Alternatively developers of non-containerized applications could import karn and apply entitlements in code at runtime. This can be thought of as [iOS entitlements](https://developer.apple.com/library/content/documentation/Miscellaneous/Reference/EntitlementKeyReference/Chapters/AboutEntitlements.html) for everyone! 

### How it works

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

### Additional resources

- [system calls](http://man7.org/linux/man-pages/man2/syscalls.2.html) - the 'API' of the kernel
- [capabilities](http://man7.org/linux/man-pages/man7/capabilities.7.html) - a way of granting permissions
- [seccomp](http://man7.org/linux/man-pages/man2/seccomp.2.html) -  a system call filtering facility 
- [apparmor](http://wiki.apparmor.net/index.php/Main_Page) - a security facility for specifying various security rules such as capabilities

### Notice
Please file bug reports and feature requests! Karn is very much in Alpha stages.
