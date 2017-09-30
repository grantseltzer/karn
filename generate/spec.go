package generate

import (
    "os"
    "io"
    "path"
    "text/template"
)

// Declaration holds all the data from karn declaration files
type Declaration struct {
    SystemCalls  SystemCalls  `toml:"System-Calls,omitempty"`
    Capabilities CapConfig    `toml:"Capabilities,omitempty"`
    Filesystem   FsConfig     `toml:"Filesystem,omitempty"`
    Network      NetConfig    `toml:"Network,omitempty"`
    System       System       `toml:"System,omitempty"`
}

// System holds OS/Arch specific arguments
type System struct {
    Architectures        []string `toml:"Architectures,omitempty"`
    DefaultSyscallAction string   `toml:"DefaultSyscallAction,omitempty"`
}

// Syscalls to handle with each supported action
type SystemCalls struct {
    Allow []string `toml:"Allow,omitempty"`
    Trap  []string `toml:"Trap,omitempty"`
    Trace []string `toml:"Trace,omitempty"`
    Kill  []string `toml:"Kill,omitempty"`
    Errno []string `toml:"Errno,omitempty"`
}

/**
 * Originally Written by Jess Frazelle
 * http://github.com/jessfraz/bane
 */
type AppArmorProfileConfig struct {
    Name         string
    Filesystem   FsConfig
    Network      NetConfig
    Capabilities CapConfig

    Imports      []string
    InnerImports []string
}

// FsConfig defines the filesystem options for a profile.
type FsConfig struct {
    ReadOnlyPaths   []string
    LogOnWritePaths []string
    WritablePaths   []string
    AllowExec       []string
    DenyExec        []string
}

// NetConfig defines the network options for a profile.
// For example you probably don't need NetworkRaw if your
// application doesn't `ping`.
// Currently limited to AppArmor 2.3-2.6 rules.
type NetConfig struct {
    Raw       bool
    Packet    bool
    Protocols []string
}

// CapConfig defines the allowed or denied kernel capabilities
// for a profile.
type CapConfig struct {
    Allow []string
    Deny  []string
}

// Generate uses the baseTemplate to generate an apparmor profile
// for the ProfileConfig passed.
func (profile *AppArmorProfileConfig) Generate(out io.Writer) error {
    compiled, err := template.New("apparmor_profile").Parse(baseTemplate)
    if err != nil {
        return err
    }

    if tunablesExists("global") {
        profile.Imports = append(profile.Imports, "#include <tunables/global>")
    } else {
        profile.Imports = append(profile.Imports, "@{PROC}=/proc/")
    }

    if abstractionsExists("base") {
        profile.InnerImports = append(profile.InnerImports, "#include <abstractions/base>")
    }

    if err := compiled.Execute(out, profile); err != nil {
        return err
    }

    return nil
}

// check if the tunables/global exist
func tunablesExists(name string) bool {
    _, err := os.Stat(path.Join("/etc/apparmor.d/tunables", name))
    return err == nil
}

// check if abstractions/base exist
func abstractionsExists(name string) bool {
    _, err := os.Stat(path.Join("/etc/apparmor.d/abstractions", name))
    return err == nil
}
