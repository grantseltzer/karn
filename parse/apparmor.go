package parse

import "io"

func WriteAppArmorProfile(out io.Writer, specifiedDeclarations []string, declarationsDirectory string) error {
	Declarations, err := readDeclarationFiles(specifiedDeclarations, declarationsDirectory)
	if err != nil {
		return err
	}

	combinedConfig := AppArmorProfileConfig{}

	for _, v := range Declarations {
		combinedConfig.Filesystem.ReadOnlyPaths =
			append(combinedConfig.Filesystem.ReadOnlyPaths, v.Filesystem.ReadOnlyPaths...)

		combinedConfig.Filesystem.LogOnWritePaths =
			append(combinedConfig.Filesystem.LogOnWritePaths, v.Filesystem.LogOnWritePaths...)

		combinedConfig.Filesystem.WritablePaths =
			append(combinedConfig.Filesystem.WritablePaths, v.Filesystem.WritablePaths...)

		combinedConfig.Filesystem.AllowExec =
			append(combinedConfig.Filesystem.AllowExec, v.Filesystem.AllowExec...)

		combinedConfig.Filesystem.DenyExec =
			append(combinedConfig.Filesystem.DenyExec, v.Filesystem.DenyExec...)

		combinedConfig.Network.Protocols =
			append(combinedConfig.Network.Protocols, v.Network.Protocols...)

		combinedConfig.Capabilities.Allow =
			append(combinedConfig.Capabilities.Allow, v.Capabilities.Allow...)

		combinedConfig.Capabilities.Deny =
			append(combinedConfig.Capabilities.Deny, v.Capabilities.Deny...)

		combinedConfig.Network.Raw = combinedConfig.Network.Raw && v.Network.Raw
		combinedConfig.Network.Packet = combinedConfig.Network.Packet && v.Network.Packet
	}

	return combinedConfig.Generate(out)
}

func packBaneConfig(d Declaration) AppArmorProfileConfig {
	x := AppArmorProfileConfig{
		Filesystem:   d.Filesystem,
		Network:      d.Network,
		Capabilities: d.Capabilities,
	}
	return x
}
