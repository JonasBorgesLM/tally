package main

import (
	"io"
	"runtime/debug"
)

// version is the release's tag, set at build time by the release workflow:
// -ldflags "-X main.version=vX.Y.Z" (ADR-0014). An auditor reads it with
// `tally version` to know which release vouches for this binary.
var version = ""

// versionString is version, or, for a binary built some other way, what the
// build recorded: the module version `go install` resolved, and the commit a
// build from a checkout was made at. Neither is a release's word.
func versionString() string {
	if version != "" {
		return version
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	v := info.Main.Version
	for _, s := range info.Settings {
		if s.Key == "vcs.revision" {
			v += " (" + s.Value + ")"
		}
	}
	return v
}

func cmdVersion(args []string, stdout, stderr io.Writer) int {
	if len(args) != 0 {
		(&output{w: stderr}).printf("tally version: takes no arguments\n")
		return exitError
	}
	o := &output{w: stdout}
	o.printf("tally %s\n", sanitize(versionString()))
	return o.status(exitIntact)
}
