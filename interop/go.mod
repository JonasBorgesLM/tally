// The interop module exists to test tally against other implementations, and
// may depend on them; the core may not (RNF-01, RNF-02). It holds tests only.
module github.com/JonasBorgesLM/tally/interop

go 1.26.0

// Always the tally in this repository: the module tests the code beside it,
// never a published version.
replace github.com/JonasBorgesLM/tally => ../

require (
	github.com/JonasBorgesLM/tally v0.0.0-00010101000000-000000000000
	golang.org/x/mod v0.43.0
)
