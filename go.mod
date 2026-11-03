module github.com/JonasBorgesLM/tally

// The floor is Go 1.26, the oldest release still receiving security fixes
// (RNF-01). v0.2 of the requirements said 1.24, which no longer gets them, and a
// cryptographic library should not promise support for an unpatched standard
// library (R-33). Raising this line is a CHANGELOG entry.
go 1.26.0
