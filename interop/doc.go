// Package interop tests tally against other implementations of the formats it
// uses. It is its own module, so that its dependencies never reach the core,
// which is stdlib only (RNF-01, RNF-02). It has tests and nothing else.
package interop
