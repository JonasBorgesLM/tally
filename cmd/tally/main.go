// Command tally verifies and inspects a tally log from outside the
// application that writes it (RF-13).
//
//	tally verify     --dir DIR --key VKEY [--anchor DIR] [--require-fully-attested] ...
//	tally head       --dir DIR
//	tally checkpoint --dir DIR --key VKEY
//
// Every command only reads: none takes the log's lock or recovers its tail,
// so they run beside the application and never alter the evidence (#93).
//
// The exit status is a contract (REQUIREMENTS §5.1): 0 the log is intact, 1 a
// violation was found, 2 a usage or IO error, which says nothing about the
// log.
//
// The log's bytes are hostile input. Every value printed that derives from the
// log is escaped first, so control characters, ANSI sequences and newlines
// cannot reach the terminal or forge a line of output (RS-13, T-17).
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Exit statuses, a contract (REQUIREMENTS §5.1).
const (
	exitIntact    = 0
	exitViolation = 1
	exitError     = 2
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

const usage = `usage:
  tally verify     --dir DIR --key VKEY [--key-file FILE] [--anchor DIR]
                   [--require-fully-attested] [--from FILE]
                   [--heartbeat DURATION --tolerance DURATION]
  tally head       --dir DIR
  tally checkpoint --dir DIR --key VKEY [--key-file FILE]

exit status: 0 intact, 1 violation, 2 usage or IO error
`

// run is main without the process: it returns the exit status.
func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		(&output{w: stderr}).printf("%s", usage)
		return exitError
	}
	switch args[0] {
	case "verify":
		return cmdVerify(ctx, args[1:], stdout, stderr)
	case "head":
		return cmdHead(ctx, args[1:], stdout, stderr)
	case "checkpoint":
		return cmdCheckpoint(ctx, args[1:], stdout, stderr)
	case "-h", "--help", "help":
		o := &output{w: stdout}
		o.printf("%s", usage)
		return o.status(exitIntact)
	default:
		(&output{w: stderr}).printf("tally: unknown command %s\n%s", sanitize(args[0]), usage)
		return exitError
	}
}

// sanitize escapes s for a terminal (RS-13): every rune that is not graphic
// (control characters, ANSI escape sequences' ESC, bidi and other format
// characters, line breaks) becomes a \x, \u or \U escape, as does each byte
// of invalid UTF-8, and a backslash is doubled so an escape cannot be faked.
// Printable text, spaces included, is unchanged.
func sanitize(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			fmt.Fprintf(&b, `\x%02x`, s[i])
		case r == '\\':
			b.WriteString(`\\`)
		case !unicode.IsGraphic(r):
			switch {
			case r < 0x80:
				fmt.Fprintf(&b, `\x%02x`, r)
			case r <= 0xffff:
				fmt.Fprintf(&b, `\u%04x`, r)
			default:
				fmt.Fprintf(&b, `\U%08x`, r)
			}
		default:
			b.WriteRune(r)
		}
		i += size
	}
	return b.String()
}

// sanitizeLines sanitizes each line of s and keeps the line breaks, for
// multi-line text, such as a signed note, that must stay multi-line.
func sanitizeLines(s string) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = sanitize(l)
	}
	return strings.Join(lines, "\n")
}
