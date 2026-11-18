package tallytest

// A test key pair named "example.com/log", in SPEC §5.3's encodings. It is the
// key of testdata/vectors/keys.json, made from a published seed (bytes 0x00 to
// 0x1f), so ANYONE can sign with it: use it in tests only, never to sign a log
// that matters. Its name is the origin of the record vectors' genesis.
const (
	TestSignerKey   = "PRIVATE+KEY+example.com/log+d455c521+AQABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f"
	TestVerifierKey = "example.com/log+d455c521+AQOhB7/zzhC+HXDdGOdLwJln5NYwm6UNXx3chmQSVTG4"
)
