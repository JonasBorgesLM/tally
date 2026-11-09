package tally

import "time"

// Observer receives the log's health signals (RF-16), for metrics and alerts,
// with no dependency on any metrics library.
//
// Its methods are called from the writer goroutine, the one that orders and
// stores every entry (ADR-0008). They must not block: a slow Observer stalls
// every Append. Hand the value to a channel or an atomic counter and return.
//
// No method receives a payload or any part of an entry, by the shape of its
// types: every parameter is a count, a duration or an error, and the errors are
// the store's or the anchor's, never an event's.
//
// A method that panics is recovered: that one event is dropped, the Observer
// is still called for later ones, and Log.ObserverPanics counts it
// (ADR-0017). The counter is the only trace, since tally has no logger.
//
// Events not yet emitted are marked with the issue that adds them.
type Observer interface {
	// Batch reports a batch of n entries made durable, and how long the
	// store took to do it, fsync included.
	Batch(n int, syncLatency time.Duration)
	// AnchorPublish reports a failed publication to an anchor, and how many
	// checkpoints the bounded queue has dropped so far (RF-07, RF-19; #38).
	AnchorPublish(err error, dropped uint64)
	// DiskSpace reports free space below the configured threshold (RNF-10;
	// #37).
	DiskSpace(free uint64)
	// ClockRegression reports a Clock reading earlier than the last
	// recorded_at, and by how much; the entry was recorded with the last value
	// instead (RF-03, ADR-0007). It repeats for every entry until the clock
	// catches up.
	ClockRegression(by time.Duration)
	// Poisoned reports the store error that poisoned the log (ADR-0009; #20).
	Poisoned(err error)
	// Recovered reports bytes quarantined while opening (RF-20; #34).
	Recovered(quarantinedBytes int64)
}

// WithObserver sets the Observer. nil means none.
func WithObserver(o Observer) Option {
	return func(c *config) { c.observer = o }
}

// ObserverPanics returns how many Observer calls have panicked (ADR-0017). A
// panic loses that one event and changes nothing else; this counter is how a
// caller learns that its observer is broken.
func (l *Log) ObserverPanics() uint64 { return l.observerPanics.Load() }

// observe calls f with the Observer, if there is one, and recovers a panic.
func (l *Log) observe(f func(Observer)) {
	if l.cfg.observer == nil {
		return
	}
	defer func() {
		if recover() != nil {
			l.observerPanics.Add(1)
		}
	}()
	f(l.cfg.observer)
}
