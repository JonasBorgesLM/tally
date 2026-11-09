package tallytest_test

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/JonasBorgesLM/tally"
	"github.com/JonasBorgesLM/tally/tallytest"
)

func ExampleMemStore() {
	s := tallytest.NewMemStore()
	ctx := context.Background()
	_ = s.AppendBatch(ctx, []tally.Record{{Seq: 0, Body: []byte("genesis")}, {Seq: 1, Body: []byte("entry")}})

	for r, err := range s.Records(ctx, 0) {
		if err != nil {
			panic(err)
		}
		fmt.Println(r.Seq, string(r.Body))
	}
	// Output:
	// 0 genesis
	// 1 entry
}

func ExampleFaultyStore() {
	errFsync := errors.New("fsync: input/output error")
	mem := tallytest.NewMemStore()
	// The second AppendBatch fails, as a failed fsync would.
	s := tallytest.NewFaultyStore(mem, tallytest.FailAppend(2, errFsync))
	ctx := context.Background()

	fmt.Println(s.AppendBatch(ctx, []tally.Record{{Seq: 0}}))
	fmt.Println(s.AppendBatch(ctx, []tally.Record{{Seq: 1}}))
	fmt.Println("calls:", s.AppendCalls(), "stored:", mem.Len())
	// Output:
	// <nil>
	// fsync: input/output error
	// calls: 2 stored: 1
}

func ExampleBlockAppend() {
	mem := tallytest.NewMemStore()
	entered, release := make(chan struct{}), make(chan struct{})
	s := tallytest.NewFaultyStore(mem, tallytest.BlockAppend(1, entered, release))

	done := make(chan error)
	go func() { done <- s.AppendBatch(context.Background(), []tally.Record{{Seq: 0}}) }()

	<-entered // the writer is inside the store, and nothing is durable yet
	fmt.Println("stored while blocked:", mem.Len())
	close(release)
	fmt.Println(<-done, "stored:", mem.Len())
	// Output:
	// stored while blocked: 0
	// <nil> stored: 1
}

func ExampleFixedClock() {
	c := tallytest.NewFixedClock(time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC))
	c.Advance(-time.Minute) // an NTP step backwards
	fmt.Println(c.Now().Format(time.TimeOnly))
	// Output:
	// 11:59:00
}
