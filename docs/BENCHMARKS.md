# Benchmarks

RNF-03's measurements (#49). A number here means nothing without the machine, the filesystem and the Go
version beside it: an `Append` costs what one fsync costs on that disk, and the rest is tally.

## How to measure

```bash
go test ./filestore -run '^$' -bench . -count 10 | tee new.txt
benchstat new.txt   # golang.org/x/perf/cmd/benchstat
```

`TMPDIR` picks the disk the logs are written to. The benchmarks are in `filestore/bench_test.go`:

| Benchmark | What it measures |
| --- | --- |
| `Append/writers=N/maxdelay=D` | Durable appends (each returns after its fsync, RF-01) from `N` concurrent callers, with the default `MaxBatch` (256) and checkpoint policy (one per 1000 entries). Reports entries/s, the p99 of one `Append`, and entries/batch: one segment fsync per batch |
| `Reopen` | Opening a log of 100,000 entries whose last segment has a torn tail: the tail is quarantined (SPEC §3.3) and `tally.Open` rehashes every stored entry to rebuild the head and the idempotency window. Reports entries/s |
| `Verify` | `tally.Verify` over `filestore.OpenReader`, as `tally verify` runs it, on the same 100,000 entries, files in the page cache. `Verify` runs on one goroutine, so this rate is per core, the garbage collector aside |

CI runs them on every pull request, base and head alternating, and puts `benchstat`'s comparison in the job
summary without gating on it: a shared runner's fsync moves by tens of percent between runs.

## Results

Recorded 2026-11-16, ten runs each; the value is benchstat's median, ± its 95% confidence interval.

**macOS:** Apple M1, 8 cores, 8 GB, internal SSD (Apple Fabric), APFS, macOS 26.6.2, Go 1.27.3. Go's
`File.Sync` is `F_FULLFSYNC` on macOS, which flushes the drive's cache: a durable write, and a slow one.

**Linux VM:** the same machine, in Docker Desktop's VM: linux/arm64, kernel 6.12.5-linuxkit, overlayfs on the
VM's virtual disk, Go 1.26.9. Whether that fsync reaches the physical drive was not verified. **These are
not NVMe numbers**, and the VM's timers fire late (below).

| Benchmark | macOS entries/s | macOS p99 | Linux VM entries/s | Linux VM p99 |
| --- | ---: | ---: | ---: | ---: |
| `Append`, 1 caller, MaxDelay 0 | 249 ± 4% | 7.0 ms ± 14% | 2,244 ± 5% | 1.3 ms ± 13% |
| `Append`, 1 caller, MaxDelay 2 ms | 171 ± 4% | 7.7 ms ± 37% | 237 ± 7% | 6.5 ms ± 44% |
| `Append`, 16 callers, MaxDelay 2 ms | 2,509 ± 2% | 10.6 ms ± 13% | 3,796 ± 4% | 6.8 ms ± 16% |
| `Append`, 256 callers, MaxDelay 2 ms | **43,780** ± 2% | 11.0 ms ± 9% | **157,800** ± 11% | 4.1 ms ± 34% |
| `Reopen`, 100k entries | 827,000 ± 5% | | 542,400 ± 12% | |
| `Verify`, 100k entries | **1,295,000** ± 1% | | **768,700** ± 4% | |

Batches achieved: 1 entry per fsync with one caller, 16 with 16, 255 with 256, on both.

**Raspberry Pi** (#115), recorded 2026-11-18, ten runs, the same benchstat median: a Raspberry Pi 5 Model B,
4 cores, 8 GB, booting from a 64 GB microSD card (`mmcblk0`, name `USD00`, manufacturer id `0x0000ad`,
dated 08/2024, kernel write cache "write back"), ext4 mounted `noatime`, Debian 13 (trixie), kernel
6.12.62+rpt-rpi-2712. The test binary was cross-compiled with Go 1.27.3 (`GOOS=linux GOARCH=arm64`) and run
with `TMPDIR` on the card: Debian 13 mounts `/tmp` as tmpfs, and a benchmark there measures memory, not the
card. Linux sends a cache flush with each fsync; whether this card holds the data through a power cut once
it acknowledges was not tested.

| Benchmark | Pi entries/s | Pi p99 |
| --- | ---: | ---: |
| `Append`, 1 caller, MaxDelay 0 | 375 ± 1% | 2.8 ms ± 7% |
| `Append`, 1 caller, MaxDelay 2 ms | 214 ± 1% | 5.2 ms ± 6% |
| `Append`, 16 callers, MaxDelay 2 ms | 3,212 ± 1% | 7.7 ms ± 0% |
| `Append`, 256 callers, MaxDelay 2 ms | **43,970** ± 1% | 8.7 ms ± 4% |
| `Reopen`, 100k entries | 284,800 ± 7% | |
| `Verify`, 100k entries | **455,000** ± 16% | |

Batches: 1 entry per fsync with one caller, 15.95 with 16, 255.1 with 256. One fsync on this card costs about
2.7 ms (one caller, no delay), and the 2 ms `MaxDelay` added 2.0 ms (4.67 against 2.67 ms per `Append`): on
real Linux the timer fires on time, so the VM's lateness below was the VM's.

## Against RNF-03

| Target | Result |
| --- | --- |
| Batched append ≥ 10k entries/s | **Met** with 256 callers: 43.8k/s on macOS, 158k/s in the Linux VM, 44.0k/s on the Pi's microSD card. With few callers it is not reachable on any disk: 16 callers share each fsync 16 ways and no more |
| Verify ≥ 100k entries/s per core | **Met**: 1.3M/s on macOS, 0.77M/s in the Linux VM, 0.46M/s on the Pi |
| `Append` p99 ≤ 5 ms with a 2 ms `MaxDelay` | **Not met as a fixed number**, and replaced by a structural statement (RNF-03) |

### Why the p99 is not a number tally can promise

An `Append` that arrives while a batch is being made durable waits for that batch's fsync, then for the next
batch's `MaxDelay`, then for its own fsync; when a checkpoint is due after a batch, its signature and its
fsync come between (one every 1000 entries by default). tally's own work per entry is around a microsecond:
`Verify`, which decodes, re-encodes and hashes every entry, does 1.3M a second. So the p99 is a sum of the disk's fsync latency, the platform's timer, and the
checkpoint policy, and the measurements show each one dominating somewhere:

- **The disk.** On macOS one `F_FULLFSYNC` averages 4 ms (`maxdelay=0`, one caller), and its p99 alone, 7 ms,
  is over 5 ms. No setting of tally reaches the target there.
- **The card.** On the Pi, one caller without a delay has a p99 of 2.8 ms, under 5 ms; with the 2 ms
  `MaxDelay` it is 5.2 ms, just over, and every extra caller adds a batch in flight to wait for.
- **The timer.** In the Linux VM the 2 ms `MaxDelay` cost 3.8 ms on average (one caller: 4.2 ms with it,
  0.45 ms without), and the p99 with it stayed at 6.5 ms with automatic checkpoints turned off as well. A
  `MaxDelay` is a lower bound on the wait, not an upper one.
- **Few callers wait the whole `MaxDelay`.** The writer cannot know that no one else is coming, so with fewer
  callers than `MaxBatch` every batch waits out the delay. **One caller should set `WithMaxDelay(0)`:** in
  the Linux VM that took its p99 from 6.5 ms to 1.3 ms and its rate from 237 to 2,244 entries/s.

The 5 ms figure stays a provisional target for Linux on NVMe, to be confirmed on such hardware; nothing
measured here is that platform.
