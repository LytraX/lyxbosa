# Parallel scanning — measured scaling, what blocks it, and what it costs a live server

**Date:** 2026-09-03
**Commit:** `bbfbcee`
**Build:** `build-release`, `-O3 -DNDEBUG -std=c++20`, RE2 2025-11-05
**Rule set:** the live registry, 173 patterns across 125 builtin rules
**Machine:** Intel Xeon w7-3465X, 28 cores / 56 threads, 32 GB, WSL2
**Corpora:** `trail-data/CMS` (stock CMS), `trail-data/Sites` (production site), `trail-data/Infected` (malware)

The scanner runs on one thread. This measures what it would take to run it on several,
what that buys, and what it costs the machine it is running on — which for this tool is
usually somebody's live web server.

The short version: **`MatchEngine` already scales and needs no changes at all.** Every
obstacle is in `Scanner` and the reporting seam. And parallelism does not make a scan
cost more CPU; it makes it cost the same CPU in a shorter, deeper burst.

---

## 1. Where the time goes today

Before asking whether threads help it is worth knowing what they would be helping with.
A full run over `trail-data/CMS` — 51,293 files scanned out of 53,977, 561 MB on disk —
takes 5.77 s with the page cache warm, and spends nearly all of it on the CPU.

Cutting the rule set to a single rule isolates everything that is *not* matching:
opening files, reading them, walking directories, dispatching.

| configuration | wall | user | sys | attributable |
|---|---:|---:|---:|---|
| walk + read + framework, 1 rule | 1.36 s | 1.16 s | 0.72 s | I/O and traversal floor |
| walk + read + all 125 rules | 5.77 s | 5.51 s | 0.70 s | **matching ≈ 4.4 s, 76%** |
| `readdir` alone | 0.16 s | — | — | 3% of the scan |
| `readdir` + `file_size()` per entry | 0.24 s | — | — | 5% of the scan |

Three quarters of a warm scan is regex and analyzer work on bytes already in memory,
and the serial traversal that a producer thread would keep to itself is 3–5% of it.
That is close to the ideal starting point for a worker pool: a large, embarrassingly
parallel body of work behind a cheap serial front.

The 107% CPU a scan shows today is the concurrent pre-count thread, not parallel work.

---

## 2. It scales, and the engine needs no changes to do it

Method: load each corpus into memory, then run `MatchEngine::match()` from *N* threads
pulling files off one atomic counter. I/O is removed on purpose, so what is measured is
the matching work and whatever the threads contend on while doing it. Best of three per
thread count, after a warm-up pass — RE2 builds its DFA lazily, and charging that
construction to the first measured run would flatter every later one.

Files are handed out largest-first (see §4 for why that matters).

| corpus | files | MB | 1 thread | 2 | 4 | 8 | 16 |
|---|---:|---:|---:|---:|---:|---:|---:|
| stock CMS | 50,230 | 268 | 4.30 s | 1.96× | 3.96× | **7.56×** | **14.91×** |
| production site | 18,968 | 386 | 7.01 s | 1.98× | 4.00× | **7.67×** | **14.86×** |
| malware | 4,950 | 132 | 4.05 s | 2.00× | 3.99× | **7.84×** | 8.39× |

Efficiency at 8 threads is 95–98% on all three. At 16 it is 93% on the two clean trees;
the malware corpus stalls at 8.39× for a reason that is not contention and is dealt with
in §4. Past 16 it falls away as SMT siblings contend — 59% efficiency at 32 threads on a
28-core host — so there is no case for a default above single digits.

### Two things that looked like bottlenecks and are not

**The global `PatternCache` mutex.** Every pattern lookup in `BuiltinRule::findMatches`
takes `std::lock_guard` on one process-wide mutex
(`src-lib/cpp/rules/RuleDefinition.hpp:74-78`), which is the obvious serialization point.
Counting the acquisitions says otherwise:

| corpus | lookups | per file |
|---|---:|---:|
| stock CMS | 144,567 | 2.9 |
| production site | 77,309 | 4.1 |
| malware | 41,149 | 8.3 |

The literal prefilter shipped in 2.1.0 cut rule dispatch to a handful of rules per file,
and it cut this with it. Recompiling with a `thread_local` cache — removing the lock
entirely — made the scan **slower** at every thread count (7.10× vs 7.67× at 8 threads,
13.85× vs 14.86× at 16), because each thread then compiles and warms its own RE2 objects
instead of sharing hot ones. The lock stays.

**RE2's shared DFA state cache.** Giving every thread its own `MatchEngine`, prefilter
and residual `RE2::Set` changed nothing measurable:

| corpus, 8 threads | shared engine | engine per thread |
|---|---:|---:|
| stock CMS | 7.45× | 7.47× |
| production site | 7.79× | 7.27× |
| malware | 4.74× | 4.82× |

One engine, shared read-only across all workers, is the right design, and it saves the
per-thread memory that duplication would cost.

> `MatchEngine::match()` (`core/MatchEngine.cpp:1382`) is `const` over state that is
> immutable after `rebuildPrefilter()`. It needs no lock, no duplication and no change
> to go parallel.

### A cold page cache makes threads matter more, not less

Everything above is warm-cache, which is a re-scan. The first scan of `/var/www` on a
live host is not. Evicting the corpus with `posix_fadvise(POSIX_FADV_DONTNEED)` before
each run puts the reads back on the device, where per-file open latency dominates and
parallelism hides it.

`trail-data/Sites`, 24,126 files / 661 MB:

| threads | read only | MB/s | read + match | MB/s | speedup |
|---:|---:|---:|---:|---:|---:|
| 1 | 7.55 s | 88 | 18.30 s | 36 | 1.00× |
| 2 | 2.85 s | 232 | 8.84 s | 75 | 2.07× |
| 4 | 1.45 s | 456 | 4.40 s | 150 | 4.16× |
| 8 | 0.78 s | 853 | 2.28 s | 291 | **8.04×** |
| 16 | 0.45 s | 1477 | 1.17 s | 566 | **15.65×** |

Read-only scaling is superlinear — 2.64× at two threads — because a single thread spends
most of its time waiting on one outstanding read at a time. Queue depth, not bandwidth,
is the constraint on a tree of 24,000 small files. This is the case an operator actually
runs.

---

## 3. The full pipeline, and how little of it is serial

Walk, open, read and match together, with the walk timed on its own because that is the
Amdahl term a producer thread cannot shorten:

| corpus | files | serial walk | 1 thread | 8 | 16 | walk as % of 1-thread scan |
|---|---:|---:|---:|---:|---:|---:|
| stock CMS | 53,914 | 0.30 s | 6.06 s | 7.60× | 13.60× | 5% |
| production site | 24,126 | 0.09 s | 12.13 s | 7.57× | 14.60× | 1% |

The walk is not the problem. It becomes one only in the sense described at the end of
§6: at 16 threads the *pre-count* — a second full traversal — takes about as long as the
whole scan.

---

## 4. The one thing that does not scale is the long tail

Per-file cost spans four orders of magnitude.

| corpus | files | p50 | p90 | p99 | p99.9 | max | slowest 10 |
|---|---:|---:|---:|---:|---:|---:|---:|
| malware | 5,325 | 0.07 ms | 0.81 ms | 11.6 ms | 98.7 ms | **617 ms** | **44.5%** of all work |
| production site | 24,126 | 0.03 ms | 0.50 ms | 9.3 ms | 41.4 ms | 285 ms | 8.9% of all work |

With one file per queue pull the scheduler is already as fine-grained as it can be, so
the ceiling is set by the longest single item. For the malware corpus that is **8.84×,
whatever the thread count** — sixteen threads cannot finish sooner than the 617 ms file.

What *can* be fixed is the order in which files are handed out. Pulling in directory
order, a 617 ms file picked up last leaves fifteen threads idle. Handing out the largest
files first is the classic LPT approximation, and it recovers nearly all of the loss:

| malware corpus, order | 2 | 4 | 8 | 16 |
|---|---:|---:|---:|---:|
| walk order (directory sequence) | 1.92× | 3.11× | 4.76× | 6.53× |
| **largest first (LPT)** | **2.00×** | **3.99×** | **7.84×** | **8.39×** |
| ceiling (Amdahl on the longest file) | 2.00× | 4.00× | 8.00× | 8.84× |

At 8 threads LPT is worth **+65%** on infected trees, and it costs nothing on clean ones
— it moved the production site from 91% to 93% efficiency at 16 threads.

It needs sizes before dispatch, which the walker already has: `FileInfo::size` is filled
in during traversal. A full sort would serialize the walk, so the practical form is a
bounded reorder window — buffer a few thousand entries, emit largest-first, refill.

---

## 5. What blocks it in the code

All of it is in `Scanner::scan()` and the reporting seam it feeds.

### Must be restructured

**The walk callback is the accumulator** — `src-lib/cpp/core/Scanner.cpp:227-393`.
`fileCallback` reads the file, matches it, quarantines it, increments nine counters on
`result`, appends to `result.files`, and publishes progress, all inline. Every one of
those becomes a race the moment a second thread enters. This is the actual work of the
change.

**`files.push_back(x)` then `callback(files.back())`** — `Scanner.cpp:200-202, 242-244,
259-263, 292-296`. Four call sites hand the consumer a reference into a vector that any
other thread's `push_back` can reallocate out from under it. Safe today only because
nothing else is running. Pass the `FileResult` by value, or hold it in a stable
container.

**One `ArchiveScanner` for the whole scan** — `Scanner.h:123`, `ArchiveScanner.h:64-65,
105-113, 131-134`. A single instance whose `onFinding_`/`onProgress_` callbacks are
reassigned mid-scan, and whose `Context` carries a per-archive `Budget` and `Stats`. It
needs to be one per worker — they are cheap, `MatchEngine` is held by reference — or
archives handled on a dedicated thread.

### Races to fix

**Quarantine picks a free filename by looking** — `Scanner.cpp:585-593`. The
duplicate-suffix loop tests `fs::exists(dest)` and then renames into it. Two workers
quarantining same-named files from different directories will both pick `shell.1.php`
and one will silently overwrite the other's evidence. Needs a mutex around name
selection, or an exclusive-create probe.

**Report writers stream, and would interleave** — `JsonReportWriter.h:23`,
`ScanUseCase.h:421-439`. `onFile` writes a record and flushes on every finding; the same
callback also drives the CSV writer, the console writer and the TUI. Unsynchronized this
corrupts output. Naively locked it produces a *different file order every run*, which
breaks diffing against `.baseline/`. Order has to be **restored**, not just serialized —
see §6.

**`mutable std::string patternDesc_`** — `patterns/HeuristicPattern.h:50`. Lazily filled
by `pattern()` on a `const` object: a data race if two workers describe the same custom
YAML rule at once. Unreachable from the builtin path, but it contradicts `Pattern.h`'s
own "immutable after construction (thread-safe)" comment and should be precomputed in
the constructor.

**The walker's directory callback** — `FileWalker.h:70-74` already says it: "Not
thread-safe with respect to `walk()`; set it before walking, and use a separate
`FileWalker` per thread." In a producer/consumer shape only the producer walks, so this
stays satisfied — but `ArchiveScanner::filters_` is a second walker instance to account
for.

### Correct, but scales per thread

**`thread_local FoldCache`** — `analysis/StringAssembly.cpp:978`. The constant-folding
memo keeps a full copy of the last file's bytes per thread. Correct as written, but with
`max_file_size` at 25 MB it is a *per-thread* allowance, not a global one. Measured
growth is ~14 MB of RSS per worker; see §7.

### Needs no change at all

`MatchEngine::match()`, `PatternCache` (already mutex-guarded, measured harmless), RE2
and `RE2::Set` (thread-safe for const use), and `g_interrupted`
(`core/Interrupt.h:12`, already an atomic polled by every long-running loop).

---

## 6. The shape that keeps the reports identical

A security scanner whose JSON output reorders itself between runs cannot be diffed
against a baseline, and this project keeps `.baseline/` precisely to do that. So the
design has to restore walk order on the way out, not merely stop the writers from
corrupting each other.

```
  produce           buffer         match            reorder          emit

  ┌─────────────┐   ┌──────────┐   ┌────────────┐   ┌────────────┐   ┌──────────────────────┐
  │ FileWalker  │   │ bounded  │   │  worker 1  │   │  ordered   │   │    report writers    │
  │  1 thread   │──▶│  queue   │──▶│  worker 2  │──▶│    sink    │──▶│ progress + counters  │
  │ stamps seq  │   │ cap 4×N  │   │  worker N  │   │  next = 7  │   │ walk order preserved │
  └─────────────┘   │ largest  │   └────────────┘   │#9 #10 held │   └──────────────────────┘
         ▲          │  first   │   read + match,    └────────────┘
         │          └─────┬────┘   one shared       releases only when
         │                │        MatchEngine,     its seq is next due
         └────────────────┘        read-only
         blocks when full
         → bounds memory
```

The walker stamps a sequence number; the sink hands it back. Workers finish out of order
— that is the whole point — but the sink releases a result only when its sequence number
is the next one due, so the writers, the TUI and the counters see exactly the stream a
serial scan produced.

Three properties fall out of this shape and are worth stating as requirements:

- **Determinism is preserved by construction.** Reports, exit codes and `.baseline/`
  diffs are unchanged. That should be a *test*: run the same tree at 1 and 8 threads and
  assert the JSON is byte-identical modulo `durationMs`.
- **Only the sink thread touches `result`.** No atomics on the counters, no lock on the
  writers, and no thread-safety requirement pushed into `TuiReporter` or `PlainProgress`
  — which today are documented as single-threaded and can stay that way.
- **Interruption already works.** `g_interrupted` is polled by the walk and the count;
  workers poll the same flag and drain. The partial report stays correct because the
  sink still emits in order.

**One side effect to plan for.** The concurrent pre-count is a second full traversal, and
it does not get faster. On the stock-CMS tree it takes ~0.3 s while a 16-thread scan
finishes everything in 0.45 s — so the progress bar would reach 100% at roughly the
moment the percentage first becomes available. Either fold the count into the same walk
(the producer already stats every file) or drop the second traversal at high thread
counts.

---

## 7. What it costs a live server

This is the part that decides the default, and the headline is slightly
counter-intuitive: **threads do not make the scan cost more CPU.**

Identical total work at every thread count, `trail-data/Sites`:

| threads | total CPU (user+sys) | peak RSS |
|---:|---:|---:|
| 1 | 48.96 s | 75 MB |
| 2 | 48.67 s | 96 MB |
| 4 | 48.34 s | 133 MB |
| 8 | 49.31 s | 205 MB |
| 16 | 50.82 s | 296 MB |

CPU-seconds vary by **4% across a sixteen-fold change in concurrency**. The machine does
not do more work; it finishes sooner. Memory is the resource that actually scales with
the pool: roughly **14 MB of RSS per worker**, from the per-thread read buffer and the
`thread_local` fold cache.

### The operator's actual trade

For a 24,000-file, 661 MB web root with a cold cache, on a 4-vCPU host:

| threads | wall clock | host CPU used | CPU-seconds | peak RSS | what's left for the site |
|---:|---:|---:|---:|---:|---|
| 1 (today) | 18.3 s | 25% | ~18 s | 75 MB | 3 of 4 cores stay free |
| 2 | 8.8 s | 50% | ~18 s | 96 MB | half the box, half as long |
| 4 | **4.4 s** | **100%** | ~18 s | 133 MB | nothing free for 4 seconds |

A four-second interval where every core is busy is not automatically worse than eighteen
seconds at a quarter of the box — for many hosts it is better, because the disturbance is
over before a monitoring window closes and before request queues build. But it is a
decision the operator has to make against their own latency budget, not one the scanner
should make for them.

### What that implies for defaults

1. **Default to one thread.** The tool runs on production web servers; the current
   behaviour is the safe behaviour and should stay the default. Threads are opt-in via
   `-j/--threads`, with `--threads=auto` for the analyst running it on a workstation or a
   quarantined copy.
2. **Never trust `hardware_concurrency()` for "auto".** On this host it reports 56. In a
   2-vCPU container it still reports the host's count, so `auto` would spawn 56 workers
   into a 2-CPU quota and spend the scan being throttled by the CFS period. Detection has
   to read the actual limit — see §8.
3. **Cap "auto" well below the core count.** Efficiency is 95–98% at 8 threads and 93% at
   16 on this 28-core host, then falls to 59% at 32. `min(cores, 8)` is a defensible
   auto, and it is where the measured efficiency still is.
4. **Offer a real throttle, not just a thread count.** Lowering scheduling priority is the
   right primitive for "scan without anyone noticing"; a thread count alone cannot express
   it.
5. **Budget memory as N × per-worker.** With `max_file_size: 25MB`, worst case per worker
   is the read buffer plus the fold cache's copy — 50 MB each in the pathological case,
   ~14 MB measured. Shrinking the read buffer when it exceeds a threshold, and bounding
   the fold cache, would cap it.

---

## 8. Linux and Windows

The threading itself is portable: `std::jthread`, `std::atomic`, a condition variable and
a bounded queue need no platform code. Everything that makes the scan a *polite*
background job does.

| question | Linux | Windows |
|---|---|---|
| How many CPUs may I use? | `sched_getaffinity()` for cpusets and `taskset`, then the cgroup quota — v2 `/sys/fs/cgroup/cpu.max` (`"200000 100000"` = 2 CPUs, `"max"` = none), v1 `cpu.cfs_quota_us ÷ cpu.cfs_period_us`. Resolve the process's own cgroup via `/proc/self/cgroup`, not the root. | `GetActiveProcessorCount(ALL_PROCESSOR_GROUPS)`, `GetProcessAffinityMask`, and job-object limits via `QueryInformationJobObject(JobObjectCpuRateControlInformation)` — the Windows-container equivalent of a cgroup quota. |
| Yield CPU to the web server | `setpriority(PRIO_PROCESS, 0, 10)` for a nice level, or `sched_setscheduler(0, SCHED_IDLE, …)` for "run only when nothing else wants the CPU" — the right setting for an unattended cron scan. | `SetPriorityClass(GetCurrentProcess(), PROCESS_MODE_BACKGROUND_BEGIN)` drops CPU, I/O *and* memory priority in one call; `PROCESS_MODE_BACKGROUND_END` restores it. `SetThreadPriority(…, THREAD_MODE_BACKGROUND_BEGIN)` is the per-worker form. |
| Yield the disk | `ioprio_set` with `IOPRIO_CLASS_IDLE`, reached through `syscall()` since glibc exposes no wrapper. Matters more than CPU priority when the database shares the spindle or the IOPS budget. | Covered by `PROCESS_MODE_BACKGROUND_BEGIN` above — there is no separate call to make. |
| Cost of the walk | `readdir` gives no size, so `directory_entry::file_size()` is a syscall per file: 0.16 s → 0.24 s across 54k files. | `FindFirstFileEx` returns the size in `WIN32_FIND_DATA` and MSVC's `directory_entry` caches it, so `file_size()` during a walk is free. |
| Cost of opening a file | One `openat`. | Every `CreateFile` traverses the filter-driver stack, and with Defender real-time protection each open can trigger an AV scan of its own. |

Two traps worth calling out:

- **Processor groups.** Above 64 logical CPUs a Windows process sees only its own group
  unless it is group-aware, so `hardware_concurrency()` can *under*-report there as badly
  as it *over*-reports inside a Linux container.
- **Defender.** Expect parallelism to pay better on Windows than on Linux, because there
  is more per-open latency to hide — and expect some of the resulting CPU to land in
  `MsMpEng.exe` rather than in this process, where an operator watching the scanner's own
  usage will not see it.

Largest-first dispatch (§4) is free on both platforms, for different reasons.

Both sets belong behind one small interface — something like `system/CpuBudget.h` (how
many workers may I run?) and `system/Priority.h` (run me in the background), alongside
the existing `system/SystemDirectory.h` and the `fnmatch` shim in `core/FileWalker.cpp`,
which is already the project's pattern for this.

---

## 9. Recommendation

**Build it, default it to one thread, and make `auto` mean the cgroup quota rather than
the host's core count.**

The engine is already in the right shape and the measurement says the win is real: 7.6–7.8×
on 8 threads warm, 8.0× cold, and the cold case is the one an operator runs. The cost is
confined to `Scanner`, and the one property that must not regress — byte-identical
reports — is preserved by construction rather than by care.

### Sequence

Ordered so that each step is independently useful and independently revertible, and so
the risky one lands after the safety net exists.

1. **Pin determinism first.** Add the test that asserts a scan of a fixed tree produces
   byte-identical JSON on two runs. It passes trivially today, and it is what will catch
   every ordering mistake in steps 3–5. Recapture `.baseline/` against it.
2. **Fix the latent hazards while still single-threaded.** Pass `FileResult` to the
   callback by value rather than as `files.back()`; precompute
   `HeuristicPattern::patternDesc_` in the constructor; guard the quarantine
   name-selection loop. All three are correct improvements on their own, and none of them
   needs a thread to justify.
3. **Split the walk callback into produce and consume.** Extract the body of
   `fileCallback` into a pure `FileOutcome scanOne(const FileInfo&)` that returns
   everything instead of mutating `result`, and a sink that folds an outcome into `result`
   and drives the callbacks. Still one thread, still identical output — this is the whole
   refactor, done safely.
4. **Add the pool, the bounded queue and the ordered sink.** Walker stamps a sequence
   number, workers call `scanOne`, the sink releases in sequence order. One
   `ArchiveScanner` per worker. Default `--threads=1`, so shipped behaviour is unchanged
   until someone asks for more. The test from step 1 gates the merge.
5. **Largest-first dispatch.** A bounded reorder window in the producer. Worth +65% at 8
   threads on infected trees and nothing on clean ones — a scheduling change on top of a
   working pool, not part of building it.
6. **The live-server controls.** `--threads=auto` backed by real cgroup and job-object
   detection, capped at 8; `--background` for `SCHED_IDLE` + idle I/O priority on Linux
   and `PROCESS_MODE_BACKGROUND_BEGIN` on Windows. Then fold the pre-count into the
   producer's walk, which by that point is the remaining serial traversal.

---

## 10. Method, and where not to trust these numbers

Three harnesses were built against the live `src-lib` at `bbfbcee` with the release flags
from `build-release/compile_commands.json`:

- **`par_scale`** — corpus preloaded into memory, *N* threads over
  `MatchEngine::match()`; modes for one shared engine vs one per thread, and for walk
  order vs largest-first.
- **`pipe_scale`** — the same with `open`/`read` in the worker, plus the serial walk timed
  separately.
- **`file_cost`** — the per-file cost distribution and the Amdahl ceiling it implies.

They lived in the session scratchpad and **are not in the repository**, so the numbers
here are not currently reproducible the way
[`regex-engine-benchmark-2026-09-02.md`](regex-engine-benchmark-2026-09-02.md)'s are.
Landing them as a `benchmarks/parallel_scale.cpp` target behind the existing
`LYXBOSA_BENCHMARKS` option is the obvious follow-up, and should happen before step 4 of
the sequence so the scaling claim can be re-checked on the machine that ships it.

Caveats:

- The host is WSL2 on a virtualised disk. Absolute I/O figures — particularly the
  cold-cache table in §2 — indicate the *shape*, not what bare-metal NVMe or a network
  mount would give. The CPU-side measurements are not affected by this.
- Cold-cache runs evict with `posix_fadvise(POSIX_FADV_DONTNEED)`, which is best-effort:
  dirty or mapped pages survive it. Those numbers are a lower bound on the benefit of
  parallel I/O, not an upper one.
- The 8.84× ceiling on the malware corpus is a property of *that corpus*, not of the
  scanner. A tree with a different largest file has a different ceiling; the mechanism —
  one item bounds the finish — is general.
- **Nothing in the Windows column of §8 has been run.** It is from the platform
  documentation and from reading this code, and it should be measured — the 4-vCPU
  container case on both platforms especially — before a default ships.
