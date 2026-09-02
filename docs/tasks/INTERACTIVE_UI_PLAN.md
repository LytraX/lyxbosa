# Interactive CLI UI & Output-File Plan

Status: **phases 0, 1 and 2 implemented**; phase 3 proposed
Scope: `lyxbosa scan` (and, secondarily, `check`)

Decisions taken: the pinned status goes **below** the findings; the output-file option
is **`-O, --output-file`**; the full-screen TUI is **the interactive default where the
terminal supports it**, falling back automatically where it does not, and it dumps the
findings and summary into the primary buffer on exit.

## 1. Goals

1. **Interactive progress UI** when attached to a real terminal: percentage, files/dirs
   scanned, live severity breakdown, currently-scanning path, and a pinned status
   region that findings scroll past without disturbing.
2. **`--output-file`**: write the machine report to a file so stdout is free for the
   live UI. Output format then applies to the *file*, not to what the user watches.
3. Degrade cleanly and predictably when there is no terminal (pipes, redirects, CI,
   cron), and let the user force either behaviour.

---

## 2. What already exists

The scanner is already well-decoupled from rendering, which makes this cheaper than
it looks:

- `Scanner` (`src-lib/cpp/core/Scanner.h`) exposes three callbacks:
  `ProgressCallback`, `CountingCallback`, `MatchCallback`. Rendering is entirely in
  the use case, not in the engine.
- `FileWalker::countFiles()` pre-counts, so a determinate percentage is possible.
- `Terminal` (`src-lib/cpp/infrastructure/Terminal.h`) already wraps cursor moves and
  styles behind a single `useAnsi_` switch.
- `ActionsConfig::report` already has `console`, `file` and `format` fields, parsed by
  `Config.cpp:135-145` — **but never read by any code**. `--output-file` should land
  here rather than inventing a parallel mechanism.

What does *not* exist: any TTY detection, any stream discipline, and any report sink
other than raw `fmt::print` to stdout.

---

## 3. Problems found during the audit

These are worth fixing as part of this work; several are the actual cause of the
reported symptom.

### 3.1 ANSI is emitted regardless of whether stdout is a terminal — the root cause

`src-cli/lyxbosa.cpp:74` builds `Terminal terminal(!args.noAnsi)`. There is no
`isatty()` anywhere in the tree. So `lyxbosa scan /var/www > out.txt` writes colour
codes, `\033[2K`, `\033[1A` and the progress dance *into the file*, and the user sees
nothing. Redirecting is currently broken in both directions.

**Fix:** auto-detect. Progress and diagnostics go to **stderr**; the report goes to
stdout (or `--output-file`). That alone makes `lyxbosa scan ... > out.txt` show
progress today, before any TUI work.

### 3.2 The graceful-interrupt path is dead code

`signalHandler` (`src-cli/lyxbosa.cpp:34-41`) sets `g_interrupted`, then immediately
restores `SIG_DFL` and re-raises — the process dies inside the handler. The
`wasInterrupted()` branch in `ScanUseCase` (partial summary, exit 130) can never run.
The handler also calls `fmt::print` and `std::cout.flush()`, neither async-signal-safe.

**Fix:** handler sets an `atomic_bool` and nothing else. First Ctrl+C unwinds the scan
loop cleanly (flush partial report, print summary, exit 130); a second Ctrl+C hard-exits.
With a TUI this is not optional — dying inside the handler leaves the terminal in raw
mode with the cursor hidden.

### 3.3 The confirmation prompt defaults to *yes* on EOF

`ScanUseCase.h:112-119`: `std::getline` fails at EOF, leaves `input` empty, and empty
is treated as "yes". So `lyxbosa scan /var/www < /dev/null` proceeds — and quarantine
may be enabled. For a tool that moves files, that is a sharp edge.

**Fix:** when stdin is not a TTY, do not prompt; require `--force` (or abort with a
clear message). Same for the directory prompt at `ScanUseCase.h:33-42`.

### 3.4 Every scanned file is retained in memory — *fixed in phase 1*

`Scanner.cpp:101` pushes a `FileResult` for *every* file, matches or not. On a
5M-file scan that is millions of `std::filesystem::path` objects held for the whole
run, to be filtered out at print time. Now that we want long scans to be watchable,
this becomes the thing that OOMs at hour three.

**Fix:** retain only files with matches or `skippedSize`; keep counters for the rest.
Streaming report writers (§5.3) make this straightforward.

### 3.5 Path truncation counts bytes, not display columns — *partly fixed*

`ResultPrinter::truncatePath` no longer splits a UTF-8 codepoint (phase 1), but it
still counts *bytes* rather than display columns, so a path of wide characters is cut
short of the space available. Full width-awareness needs FTXUI's cell measurement in
phase 3. Originally both call sites used plain `std::string::length()` on UTF-8. Greek/Cyrillic paths — which this project explicitly
cares about, see the `SetConsoleOutputCP(CP_UTF8)` comment in `lyxbosa.cpp` — truncate
mid-codepoint and mis-align columns. A pinned status region makes every such glitch
permanent instead of scrolling away.

### 3.6 The 3-line cursor dance is structurally fragile

`ScanUseCase.h::updateProgress` / the match callback move the cursor up 1-2 lines and
rewrite in place. This breaks whenever a line soft-wraps (long paths at narrow widths),
whenever the terminal is resized (no `SIGWINCH` handling at all), and whenever anything
else writes to the terminal. This is precisely what FTXUI replaces.

### 3.7 The pre-count is a silent dead phase — *fixed in phase 2*

`Scanner.cpp:53` calls `walker.countFiles()`, a full second traversal, before the first
file is scanned. On a large or network-mounted tree that is minutes of `Globbing
files...` with no feedback, and it doubles directory I/O.

**Fix (choose one):** (a) show an indeterminate spinner with a live "discovered N"
counter, or (b) run the count on a background thread concurrently with scanning and
switch the bar from indeterminate to determinate when it lands, or (c) `--no-precount`.
`FileWalker` is const and stateless apart from its config, so (b) is safe.

### 3.8 Windows VT is assumed, not enabled

`main` sets the output code page but never enables
`ENABLE_VIRTUAL_TERMINAL_PROCESSING`. On older conhost the escape sequences print as
garbage. FTXUI's screen does this for us; the non-TUI path should do it explicitly.

---

## 4. Design: stream discipline and mode matrix

The single organising principle:

> **stdout carries the report. stderr carries the human. The TUI is a form of stderr.**

### Resolution order for "is the UI on?"

```
interactive = tty(stdout or stderr)
            && !--no-interactive && !--no-ansi && !--quiet
            && TERM != "dumb" && !NO_COLOR-ish
            || --interactive (forced)
```

Honour the conventional environment: `NO_COLOR` (any value ⇒ no colour),
`CLICOLOR_FORCE`, `TERM=dumb`, and a `CI` check for the default.

### Behaviour matrix

| stdout | `--output-file` | What the user sees | Where the report goes |
|---|---|---|---|
| TTY | no | Live UI; findings + summary dumped to the primary buffer on exit | stdout |
| TTY | yes | Live UI | the file, in `--output` format |
| pipe/file | no | plain progress on stderr if stderr is a TTY, else nothing | stdout, in `--output` format |
| pipe/file | yes | plain progress on stderr if stderr is a TTY | the file; stdout stays empty |

Note the third row: `lyxbosa scan ... > out.json -o json` becomes useful *without*
`--output-file`, because progress moves to stderr. `--output-file` is then the
convenience that also lets stdout stay clean for the UI.

---

## 5. Component design

Four new seams. All of them keep `Scanner` untouched apart from a richer progress
struct.

### 5.1 `TerminalCaps` — `src-lib/cpp/infrastructure/TerminalCaps.h`

One place that answers: is stdout a tty, is stderr a tty, is stdin a tty, terminal
width/height, colour allowed, VT enabled (and enables it on Windows), `NO_COLOR`,
`TERM`, CI. `Terminal` is constructed from it instead of from `!noAnsi`.

### 5.2 `ProgressModel` — `src-lib/cpp/infrastructure/ProgressModel.h`

Pure state, no rendering, unit-testable without a terminal:

```
phase          Counting | Scanning | Finalizing | Done | Interrupted
filesScanned / filesTotal / percent
dirsScanned                        (currently only known at the end)
bytesScanned
skipped(size) / unreadable
filesWithMatches
critical / high / medium / low     (currently only totalMatchCount exists)
quarantined
currentPath
elapsed, filesPerSec, bytesPerSec, eta
```

`ScanProgress` in `Scanner.h` grows to feed this: add the severity breakdown, a live
directory counter, bytes, and a phase enum. Rate/ETA are derived in the model with a
smoothed (EWMA) rate so the ETA does not thrash.

### 5.3 `ReportWriter` — `src-lib/cpp/infrastructure/report/`

```
class ReportWriter {
  virtual void begin(const AppConfig&) = 0;
  virtual void onFile(const FileResult&) = 0;   // streamed, as found
  virtual void end(const ScanResult& summary, bool interrupted) = 0;
};
```

Implementations: `TextReportWriter`, `JsonReportWriter`, `CsvReportWriter`, `NullReportWriter`.
All take a `std::ostream&`, so the same code serves stdout and a file. Streaming means:

- Partial results survive Ctrl+C (open the JSON array in `begin`, close it in `end`;
  on interrupt still close it and set `"interrupted": true`).
- No need to retain clean files in memory (§3.4).

This also replaces the current `printJson`, which builds JSON with `fmt::print` and
**does not escape strings** — a path containing `"` or `\` produces invalid JSON today.
Worth fixing while we are in there.

### 5.4 `ScanReporter` — the UI seam

```
class ScanReporter {
  virtual void onCountingProgress(size_t discovered) = 0;
  virtual void onCountingDone(size_t total) = 0;
  virtual void onProgress(const ProgressModel&) = 0;
  virtual void onFinding(const FileResult&) = 0;
  virtual void onFinished(const ScanResult&, bool interrupted) = 0;
};
```

Three implementations:

- **`NullReporter`** — quiet / no tty / `--progress=none`.
- **`PlainReporter`** — no ANSI. One line to stderr every N seconds or N files:
  `[ 34%] 12043/35110 files  8 crit  21 high  2m14s left`. Safe for CI logs and cron.
- **`TuiReporter`** — FTXUI (§6).

Choosing the reporter is the *only* place the mode matrix is consulted.

---

## 6. FTXUI: recommendation and verified API

**Recommendation: yes, use FTXUI — but for the pinned-status model first, not a
full-screen dashboard.**

`ftxui` is in the vcpkg registry at the pinned baseline (`30ef65c`) as **7.0.3**. Add
it to `vcpkg.json` and link `ftxui::screen ftxui::dom ftxui::component`.

Verified against the 7.0.3 headers (not assumed):

- `ftxui::ScreenInteractive` is now an alias for **`ftxui::App`** — the v7 rename. Code
  written against v5/v6 tutorials still compiles, but new code should say `App`.
- **`App::TerminalOutput()`** — full terminal width, height fits the component, drawn in
  the *primary* buffer at the cursor. This is the pinned-status-at-the-bottom model.
- **`App::Fullscreen()`** — alternate screen buffer, for the later full dashboard.
- **`App::WithRestoredIO(Closure)`** — wraps a closure so it runs with FTXUI's terminal
  hooks temporarily uninstalled. **This is the mechanism for printing findings into
  real scrollback above the live region.** It is the piece that makes the "hard part"
  not hard.
- **`ftxui::Loop(App*, Component)` with `RunOnce()` (non-blocking)** — so the scan stays
  on the main thread and we pump one frame between files. **No worker thread needed for
  v1.** This is a significant simplification over the usual `Loop(component)` +
  background-thread pattern.
- `App::ForceHandleCtrlC(false)` — hand Ctrl+C back to us so §3.2's graceful cancel works.
- `App::HandlePipedInput(bool)` — relevant because we may be reading a piped stdin.

### Why full-screen, after all

The original proposal here was a status block in the *primary* buffer
(`App::TerminalOutput()` + `WithRestoredIO`), on the grounds that findings would then
live in the terminal's own scrollback. That was reconsidered against the actual
requirement: **the status must stay visible while the user scrolls back through the
findings.**

That is not achievable in the primary buffer. Terminal scrollback belongs to the
emulator and is entirely client-side; the application is never told the user scrolled
and cannot draw into the scrolled-back view. Anything we print — pinned-looking or not
— scrolls away with everything else. `DECSTBM` (`CSI top;bottom r`) reserves a fixed
footer and confines scrolling above it, which removes flicker during the scan, but the
footer is part of the viewport and is replaced along with it when the user scrolls
history.

Pinning while the user scrolls therefore requires the application to own the viewport
and implement its own scroll: the alternate screen buffer. Claude Code's own CLI is the
existence proof — its "jump to bottom" affordance can only exist because it owns
scrolling. tmux's status bar is the same trick one level up.

So the dashboard is **reinstated as the interactive default**, with two obligations:

1. **On exit, dump the findings and the summary into the primary buffer.** This is what
   keeps `grep`, copy-paste and "what did that scan actually say" working after the
   alternate screen is torn down, and it removes the only real objection to owning the
   screen.
2. **Detect support and degrade automatically** — never assume the alternate screen
   works (see below).

### Detecting whether the full-screen UI is usable

`TerminalCaps` already answers most of this from phase 0. The TUI runs only when *all*
of the following hold, and otherwise falls back silently to the phase-0 stderr line:

- stdout is a terminal and virtual-terminal sequences are usable (`vtOut_`);
- colour is not disabled (`--color=never` / `--no-ansi` / `NO_COLOR`);
- `TERM` is set and is not `dumb`;
- the terminal reports a workable size — a dashboard needs roughly 10 rows and 40
  columns; below that the status block is worth more than the pane;
- the alternate screen is actually supported (terminfo `smcup`/`rmcup`, or FTXUI
  reporting the capability);
- we are not in CI, and `--progress=plain|none`, `--no-interactive` and `--quiet` were
  not given;
- the binary was built with `LYXBOSA_TUI=ON`.

Resize is handled by FTXUI (`SIGWINCH`), and a terminal that shrinks below the minimum
mid-scan should collapse to the status block rather than draw a broken frame.

### Costs to acknowledge

FTXUI is a real dependency: build time, binary size, and a second rendering path. Given
`docker/` and `dist/` exist, gate it with a CMake option `LYXBOSA_TUI` (default `ON`)
so a minimal/static build can compile `TuiReporter` out and fall back to `PlainProgress`.
The `ScanReporter` interface is what makes that a one-line change.

---

## 7. CLI surface

New and changed options on `scan`:

```
  -O, --output-file FILE   Write the report to FILE instead of stdout.        [done]
                           --output selects that file's format.
      --progress MODE      auto | plain | none          (default: auto)       [done]
      --color WHEN         auto | always | never        (default: auto)       [done]
      --no-ansi            Alias for --color=never (kept)                     [done]
      --no-interactive     Never take over stdout                             [done]
  -q, --quiet              Suppress progress and the summary                  [done]
      --no-precount        Skip the pre-count; indeterminate progress         [done]
```

Details:

- `-o/--output` is already taken by *format*, so the path option is `-O/--output-file`.
- `--output-file` overrides `actions.report.file` from config; `--output` overrides
  `actions.report.format`. Wire `report.console` at the same time — it is parsed and
  ignored today.
- Refuse (or loudly warn) when the output file is inside a directory being scanned;
  create parent directories; write via temp-file + rename where the format allows it,
  otherwise stream and truncate on open.
- `--quiet` suppresses the progress display and the scan summary. It deliberately does
  *not* alter the report itself — a `--quiet` run still writes its findings, so the
  flag never silently changes what a script receives.
- Exit codes are unchanged: 0 clean, 1 error, 2 matches, 130 interrupted.

---

## 8. Proposed phases

Each phase is independently shippable and independently useful.

### Phase 0 — Stream discipline and safety *(no new dependency)* — **DONE**
- `TerminalCaps` (`infrastructure/TerminalCaps.h`): per-stream `isatty`, `NO_COLOR`,
  `CLICOLOR_FORCE`, `TERM=dumb`, `COLUMNS`, and Windows VT enabling.
- `Terminal` now tracks stdout and stderr independently. Cursor control is gated on the
  target stream being a terminal, so escape sequences can no longer reach a redirected
  file; colour is gated additionally on `--color`.
- Progress and diagnostics moved to stderr (including `Config::printSummary`, the
  cancellation notices and "Halted by user"); the report keeps stdout to itself.
- `PlainProgress` (`infrastructure/PlainProgress.h`): one throttled stderr line,
  carriage-return only and no escape sequences, so it behaves identically with and
  without `--color`. Used whenever the in-place display cannot own stdout — which is
  what makes `lyxbosa scan ... > report.txt` show progress at all. It also gives JSON
  and CSV runs a progress display for the first time.
- Text findings are streamed to stdout in every progress style, so a redirected report
  is written as the scan proceeds rather than all at the end.
- Signal handling (§3.2): the handler now only raises a flag. The first interrupt
  unwinds the scan, writes the partial report and summary, and exits 130; a second one
  hard-exits via `_Exit` after a signal-safe cursor restore. `FileWalker::countFiles`
  polls the flag too, so Ctrl+C during the pre-count is no longer ignored.
- The EOF-implies-yes prompt (§3.3) is fixed, and both `scan` and `check` now refuse to
  prompt when stdin is not a terminal.
- New options: `--color`, `--progress`, `--no-interactive`, `-q/--quiet`.

Deliberately not addressed in phase 0: the UTF-8 truncation bug (§3.5), the retained
clean-file results (§3.4), the JSON escaping bug, and the silent pre-count (§3.7).

### Phase 1 — Output file and streaming report writers — **DONE**
- `ReportWriter` (`infrastructure/report/`) with streaming `Text`, `Json` and `Csv`
  implementations, all writing to a `std::ostream&` so the same code serves the
  terminal and a file.
- `ResultPrinter` is no longer hardwired to stdout: it takes `(ostream, color, width)`,
  which is what lets the text format be reused for a report file without a second
  implementation of it. `printJson`/`printCsv`/`printResults` moved into the writers.
- `-O/--output-file`, wired through `actions.report.{file,format,console}` — three
  configuration keys that were parsed and then ignored by every part of the program.
  With an output file the terminal keeps the readable text view and `--output` selects
  the *file's* format.
- Parent directories are created; the file is opened *before* the scan so an unwritable
  path fails immediately rather than after forty minutes; a warning is issued when the
  report would land inside the tree being scanned.
- Clean files are no longer retained (§3.4). Measured on this tree: 29,022 files
  scanned, **2** `FileResult`s retained, 11.5 MB peak RSS.
- Reports stream as the scan proceeds, so an interrupted run leaves a well-formed
  report. Verified: Ctrl+C mid-scan yields valid JSON carrying `"interrupted": true`
  and the results found so far.
- **JSON escaping fixed** — a path containing `"` or `\` previously produced invalid
  JSON. **CSV quoting added** (RFC 4180) — a path containing a comma previously broke
  the row.
- Skipped-size files now reach the report callback, so they appear in every format
  rather than only in the summary counters.

### Phase 2 — Progress model — **DONE**
- `ScanProgress` extended: `ScanPhase`, live directory count, bytes scanned, the
  running severity breakdown, skipped and quarantined counters, and the discovered
  count from the concurrent pre-count. This is what puts "what is infected, by
  severity" and the directory count on screen.
- `ProgressModel` (`infrastructure/ProgressModel.h`): percentage, EWMA-smoothed
  throughput and ETA, with an injectable clock and no terminal dependency. Covered by
  12 unit tests driving time explicitly — clamping when the count lags the scan, empty
  scans, absent ETA while the total is unknown, and the pre-sample fallback to the
  overall average. Plus `formatDuration` and `formatBytes`.
- **The pre-count now runs on its own thread, concurrently with the scan** (§3.7).
  Scanning starts immediately and the display reads `Scanning 1 of 15360+` until the
  total lands, then switches to `Scanning 25/60548 (0%) 9 dirs ETA 1h 15m`. The
  counting thread publishes only through atomics and the progress callback always runs
  on the scan thread, so no display code has to be thread-safe.
- `--no-precount` keeps progress indeterminate for anyone who would rather not pay for
  the second traversal.
- `CountingCallback` is gone: `ScanPhase` and a zero `totalFiles` carry the same
  information, and displays initialise lazily instead.

### Phase 3 — FTXUI full-screen UI *(the main deliverable)*
- Add `ftxui` to `vcpkg.json`; `LYXBOSA_TUI` CMake option.
- `TuiReporter` on `App::Fullscreen()` + `ftxui::Loop::RunOnce()` pumped from the scan
  loop, so the scan stays on the main thread and no worker thread is needed.
- Capability gate per §6; silent fallback to `PlainProgress` when unmet.
- Status block pinned **below** the findings pane: gauge + percent, `files N/M`,
  `dirs D`, severity chips, throughput, ETA, elapsed, truncated current path.
- Findings pane owns its scrolling (`vscroll_indicator | yframe`), with `TrackMouse()`
  for the wheel, keyboard nav, auto-follow that disengages when the user scrolls up,
  and a jump-to-bottom affordance that reveals itself when it does.
- `p` pauses and resumes the scan, `q` ends it early with a valid partial report.
- **On exit, write the findings and summary into the primary buffer** so nothing is
  lost when the alternate screen is torn down.
- Correct grapheme-aware truncation via FTXUI's cell measurement (fixes §3.5); middle-
  ellipsis for paths reads better than head-ellipsis.
- Delete the hand-rolled cursor dance in `ScanUseCase`.

### Phase 4 — Docs, tests, CI
- README updates (the `--help` reference is already current).
- Golden-output tests for each writer under `--no-ansi --progress=none`.
- A non-TTY regression test asserting **zero** escape bytes on stdout when redirected.
- `ProgressModel` unit tests (percentage edges, ETA, zero-file scans).

---

## 9. Forward-compatibility note

`MODERNIZATION_PLAN.md` lists single-threadedness as an inherited limitation. Design
the reporter seam as if scanning will become parallel: progress counters as atomics,
`ScanReporter` documented as "called from the scan thread, must not block", and findings
handed over by value. Doing this now costs nothing; retrofitting it after a parallel
scanner lands costs a rewrite of the UI layer.

---

## 10. Decisions

1. **Output-file option**: `-O, --output-file`.
2. **Status position**: below the findings, cargo/docker style.
3. **Full-screen UI**: reinstated as the interactive default, because keeping the
   status visible *while the user scrolls the findings* is unachievable in the primary
   buffer. It must detect support and degrade automatically, and must dump the findings
   and summary into the primary buffer on exit.
4. **Pre-count**: runs concurrently with the scan by default, with `--no-precount` to
   skip it. A spinner-only variant was unnecessary once counting stopped blocking.
5. Still open: whether `LYXBOSA_TUI=OFF` should be the default for `docker/` and
   `dist/` (phase 3).

