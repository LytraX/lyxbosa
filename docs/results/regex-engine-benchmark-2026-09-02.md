# Regex engine benchmark — RE2 vs RE2::Set vs Hyperscan

**Date:** 2026-09-02
**Harness:** `benchmarks/regex_engines.cpp` — `cmake -B build -DLYXBOSA_BENCHMARKS=ON`
**Rule set:** the live registry, 163 patterns across 122 builtin rules
**Machine:** x86-64, AVX2 + AVX-512, Release build

Run it yourself:

```
./build/lyxbosa_bench_regex <corpus-dir> [cap-MB]      # timings
./build/lyxbosa_bench_regex <corpus-dir> [cap-MB] --agree   # correctness gate
```

---

## 1. Why this is not a pattern-for-pattern comparison

`MatchEngine` runs **one RE2 pass per pattern over every file** — 163 passes per file.
`RE2::Set` and Hyperscan compile every pattern into a single automaton and answer
"which of these match?" in one pass. That difference is the entire reason to look at
them, so each engine is measured the way it would actually be used.

Neither multi-pattern engine can replace RE2 outright. Both report *which* pattern
matched and where it *ended*; findings need the start offset and the matched text.
So the shape under evaluation is a **prefilter**: one fast pass to decide which rules
are worth running, then the existing RE2 only for those.

That shape is worth it because almost nothing matches:

| corpus | files | files with any match |
|---|---:|---:|
| stock CMS | 51,294 | 0 |
| real production site | 22,416 | 4 (0.02%) |
| malware bulk sweep | 3,835 | 57 (1.5%) |

**98.5–100% of scan time is spent proving that nothing matches.**

---

## 2. Compatibility

| Engine | Patterns accepted |
|---|---|
| RE2 | **163 / 163** |
| RE2::Set | **163 / 163** |
| Hyperscan | **163 / 163** |

Hyperscan documents no support for backreferences, lookarounds, atomic groups,
possessive quantifiers, conditionals or `\K`. The rule set contains **none of them** —
a side effect of the earlier rule audit, which removed the possessive quantifiers and
backreferences that had silently prevented 20 rules from compiling under RE2 at all.

Two details that decide whether it works:

- **Inline `(?i:…)`** — 89 patterns use it after the case-insensitivity fix. Hyperscan
  accepts it.
- **`\x{3040}`-style ranges above `0xFF`** (the Japanese-keyword rule) need
  `HS_FLAG_UTF8`. Applying that flag **globally** costs dearly:

  | | compile | database | accepted |
  |---|---:|---:|---:|
  | no UTF-8 | 0.26 s | 442 KB | 162 / 163 |
  | UTF-8 on everything | 4.38 s | 1196 KB | 163 / 163 |
  | **UTF-8 only where needed** | **0.26 s** | **442 KB** | **163 / 163** |

  Hyperscan takes flags per expression, so only the one rule that needs it should pay.

---

## 3. Correctness

A prefilter that over-reports is free — the follow-up RE2 pass discards it. A
prefilter that under-reports is **missed malware**. Gate: for every file, the set of
patterns Hyperscan reports must be a superset of what RE2 finds.

| corpus | files | exact agreement | under-reported |
|---|---:|---:|---:|
| stock CMS | 8,034 | 8,034 | **0** |
| real production site | 2,937 | 2,937 | **0** |
| malware corpus | 3,317 | 3,317 | **0** |

Not merely a superset — **exact agreement on all 14,288 files**, zero over-reporting
too. `--agree` exits non-zero on any under-report, so it can gate CI.

---

## 4. Throughput

**A** is the current engine. **B** and **C** are the prefilter pass alone.

| corpus | A: RE2 per pattern | B: RE2::Set | C: Hyperscan | A→B | A→C |
|---|---|---|---|---:|---:|
| stock CMS, 128 MB | 13.33 s · 9.6 MB/s | 0.53 s · 244 MB/s | **0.27 s · 481 MB/s** | 25.4× | **50.1×** |
| production site, 96 MB | 9.76 s · 9.8 MB/s | 5.08 s · 18.9 MB/s | **0.20 s · 491 MB/s** | 1.9× | **49.9×** |
| malware, 89 MB | 9.38 s · 9.5 MB/s | 8.07 s · 11.1 MB/s | **0.29 s · 309 MB/s** | 1.2× | **32.5×** |

One-time compile: RE2 singles 8 ms, RE2::Set 12 ms, Hyperscan 264 ms (442 KB database).

### RE2::Set is not the free win it first appears to be

On stock CMS it looks excellent — 25×. On a real site it drops to **1.9×** and on
malware to **1.2×**. RE2's DFA has a memory budget; one automaton holding all 163
patterns thrashes it on varied or adversarial content and falls back to the much
slower NFA path. It is fast exactly where a scanner needs it least.

Hyperscan holds **309–491 MB/s across all three**, including malware.

---

## 5. What this is worth end to end

Regex matching is not all of a scan. Measured on stock CMS (51,294 files, 344 MB) by
selectively enabling rules:

| configuration | time | attributable |
|---|---:|---|
| walk + read + framework + 1 pattern | 3.7 s | I/O floor, 3% |
| \+ the 5 C++ analyzer rules | 17.3 s | analyzers ≈ 13.6 s, 12% |
| \+ all 163 regex patterns | 112.5 s | **regex ≈ 95 s, 85%** |

So a 50× cut in the regex portion takes a 112 s scan to roughly **19 s — about 6×
end to end**. After that the analyzers (`StringAssembly` in particular) become the
next bottleneck at ~70% of what remains.

---

## 6. A third option that needs no second engine

Hyperscan's advantage is not really the automaton — it is that **it stops looking
early**. Any pattern can be skipped outright when a string it *must* contain is
absent from the file. That check needs no new engine and no new dependency.

For each pattern, extract the literal runs that every match must contain. A run
qualifies only when nothing can make it optional: not inside an alternation, not
inside a `?`/`*` group, not the character before a quantifier. **82% of patterns
(134/163) yield one**, e.g. `RCE001` requires `eval` and `base64_decode`; `BD004`
requires `file_get_contents` and `wp-config`.

Then one pass over the file finds which of the 136 distinct literals are present,
and only patterns whose literals are all present are run.

| corpus | A: today | literal prefilter | patterns run per file | speedup |
|---|---|---|---:|---:|
| stock CMS, 128 MB | 13.36 s | **4.63 s** | 31.0 | **2.9×** |
| production site, 96 MB | 9.82 s | **3.82 s** | 31.8 | **2.6×** |
| malware, 89 MB | 9.43 s | **3.89 s** | 35.0 | **2.4×** |

Results are **identical**, and the prototype verifies it: it re-checks every pattern
that matched and asserts its literal really was present. Zero unsound extractions
across all three corpora.

### The 29 patterns without a literal are the bottleneck

31 patterns run per file, and 29 of them are the ones no literal could be extracted
from — because their required text sits in an alternation
(`(shell_exec|system|passthru|exec|popen)`) or is shorter than the four-character
floor. Extracting literal *sets* — "any of these five" — is the obvious next step and
is just as sound.

Measured ceiling with every pattern gated (unsound shortcut, upper bound only):

| corpus | patterns run per file | time | speedup |
|---|---:|---|---:|
| stock CMS | 2.0 | 0.75 s | **17.9×** |
| production site | 2.8 | 0.88 s | **11.2×** |
| malware | 6.0 | 1.14 s | **8.2×** |

So a complete literal prefilter lands at **8–18×**, against Hyperscan's 33–50×.

---

## 7. Recommendation

**Build the literal prefilter. Do not adopt a second engine.**

| | speedup | engines | correctness | dependency | platforms |
|---|---:|---|---|---|---|
| RE2::Set prefilter | 1.2–25× | 1 | identical | none | all |
| **Literal prefilter** | **8–18×** (2.4–2.9× today) | **1** | **provable** | **none** | **all** |
| Hyperscan prefilter | 33–50× | 2 | verified empirically | 88 ports | x86 only |

Three reasons the literal prefilter wins despite being slower on paper:

1. **Its correctness is provable, not measured.** A pattern that requires the literal
   `base64_decode` cannot match a file that does not contain it — that is a property
   of the pattern, checkable per rule, not a claim about two engines agreeing on the
   corpora we happened to test. For a scanner, "provably cannot miss" beats "did not
   miss on 14,288 files".
2. **One engine means one result everywhere.** Hyperscan is `!arm` and vectorscan is
   `!(x64 | x86)`; shipping both to cover the `linux-amd64` and `linux-arm64` targets
   means the same file could in principle be classified differently depending on the
   platform that scanned it. For a security tool that is a defect, not a trade-off,
   and no benchmark number justifies it.
3. **It is not a second pass over the file.** The file is read once. What changes is
   how much *pattern* work runs on the buffer: 163 passes today, 31 with partial
   gating, 2–6 with complete gating. It cannot be slower than the status quo — the
   prefilter replaces work rather than adding to it.

RE2 stays the matcher of record either way: it produces the offsets and matched text
findings need, and its linear-time guarantee is a security property when the input is
attacker-chosen.

### Sequence

1. Declare the required literals **next to each rule**, hand-written and reviewed,
   rather than parsed out of the pattern. The prototype's generator derived them by
   parsing regexes and the first version silently paired every literal with the wrong
   rule; explicit declaration is auditable and cannot drift.
2. Add a test that asserts soundness for every rule: if the rule matches a string,
   the string must contain the rule's declared literals. That is a property test, and
   it makes the optimisation safe to extend.
3. Extract literal sets for alternations to close the remaining 29 patterns.
4. Revisit the analyzers — at ~12% of scan time today, they become the next
   bottleneck once regex drops to a fifth of its current cost.

Hyperscan stays in the benchmark as a reference point. If throughput ever becomes the
binding constraint on one platform, the numbers are here — but the portability and
determinism cost should be paid deliberately, not for a benchmark win.

### Note on the benchmark's `--agree` flag

`--agree` is a mode of `lyxbosa_bench_regex`, the benchmark binary. It is not, and was
not proposed as, an option on `lyxbosa` itself. No engine selection or prefilter
tuning should ever reach the CLI: the scanner has one behaviour, and the prefilter is
an internal optimisation that is invisible precisely because it cannot change results.
