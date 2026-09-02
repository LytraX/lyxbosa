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

## 6. Recommendation

**Do not replace RE2.** It stays the matcher of record: it produces the offsets and
text that findings need, its linear-time guarantee is a security property when the
input is attacker-chosen malware, and it is the only one of the three that builds
everywhere.

**Hyperscan is worth adopting as an optional prefilter**, behind a build flag, with
the current path as the fallback. The evidence: 163/163 compatible, exact agreement
on 14,288 files, and 32–50× on the dominant cost.

Costs to weigh before committing:

- **Portability is the real obstacle.** vcpkg marks `hyperscan` as `!arm` and
  `vectorscan` as `!(x64 | x86)` — they are complementary forks, so covering the
  `linux-amd64` and `linux-arm64` targets in `dist/` means shipping *both*, plus RE2
  as the fallback for anything else.
- **Build weight.** 88 transitive ports, mostly Boost.
- **Startup.** 264 ms to compile the database. Irrelevant for a 100 s scan, but
  material for `lyxbosa check` on one file. `hs_serialize_database()` can ship it
  prebuilt.
- **Prefilter only.** Start-of-match needs `HS_FLAG_SOM_LEFTMOST`, which is expensive
  and bounded; the follow-up RE2 pass is what supplies positions and text.

Suggested sequence:

1. Land the prefilter interface with RE2::Set as the default implementation — no new
   dependency, and it already pays for itself on clean trees.
2. Add Hyperscan behind `LYXBOSA_HYPERSCAN`, selected at build time per platform.
3. Gate both in CI with `--agree`; a prefilter that under-reports is a silent
   detection failure, which is exactly the class of bug the rule audit just found.
4. Revisit the analyzers afterwards — they are next.
