# Known issues

Defects that are understood, reproduced, and deliberately not fixed yet — with the reason,
so nobody has to rediscover them and nobody "fixes" one without knowing what it costs.

Fixing any of these means removing its entry here and adding a `CHANGELOG.md` line.

---

## 1. Archive member paths are ambiguous — `!` is not escaped

**Where:** `src-lib/cpp/archive/ArchiveScanner.cpp`, `kMemberSeparator`.

A member's reported path is plain concatenation:

```cpp
constexpr std::string_view kMemberSeparator = "!";
const std::string display = ctx.display + std::string(kMemberSeparator) + name;
```

So `backup.zip!wp-content/shell.php` is unambiguous, but two cases are not:

- **Nesting.** A zip inside a zip produces `outer.zip!css/c!s`. A consumer that splits on
  the first or last `!` gets the wrong answer. This is not hypothetical — the 2026-09-03
  collection hit 27 such members (25 zip, 2 tar), where the inner container was a ~1.6 KB
  file literally named `c` sitting in `.../css/` and `.../fonts/`, carrying `OBF015` and
  `OBF037`. A naive single-`!` split drops all 27 **silently**.
- **Filenames containing `!`.** Legal on Linux and inside a zip entry. `a.zip!we!rd.php`
  is indistinguishable from a nested container, and unlike the nesting case there is no
  tell to catch it.

**Impact:** reporting and downstream tooling only. Detection is unaffected — the scanner
never parses these back, it only emits them. The risk is that a consumer of the JSON
silently mis-attributes or drops findings, which is what nearly happened during collection.

**Fix when it is worth doing:** keep `!` for the human-readable `display` string, and add
structured fields to the JSON — `container` plus a `members[]` array — so consumers never
have to parse. Escaping the separator is the cheaper option but leaves the display string
lossy for filenames that legitimately contain the escape character.

**Until then:** any consumer must treat the path as *display only* and reconstruct
membership from the archive itself. Check whether an inner segment is a container rather
than assuming depth 1.

---

## 2. `node_modules/**` and `vendor/**` in the default excludes match nothing

**Where:** `FileWalker::matchesGlob`, and the generated config in
`src-lib/cpp/config/Config.cpp` (which carries a longer warning inline).

`matchesGlob` compares a pattern against the *filename* first, and against the full path
only when the pattern contains `**`, using `fnmatch` with `FNM_PATHNAME` — under which `*`
does not cross a `/`. So `vendor/**` can only match a path that *begins* with `vendor/`,
and every path the walker produces is absolute. Verified directly against `fnmatch(3)`.
Only filename patterns such as `*.min.js` do anything.

**Impact:** the two path excludes shipped in the default configuration are inert.

**Why it is not fixed:** the bug is currently protective. Making the patterns live would
silently stop scanning `vendor/` and `node_modules/`, and on the production host this was
measured against, a large share of the real malware sits under vendored paths — webshells
dropped in `vendor/psr/log/Psr/Log/index.php` among them. Fixing the glob without first
deciding what the defaults *should* exclude would quietly reduce coverage.

**Note for whoever picks this up:** the `excluded` count in the skip tally will not reveal
the problem, because that number is dominated by the include allow-list rejecting file
types rather than by these patterns. On a 1.3 M-file host it read 100,932 while the
exclude patterns contributed nothing.

**Fix when it is worth doing:** decide the intended default excludes first, then make the
matcher do what the patterns say — most simply by matching `**` against the full path
without `FNM_PATHNAME`, or by translating globs to a regex.

---

## 3. A webroot-anchored scan cannot see payloads staged outside the webroot

**Where:** not a code defect — a gap between how the scanner is normally pointed at a host
and where payloads actually live. No single function is wrong.

A pre-wipe sweep of a compromised shared-hosting server, run after the webroot scan had
already been collected and analysed, found two obfuscated PHP webshells in `/var/tmp`:

```
/var/tmp/.<40-hex>   150,076 B  mode 0555  owned by one hosting account
/var/tmp/.<40-hex>   148,746 B  mode 0555  owned by a different hosting account
```

Both begin `<?php class _<id>{private static$...`, both carry the executable bit, both are
hidden dotfiles named as a hex digest, and each is owned by a *different* unprivileged web
account — so they were written by two separately compromised sites into a shared,
world-writable system directory.

**Why the scan could not see them.** The scanner is pointed at webroots, which is where
served content lives and where a webshell has to be to receive an HTTP request. These files
are not served directly. A staging directory outside the webroot is used precisely because
it is not in the scan path: the payload is written there and pulled in at execution time.

**Which execution path — one is now documented, two remain hypotheses.** This originally
listed three candidates with no evidence between them: an `include`/`require`, an
`auto_prepend_file` directive, or a cron entry. The corpus now settles one of them. The
second sample's `placements` field records **five copies under a `recurrent-wp-cron-*`
quarantine directory** — the containment operation isolated it as cron-related material, which
is placement evidence for the cron path specifically. `include`/`require` and
`auto_prepend_file` remain plausible and unevidenced.

That distinction matters more than it looks, and it strengthens the case for the `--profile
host` option below rather than the documentation one. **A cron-triggered payload does not need
to be reachable by HTTP at all.** The usual mental model of a webshell — it must sit in the
served tree so a request can reach it — is what makes a webroot-anchored scan feel sufficient.
It is not sufficient for this sample: nothing about it needs to be servable, so no amount of
scanning the webroot more thoroughly would find it, and the containment evidence says that is
how it actually ran. The detection
content of these files is unremarkable — the same rules that fire on any obfuscated PHP
would have fired here. **Nothing about the rules failed. The walker was never given the
directory.**

**Impact.** Recall measured against a webroot-only scan overstates coverage on exactly the
class of sample that matters most — attacker-staged, outside the served tree, and invisible
to the scan that produced the "clean" verdict. It also means a host can be reported clean
while a live payload sits one `include` away from execution.

**Shape of a fix — not implemented, recorded only. The choice between the two is now
settled.** The cron evidence above decides it: a payload that never needs to be servable is
not reachable by scanning the served tree more carefully, however well the documentation
explains where to look. Option 1 tells an operator to go and look somewhere; option 2 looks.
For this class of sample only the second one can work, so it is the design conclusion rather
than the preference it was when both were guesses.

1. **Documentation.** State plainly that a webroot scan is not a host scan, and give the
   directories worth adding: `/tmp`, `/var/tmp`, `/dev/shm`, per-account home directories
   outside the served tree (including `~/tmp`, `~/.cache` and dot-directories), and the
   system cron and systemd unit paths.
2. **A scan profile that does it by default — the chosen shape.** A `--profile host` (as
   against the implicit `webroot`) that walks those locations as well, with the ownership
   signal made explicit:
   a file in a shared temp directory owned by an unprivileged *web* account, carrying the
   executable bit, with a name that is a hex digest and no extension, is worth surfacing
   on placement alone — the same placement-and-permissions reasoning that several existing
   rules already encode.

Either way the cost is real: `/tmp` on a busy host is large and churns, so this wants its
own include/exclude defaults rather than inheriting the webroot ones. That is the reason it
is recorded here rather than fixed in passing.

**Until then:** do not describe a webroot scan's result as a host being clean, and when a
host is known-compromised, sweep the staging directories by hand.

**The two samples are now in the corpus, and they are measured misses.** Both ship in
`corpus/shards/malicious-outside-webroot-001`, masked and gated, carrying
`expect.known_miss` — checked per sample with `check`, which reads the file it is given, so
this is a rule gap and not a walker skip. Reading them settles what the sweep could only
suggest: each is a wrapper that rewrites a plugin *inside* the webroot (`$TR`) while keeping
three state files *outside* it, in the owning account's `~/tmp`, named with the same hex
digest and an incrementing final character. The two are polymorphic siblings — identical
structure, different identifiers — in two different accounts.

Their index rows also carry a `placements` count, which is new and exists because of them.
The index is content-addressed and had kept one example path per blob; these two blobs have
16 and 14 paths, and the one path each row showed was an IR quarantine copy. The placement
that motivates this whole issue — `/var/tmp`, plus `~/.cache`, `~/tmp` and, for the second
sample, five copies under a `recurrent-wp-cron-*` quarantine — was invisible in the index
while being the entire finding. A corpus that flattens placement cannot support a
placement-based rule, which is the same failure `docs/tasks/CORPUS_PLAN.md` §2.3b describes
for sibling files, arriving through deduplication rather than through collection.

---

## 4. `OBF021` counts sibling dynamic calls, not nested ones

**Where:** the `OBF021` rule, "Double variable function call".

The rule fires on two *sibling* dynamic calls — two separate `$var(...)` call expressions —
and does **not** fire when the dynamic calls are *nested*, one passed as the argument of the
other. Nesting is the cheaper construct to write and the one the samples actually use.

Minimal reproductions, all with randomised identifiers:

```php
<?php $a($x); $b($y);              // two sibling calls, one line   -> OBF021
<?php $a($x);
      $b($y);                      // two sibling calls, two lines  -> OBF021
<?php $z = $a($b($c));             // two NESTED calls              -> no match
<?php eval($a($b($c)));            // two NESTED calls              -> no match
<?php eval($a($b($c)));
      $w = $m($n($o));             // FOUR calls, all nested        -> no match
```

The last one is the point: four dynamic calls in the file, and nothing fires, because they
are arranged as two nested pairs rather than as siblings.

**Position is not the trigger.** An earlier reading of this — that the rule keyed on the
call sitting in `return` position — was wrong, and bisection disproved it. With two sibling
calls present, the rule matches in `return`, bare-statement, assignment *and*
`eval(...)`-argument positions alike. With one call, or with only nested calls, it matches
in none of them. The predicate is the count of sibling dynamic calls.

**Renaming was ruled out, deliberately.** Every reproduction above uses random identifiers,
and the matching and non-matching cases use *equally* random ones. This matters because the
two real samples that motivated the investigation are polymorphic siblings — identical
structure, different variable names — and the obvious hypothesis was that the renaming beat
the rule. It did not. The construct did.

**Measured impact.** Two of the samples in the corpus are undetected because of this: a pair
of polyglots whose payload ends in `eval($a($b($c)));` after a several-kilobyte base64
blob. A third sample carrying six dynamic calls arranged as siblings *is* detected by
`OBF021`. Same family of technique, opposite outcome, and the difference is only nesting.

**Why this is recorded rather than fixed.** Making `OBF021` count nested calls is a
one-line change to the predicate and an unknown change to the false-positive rate. Dynamic
call nesting appears in legitimate code — dependency-injection containers, `array_map` with
callable variables, and several template engines all do `$factory($resolver($id))`. Changing
it needs its own false-positive measurement against `trail-data/CMS`, the real-site corpus,
and the live sample corpus, and that is rule work with its own evidence, not a change to be
made while cataloguing samples.

**Until then:** the affected samples carry `expect.known_miss` in the corpus index with the
reason recorded, so the gap is measured rather than assumed. A golden-suite run should
report them as expected misses, not as failures — see the note on `known_miss` in §8 of
`docs/tasks/CORPUS_PLAN.md`.
