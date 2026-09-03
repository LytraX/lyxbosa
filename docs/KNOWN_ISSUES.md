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
