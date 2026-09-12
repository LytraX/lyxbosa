# LytraX Bot Search

LyxBoSa (LytraX Bot Search) is a malware and webshell scanner for web servers, written in
C++20. Point it at a document root and it reports the files carrying backdoors, webshells,
credential stealers, droppers, SEO spam and obfuscated payloads — the server-side compromises
that turn up in WordPress, Joomla and the rest of a shared host. It reads YAML configuration
and custom rules, writes Text, JSON and CSV reports, and can quarantine what it finds.

```bash
curl -fsSL https://github.com/LytraX/lyxbosa/releases/latest/download/install.sh | sh
lyxbosa scan /var/www/html --recursive
```

## What it detects

Twelve categories of server-side malware, shipped as built-in rules. Any of them can be
enabled or disabled by category or by individual rule code, and custom rules can be defined
alongside them.

| Code | Category | Description |
|------|----------|-------------|
| BD | Backdoor | Hidden admin creation, cron persistence, plugin/theme backdoors, credential harvesting |
| WS | Webshell | Remote shell access and command execution interfaces |
| RCE | Code Execution | Shell commands, eval() injection, dynamic code execution |
| OBF | Obfuscation | Base64 concatenation, variable function calls, goto obfuscation, encoded strings |
| CRED | Credential Theft | Form handlers, POST data exfiltration, login interception |
| PHI | Phishing | Phishing form and page detection |
| DRP | Dropper | Malware download and deployment scripts |
| EXP | Exploit | Vulnerability exploitation payloads |
| SEO | SEO Spam | SEO injection and hidden link spam |
| DEFC | Defacement | Website defacement markers |
| PL | Perl | Perl-based attack scripts |
| ARC | Archive | Site backups and source archives left exposed in the scanned tree |

Each file goes through a layered matching engine rather than a single pattern list:

- **String patterns** — fast literal matching for known malicious signatures.
- **Regex patterns** — powered by Google's RE2 library for safe, linear-time matching.
- **Hex patterns** — binary signature detection for encoded or packed payloads.
- **Entropy analysis** — high-entropy regions that may indicate encrypted or obfuscated content.
- **Hash matching** — known malicious files by their cryptographic fingerprint (xxHash).
- **Heuristic analysis** — variable function calls, base64 concatenation, goto-based obfuscation.
- **Constant folding** — resolves string expressions the way PHP would, so identifiers assembled
  at run time (`$f="ba"; $h="s"; $o=$f.$h."e64_decode";`, `strrev()`, `implode()`, `chr()`
  chains, nested decoders) are detected by what they resolve to rather than by how they were
  split up.

Around that sit context-aware filtering, false-positive reduction that recognises SQL queries
and code comments, and [in-file annotations](docs/SCANNING.md#in-file-annotations) that are
obeyed only when the configuration says the scanned files are trusted.

Archives are not opaque bytes: zip, tar, tar.gz and gz are opened and their members scanned by
the same rules, and a backup of an installed site left under a web root is itself reported as
an exposure. What a scan opens, what it declines to open and how each guard is expressed are
in [docs/SCANNING.md](docs/SCANNING.md).

**Around the matching.** Recursive traversal with a configurable file size limit (25 MB by
default) and symlink control; include and exclude glob patterns; four severity levels —
Critical, High, Medium and Low — for triage; quarantine that can preserve the directory
structure it moved a file out of; email alert notifications; Text, JSON and CSV reports
written incrementally; a full-screen scan UI when the terminal supports it, with an explained
fallback when it does not; and live progress carrying percentage, counts, the severity
breakdown so far, throughput and an ETA.

## Why you can trust a result

A scanner is a claim about files you are not going to read yourself, so the figures here are
built to be checked rather than believed. Every one is stated with its denominator; the
headline ones are generated from the corpus index rather than typed, and a document that
drifts from it fails a check. Detection and the false-positive rate both regenerate from a
clean checkout. **What this version misses is published beside what it catches**, measured per
file, down to the one campaign it misses most prolifically and the rule that would close it.

Two further things a sceptical reader usually asks. The standard and portable Linux builds
detect identically — same rules, same files, same severities, byte for byte over the whole
reviewed corpus. And nothing leaves the host: the only network access anywhere in the tool is
the version check, which is configurable and can be turned off.

[Detection coverage](#detection-coverage) below is the evidence, with the reasoning behind
every denominator.

## Installation

One command per platform.

**Linux**

```bash
curl -fsSL https://github.com/LytraX/lyxbosa/releases/latest/download/install.sh | sh
```

**Windows (PowerShell)**

```powershell
irm https://github.com/LytraX/lyxbosa/releases/latest/download/install.ps1 | iex
```

Both scripts are release assets, so each is covered by the release's `SHA256SUMS` and by the
minisign signature over that list — the same list and the same signature as the binaries. The
script checks every download against it, verifies the signature when minisign is installed,
and says which of the two levels of checking you got rather than implying the stronger one.

Piping a script into a shell runs bytes you have not read, chosen by whoever controls the
release. That is the same trust you extend to the binary, which you are about to run as root
on a compromised host. What it cannot give you is proof that the bytes your shell is
executing are the ones in the signed list; **no script can establish its own integrity.**

On Linux it picks between the four Linux binaries for you, installs to `/usr/local/bin` as
root or `~/.local/bin` otherwise, and refuses any destination `lyxbosa update` would later
decline to write. On Windows it installs to `%LOCALAPPDATA%\Programs\lyxbosa` and adds it to
your user PATH.

**[docs/INSTALL.md](docs/INSTALL.md)** has the rest: how the build is chosen, what each level
of verification does and does not defend against, the options, and the same steps written out
by hand for anyone who would rather not pipe.

## System support

Every release publishes six binaries. Pick by the system you are on; the table says what
each one needs from it.

| you are on | download | what it needs from the host |
|---|---|---|
| a current Linux distribution — Alma/Rocky/RHEL 8 and newer, Debian 10 and newer, Ubuntu 20.04 and newer | `lyxbosa-linux-amd64` or `lyxbosa-linux-arm64` | glibc 2.28 or newer, and a libstdc++ from GCC 6 or newer |
| an older Linux — CentOS 7, Ubuntu 16.04 and 18.04, and the shared hosting built on them | `lyxbosa-linux-amd64-portable` or `lyxbosa-linux-arm64-portable` | nothing; it carries its own C library |
| Windows, 64-bit | `lyxbosa-windows-amd64.exe` or `lyxbosa-windows-arm64.exe` | nothing; the runtime is linked in |

Ubuntu 18.04 is in the second row rather than the first: it ships glibc 2.27, one release
below what the standard build needs.

Each row offers two architectures. `uname -m` says which: `x86_64` means the `amd64`
download, `aarch64` means the `arm64` one.

**To find out which one you already have**, ask it. The version comes first and the build
that produced it follows in parentheses:

```
$ lyxbosa --version
<version> (portable build, lyxbosa-linux-amd64-portable)
```

The version is still the first thing on the line, so a script reading it is unaffected. It is
written as a placeholder here because the build identity is what this example is about, and a
real version printed beside it would be wrong at the next release.

**If you already have an error, it tells you which one you need.** A message like

```
lyxbosa: /lib64/libc.so.6: version `GLIBC_2.28' not found (required by lyxbosa)
```

means this host's system libraries are older than the standard build was made against, and
it will never start here — the version in the message is whichever symbol was missing
first, so it is not always `2.28`. The same goes for a `GLIBCXX_` message, which is the C++
library rather than the C one. In both cases the **portable** build is the answer: it needs
nothing from the host at all. Nothing else needs diagnosing, and there is no configuration
that makes the standard build load on such a host.

**The portable build costs time on a scan, and how much depends on the work.** Three
measurements, each over a different tree:

| what was scanned | portable against standard |
|---|---|
| 53,977 files, almost all of them small | +11% |
| 136 archives, 991 MB in total | +9% |
| a live server: 81,701 files, including 301 MB of archive expansion | +2.5% |

**These are three points and not a range.** They are two machines and three workloads, so
they say what the difference has been on the trees somebody put a stopwatch on — not what it
will be on yours, which may fall outside all three. The first row is container to container,
twice each with the page cache warm: 7.21 s and 7.24 s standard against 8.02 s and 8.00 s
portable. The last row is a real workload on a real host, warm against warm, and it is the
one to plan from if you are sizing a server scan: it is nearly four times smaller than the
small-file figure.

The direction of that spread is what the cause predicts. The difference is not the
allocator — two different allocators land within a hundredth of a second of each other — and
no allocator will close it. What remains is that glibc selects its byte-searching routines
for the instruction set it finds at run time, and the portable build's are plain C. So a
scan whose time goes into short reads over many small files pays most of it, and one whose
time goes into decompressing archives — the same library in both builds — pays least. The
portable build is also about a third larger to download, because the C library is inside it.

**What it does not cost is detection.** The two builds report the same findings, byte for
byte, over the whole reviewed corpus: the same rules, the same files, the same severities,
with every report compared line by line. If the standard build runs on your host, prefer it
for the time; if it does not, you lose nothing but that.

A portable build that finds itself on a host which could have run the standard one says so
after a scan, at most once every 30 days. It repeats rather than saying it once because a
server scan's output scrolls past and the person reading it is often not the person who
installed the binary. It stays quiet on a host that could not — there is no choice to offer
there — and it is silent under `--quiet`, `--silent` and `--force`, when output is
redirected, and in CI. If it cannot establish what the host could run, it says nothing: not
knowing is treated as no.

## Scanning a docroot

```bash
lyxbosa scan /var/www/html --recursive
```

That is the whole of it for an interactive run. It prints what it is about to do, asks you to
confirm, then walks the tree, prints findings as it finds them and prints a summary at the
end. `--force` skips the summary and the prompt, and is what an unattended run needs: without
a terminal on stdin the command refuses rather than guessing. It exits `0` when nothing
matched, `2` when something did, and `1` on an error — so a wrapper script can branch on the
result without reading the text.

Nothing is moved or modified unless you ask. Quarantine is off by default, and an unattended
run that would move files refuses unless `--quarantine` is given explicitly.

```bash
# Unattended: no prompt, machine-readable report in a file, progress still on the terminal
lyxbosa scan /var/www/html --recursive --force -O report.json -o json

# The same with nothing on the terminal at all
lyxbosa scan /var/www/html --recursive --force --silent -O /var/log/lyxbosa.json -o json

# Report only, never touch a file, full match detail
lyxbosa scan /var/www/html --recursive --dry-run --verbose

# One file, and configuration handling
lyxbosa check suspicious.php
lyxbosa init-config > lyxbosa.yaml
lyxbosa validate-config lyxbosa.yaml
```

The report goes to **stdout** and progress goes to **stderr**, so
`lyxbosa scan /var/www > report.txt` shows live progress on the terminal while the report
accumulates in the file — and the file never contains an escape sequence. Reports are written
incrementally, so an interrupted run still leaves a complete, well-formed one; the first
Ctrl+C finishes the report it has and exits `130`, and a second leaves immediately.

There are five subcommands in all: `scan`, `check` for a single file, `validate-config`,
`init-config`, and `update` to replace this binary with the newest release. Every option, exit
code and stream rule is in [docs/CLI.md](docs/CLI.md); `update` is in
[docs/UPDATING.md](docs/UPDATING.md). What the scan opens and what it skips — archives, the
size cap, the skip reasons it counts — is in [docs/SCANNING.md](docs/SCANNING.md).

## What a finding looks like

A WordPress tree with one file dropped into the uploads directory — a handler that runs
whatever arrives in a POST parameter:

```
$ lyxbosa scan /var/www/html --recursive --force
[!] /var/www/html/wp-content/uploads/2026/09/settings.php  C:1

=== Scan Summary ===

Files scanned: 4
Directories parsed: 8
Files with matches: 1

Matches by severity:
  Critical: 1

Scan completed in 0.20 seconds
```

One line per file, and `C:1` is the severity breakdown for that file: one Critical. `--verbose`
replaces it with the matches themselves — the rule that fired, where, and the bytes that
triggered it:

```
$ lyxbosa scan /var/www/html --recursive --force --verbose
[!] /var/www/html/wp-content/uploads/2026/09/settings.php [1 match]
  [CRITICAL] eval base64 decode (6:5) - RCE001
    ($_POST[$k])) {     eval(base64_decode($_POST[$k]));     exit; } 
```

`(6:5)` is line and column; `RCE001` is the rule code, from the categories above. The same
scan with `-o json`, which is what a pipeline reads:

```json
{
  "files": [
    {
      "path": "/var/www/html/wp-content/uploads/2026/09/settings.php",
      "skipped": false,
      "quarantined": false,
      "matches": [
        {
          "rule": "eval base64 decode",
          "severity": "critical",
          "category": "RCE001",
          "line": 6,
          "column": 5
        }
      ]
    }
  ],
  "interrupted": false,
  "totalFilesScanned": 4,
  "totalDirectoriesScanned": 8,
  "filesWithMatches": 1,
  "filesSkippedSize": 0,
  "filesSkipped": {
    "total": 0,
    "size": 0,
    "excluded": 0,
    "unreadable": 0
  },
  "directoriesUnreadable": 0,
  "directoriesCycleSkipped": 0,
  "filesQuarantined": 0,
  "rootsMissing": [],
  "durationMs": 205
}
```

Every file the scan did not open is counted in `filesSkipped` beside the ones it did, because
a file the scanner never read is not a file it found nothing in. The reasons, and the same
accounting for archive members, are in [docs/SCANNING.md](docs/SCANNING.md#skipped-files). CSV
carries the same fields one match per row.

## Detection coverage

Every figure here is stated with its denominator, and the two that matter most — detection
and the false-positive rate — are reproducible from a clean checkout:

```
corpus/fetch-benign.sh     # download and hash-verify the pinned benign corpus
corpus/verify.py           # run the golden suite
```

**The table below is generated** from `corpus/index-summary.json` by
[`corpus/doc-figures.py`](corpus/doc-figures.py), so it cannot drift from the corpus by hand.
`corpus/doc-figures.py --check` fails if it does. The prose around it is written by a person and
survives regeneration.

<!-- BEGIN GENERATED corpus-figures — corpus/doc-figures.py writes this block; edit the tool, not the block -->
| figure | value | denominator |
|---|---|---|
| **Detection** | **56.2%** | 730 of 1,299 reviewed malicious samples |
| **Detection, excluding the rules' own source material** | **94.6%** | 665 of 703 samples |
| Recorded known misses | 558 | 38 of them outside that source material |
| Recorded, but detected: no shard carries the bytes | 3 | 0 outside it; the suite has nothing to run the assertion against |
| Recorded, and not re-measurable here | 8 | 0 outside it; the bytes are not on this machine |
| Largest single known-miss family | 495 | `seo-doorway-madxtube-2017` |
| Samples a stranger can re-run | 131 | ship as bytes carrying a recorded expected rule |
| Technique coverage | 95 of 123 | distinct techniques in the reviewed set |
| Corpus | 92,800 blobs | 46,016 classified, 46,784 unreviewed |
| Of those, the tree the rules were written against | 1,131 blobs | excluded from the second detection figure |
<!-- END GENERATED corpus-figures -->

**Read the two detection figures together, and prefer the second.** The first denominator
includes the tree that the first version of these rules was written against. Measuring a rule
set against its own source material reports how well it memorised that tree, not how well it
generalises, so the in-scope figure is the honest one — and it is a *lower* bound set by the
same reviewing process that produced it, not a ceiling.

The denominator is every reviewed malicious sample, so reviewing a family the scanner misses
lowers this figure and shipping a rule for one raises it. Both directions are intended: it
measures coverage, not progress. **A jump is as likely to be a denominator moving as a rule
landing** — ruling 525 already-detected samples malicious in one pass moved it by 31 points with
no rule changing — which is why the sample count is quoted beside the percentage every time and
the series is never summarised as a trend.

The **numerator** moves the same way, for a second reason that is not detection either. A row
can only assert a rule if a public shard carries its bytes, so a sample the scanner detects and
nothing ships is counted as unasserted. Publishing 29 such samples moved this figure by 2.2
points with no rule changing — the scanner detected all 29 either way, and what changed is that
a stranger can check it. **Read a movement here as a change in what is *provable*** until
[CHANGELOG.md](CHANGELOG.md) says a rule landed.

**A known miss is recorded malware this version does not catch**, verified per file rather
than inferred from a directory scan. The largest family in that count is one 2017 SEO doorway
campaign, and the rule that would close it is deliberately not written — see
[docs/RULE_CANDIDATES.md](docs/RULE_CANDIDATES.md) §4, where it was measured against rendered
documentation and took 494 false positives in 506 at-risk files. The remainder includes a
fake-plugin family whose payloads are named `.png` (§2) and the webshells staged outside the
web root that [docs/KNOWN_ISSUES.md](docs/KNOWN_ISSUES.md) issue 3 rests on.

**Those three rows are one field, and only the first is a miss.** `expect.known_miss` marks a
sample the published suite asserts no rule for, and three different facts put a sample there.
The second row is malware the scanner *does* detect: no shard carries its bytes, so there is
nothing for the suite to run the assertion against, and
[`corpus/promote-pending.py`](corpus/promote-pending.py) refuses to record an expectation it
cannot evaluate. The third row is samples whose bytes are not on this machine, so nothing was
measured about them — counted apart rather than folded into either, because an unreachable
sample is no more evidence of a miss than it is of a catch. Collapsing the three into one number
would report files the scanner finds as files it fails on. The split is measured per file by
[`corpus/classify-known-miss.py`](corpus/classify-known-miss.py), which records on every row
the rules that fired and the binary they fired under, and
[`corpus/verify.py`](corpus/verify.py) prints the same three counts from the same source.

**Samples a stranger can re-run** are the ones whose bytes ship in a public shard *and* whose
expected rule is recorded, so the claim can be checked rather than believed. The rest of the
reviewed set is held locally — most of it carries customer content that cannot be masked —
and its results come from a recorded scan rather than from a run you can repeat. That count is
a regression denominator, not recall, and is never quoted as one.

### Family-weighted detection

Detection above weights every *sample* equally. That figure is dominated by whichever campaign
happened to be collected most heavily, and here one 2017 doorway campaign supplies 495 of the
1,299 reviewed malicious samples — so the headline can move by tens of points because of how
much of one thing was swept up. Family-weighted detection asks the other question: of the
distinct attacker campaigns this corpus has seen, how many does the scanner catch at all?

**The two answers are very different and both are true.** That one missed campaign is 495
missed samples and one missed family. Sample weighting says the scanner misses a great deal;
family weighting says it misses one thing prolifically. A reader needs both to know which,
so both are generated here, from the same rows and the same detection predicate.

**There is a column per sampling frame and no single family rate, deliberately.** A family
rate is a rate over the families somebody happened to label, and the two batches of labelling
this corpus has were selected in opposite ways. Reporting one number across both would average
two biases and name the result after the scanner.

*The family names below and elsewhere in this file are attacker-campaign labels — the names
given to malware families and kits during review. They are not customer or site identifiers,
and no customer identifier appears in this corpus's published index.*

<!-- BEGIN GENERATED family-detection — corpus/doc-figures.py writes this block; edit the tool, not the block -->
| figure | families labelled before this writer | families labelled from the unfamilied pool |
|---|---|---|
| **Sampling frame** | **sampling frame not recorded** | **detection-conditioned — 530 of 531 rows in the pool carry an expected rule** |
| Campaign families | 38 | 7 |
| Rows carrying the label | 707 | 180 |
| Families fully detected | 10 | 7 |
| Families partially detected | 5 | 0 |
| Families completely missed | 23 | 0 |
| Macro average — every family weighted equally | 32.8% | 100.0% |
| Micro average — every sample weighted equally | 19.7% (139 of 707) | 100.0% (180 of 180) |

| figure | value | denominator |
|---|---|---|
| **Sample-weighted detection, whole reviewed set** | **56.2%** | 730 of 1,299 reviewed malicious samples — unchanged by any labelling |
| Reviewed malicious rows carrying no family | 351 | 350 of them detected — outside both columns above |
| Rows under a provenance label rather than a campaign | 61 | `legacy-infected-tree-sample` — membership conditioned on detection, so excluded |
| Technique coverage | 95 of 123 | distinct techniques; 531 reviewed malicious rows carry none |
| Families a stranger can re-run in full | 24 | of 45; 17 have no re-runnable member, holding 712 rows |
<!-- END GENERATED family-detection -->

**Neither column is the headline, and that refusal is deliberate.**
The right-hand families were defined by bytes — a literal shared across their members, re-read
from each sample by the writer that recorded the label — so no rule change could move a single
membership decision. But they were all drawn from one pool, the reviewed malicious rows
carrying no family, and when they were assigned that pool held **530 detected rows out of
531**. Exactly one row in it was undetected, so at most one family drawn from it could ever
have scored below 100%. Their rate was settled before anybody opened a file.

The tempting repair is to exclude them and keep the left-hand column as the real number. That
column is not a clean control either, and in the opposite direction: **most of the rows in it
are rows no rule fires on** — the micro ratio in the table above is the count — because a mass
miss is what gets investigated and labelled, and one 2017 doorway campaign supplies most of
those. Drop that single family and the same micro average rises by tens of points. Promoting it
to *the* family rate would publish a figure that can only ever deliver bad news, which is no
better than one that can only deliver good.

So both columns, each under its own frame, and no number spanning them. A rate across the two
would be a rate over a population nobody drew, and `corpus/doc-figures.py --check` refuses any
document with a generated region that quotes one — including this one, which is why the number
is not printed here. It also refuses a per-frame rate that appears anywhere in such a document
without its own denominator and its own frame beside it.

**What the table is still silent about.** A family figure can only be computed over families
that exist, and a family exists because somebody assigned one. The reviewed malicious rows
carrying no family are counted in the second table above rather than left out of it, and they
are not a random selection — almost every one of them is detected, so they hold most of the
recorded detections while appearing in neither column. That count *falls* as labelling
proceeds, and a falling number here is not the gap closing. A census over all 95 rule-set
clusters and all 531 rows found **428 reachable** by a literal shared distinctively across a cluster and **103 that are not**: 87 in
three clusters whose only cluster-wide literal is carried by roughly a fifth of the pool, 13 in
one cluster sharing no literal at all, and 3 singletons. Those need the sample's decoded
payload rather than its stored bytes. The census is a floor rather than a ceiling — 16 of those
103 have since been labelled by splitting a cluster on a literal only a minority of its members
carry — but **87 rows remain out of reach of this method** and stay counted where they are.

**Macro and micro are both reported because they disagree.** Within the left-hand frame the
macro average weights every family equally and the micro average over the identical rows
weights every sample equally; the table above prints both, and they are far apart. A macro
average that tracked the micro average on every input would not be measuring anything the
micro average does not; the gap is the measurement. In the right-hand frame they agree at
100.0%, which is not two measurements agreeing — it is one pool showing through twice.

**Three states, never two.** A family counts as fully detected only if every member carries an
expected rule and as completely missed only if none does; the five in between are reported as
their own count. Collapsing partial into either neighbour discards exactly which campaigns the
scanner catches most of, which is the information a rule author needs first.

**A contaminated frame is not the same failure as a conditioned membership, and the corpus
records them under separate keys.** In the paragraph below, a sample is in the label *because
the scanner flagged it*: reading the code that assigns it is enough to see the problem, and no
rule change could move the figure. In the right-hand column above, every membership decision
would survive any rule change and the code that assigns them never consults the scanner — it is
the pool they were selected out of that is detection-dense. The first is visible in the
assigning code; the second is invisible there and shows up only when the pool is counted.
`index-summary.json` carries `families_detection_conditioned` for the first and
`families_sampling_frame_conditioned` for the second, and folding them together would discard
the distinction.

**One label is excluded from the family counts, and its rows are not.**
`legacy-infected-tree-sample` groups 61 samples that entered the corpus *because the scanner
flagged them* — the import pass assigns that label under a detection test, and the rows record
it as `reason: detected-and-read`. It would read fully detected however good or bad the rules
were, so counting it as a family inflates coverage by construction and in the flattering
direction. A census over all 39 labelled families found it is the only one: its 61 members
carry 39 different expected rule-sets with no rule shared by all of them, while every other
multi-member family either shares a rule or fires a single set. `make-summary.py` recomputes
that dispersion every run, so a second bucket arriving later is named rather than counted.

**Technique coverage is the same question a third way, and it cannot corroborate the other
two.** It counts techniques with a runnable published sample, and the rows carrying no technique
began as the identical set to the rows carrying no family — two coverage figures blind to the
same rows. Labelling has since moved one and not the other: 180 rows now carry a campaign label
and still no technique. The sets coming apart is a labelling artefact, not the coverage
improving.

**Technique coverage** should be read as a staleness signal rather than as completion: the
denominator is enumerated from what has been reviewed, so it cannot see a technique sitting in
the blobs that have not been. A coverage number going *down* is the healthy outcome of
reviewing something new.

**False-positive rate: 0.0223% — 44 of 197,559 files**, measured with **v2.2.0**. This one
names its build rather than being generated: it is a measurement over a binary and a fetched
tree, not a count the corpus index can produce, so the honest form ties the figure to the
release that produced it. A stale version is visible; a stale number is not.

The benign corpus is 136 sources pinned by version and sha256 in
`corpus/benign/sources.jsonl` — 87 WordPress plugins, 22 themes, 24 core versions and 3 trees
of rendered HTML documentation. Nothing is shipped: the script downloads each one and fails
hard on a hash mismatch, so the corpus regenerates anywhere and yields the same number. All 44
are upstream library code (mostly the Freemius SDK, plus an FPDF class and a handful of plugin
internals), pinned as `known_fp` fixtures — a rule change that fixes one is reported, and a
fixed one that comes back fails the suite. They stay counted inside the 44; pinning a defect
does not remove it from its own total.

That rate rose because the denominator and the numerator grew together: 50 sources were added
in one round, the versions taken from what was actually installed on collected hosts rather
than from what upstream ships today. **A rate that rises when the corpus is honestly extended
is the corpus working.** The previous figure, 8 of 146,712, was measured over a benign tree
that did not contain most of the plugin versions the scanner meets.

**Precision is not reported.** `tp/(tp+fp)` moves with the malicious-to-benign ratio, which is
about 1 in 35,000 on a real host and in any curated corpus is chosen by whoever did the
reviewing. False-positive rate and detection are each computed within a single population, so
neither depends on that ratio. Precision belongs to a field scan, which supplies the real ratio
by construction.

The corpus's construction, the classification rules and the reasoning behind each denominator
are in [docs/tasks/CORPUS_PLAN.md](docs/tasks/CORPUS_PLAN.md); the published shards and what a
consumer may conclude from them are in
[docs/corpus-release-notes.md](docs/corpus-release-notes.md).

## Building

See [docs/BUILDING.md](docs/BUILDING.md). Installing a released binary instead is
[docs/INSTALL.md](docs/INSTALL.md).

## Documentation

| document | what is in it |
|---|---|
| [docs/INSTALL.md](docs/INSTALL.md) | installing a released binary, by script or by hand, and what each level of verification does and does not defend against |
| [docs/SCANNING.md](docs/SCANNING.md) | what a scan covers: archives, skipped files, choosing `scan.max_file_size`, in-file annotations |
| [docs/CLI.md](docs/CLI.md) | every command, option, exit code, stream rule and full-screen UI key |
| [docs/UPDATING.md](docs/UPDATING.md) | `lyxbosa update`: what it verifies and in what order, what it refuses to do, and when a scan checks on its own |
| [docs/BUILDING.md](docs/BUILDING.md) | building from source |
| [docs/RELEASING.md](docs/RELEASING.md) | cutting a release, and rebuilding one to check its bytes against the published list |
| [docs/KNOWN_ISSUES.md](docs/KNOWN_ISSUES.md) | what this version does not catch, and what it would take to |
| [docs/RULE_CANDIDATES.md](docs/RULE_CANDIDATES.md) | rules that were measured and deliberately not written |
| [corpus/SOURCES.md](corpus/SOURCES.md) | the corpus: what the index records, how a sample is masked, what a shard ships |
| [docs/corpus-release-notes.md](docs/corpus-release-notes.md) | the published shards and what a consumer may conclude from them |
| [docs/tasks/CORPUS_PLAN.md](docs/tasks/CORPUS_PLAN.md) | the corpus's construction, the classification rules and the reasoning behind each denominator |

## Changes

[CHANGELOG.md](CHANGELOG.md) — the **scanner**: detection rules, the CLI, report formats and
binary releases, versioned on the `v*` tags. Anything a configuration or a calling script has
to do differently is here. Releasing is [docs/RELEASING.md](docs/RELEASING.md).

[corpus/CHANGELOG.md](corpus/CHANGELOG.md) — the **corpus**: the sample index, the published
shards, masking and publication gates, and the measurement rounds, versioned on the
`corpus-YYYY.MM.N` tags. The two series move on different cadences on purpose — the scanner
versions on rules, the corpus on review rounds — and each file's header says which questions
belong to it.
