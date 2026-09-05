# Rule candidates

Detections that the corpus work surfaced with evidence, but that are **not implemented**.
Each needs its own false-positive measurement against `trail-data/CMS`, the site corpus and
the pinned benign trees before it becomes a rule. Recorded here so the evidence is not lost
between the session that found it and the session that acts on it.

A candidate leaves this file in one of two ways: it becomes a rule with an FP number
attached, or it gets a written reason why it cannot. A closed candidate stays here with its
number, because the measurement is the useful part and re-deriving it costs another review.

| # | candidate | status |
|---|---|---|
| 1 | unpinnable plugin/theme slug | **closed** — 18.6% of unpinnable slugs are attacker staging, against a 50% bar |
| 2 | magic bytes disagreeing with the extension, in a media directory | open — FP re-measured 2026-09-05 over 207,311 files: **0**, 11,522 at risk. §2 |
| 3 | one filename in two letter-cases in one directory | open — behaviour confirmed, impact not evidenced |
| 4 | the SEO triple: `title` == `meta[keywords]` == `meta[description]` | open — 495/495 recall, **0 FPs but only 12 files at risk**; unmeasurable here. §4 |
| 5 | a bundled mailer behind a hardcoded password literal | open — 29/29 recall, 0 FPs, 230 at risk. §5 |
| 6 | `mail()` + `$_POST[…]` + a hardcoded address literal | open — reaches 1 file of a 7-file kit, 0 FPs, 175 at risk. §6 |
| 7 | card CVC/CVV reaching a remote-fetch sink in one file | open — 1 FP in 465 at risk; the FP is a form builder. §7 |

Candidates 4–7 come from review round 10, which characterised the five families holding 597
of the 638 known misses. Every FP figure in this file from 2026-09-05 onward is produced by
`corpus/fp-population.py`, which reports the **at-risk** sub-population beside the hit count
so a zero cannot be read as stronger than it is, and which carries a `--inject` positive
control because every headline it produced was a zero.

---

## 1. An unpinnable plugin or theme slug is a lead — **CLOSED 2026-09-04, measured 18.6%**

**Signal.** A directory under `wp-content/plugins/` or `wp-content/themes/` whose slug
corresponds to no known plugin or theme is anomalous **on placement alone**, before anything
about its contents is considered. This is the same placement-and-permissions reasoning that
`KNOWN_ISSUES.md` issue 3 rests on: what makes the file interesting is where it is, not what
it says.

**Why this is newly checkable.** §6 of `docs/tasks/CORPUS_PLAN.md` built a pinned benign
corpus — a lockfile of plugins, themes and core versions with verified hashes — as a
*filter*, to decide samples mechanically. It also, as a by-product, **defines what "known"
means**. Before the lockfile there was no mechanical answer to "is this a real plugin";
there now is, and it is reproducible by anyone who runs `corpus/fetch-benign.sh`.

**Worked example — a fake theme directory.** A randomly named theme directory held four
PHP files, all exactly 14,916 bytes, each a **raw zlib stream** (`78 9c`) rather than PHP —
two of the four byte-identical, so three unique payloads. Live on the host it also held a
copy of a legitimate commercial theme's `style.css` and `screenshot.png`, which is what made
the directory look like a theme to anything glancing at it.

Three separate signals, none of which requires reading the payload:

- the slug matches no known theme;
- the directory contains no theme structure, only same-sized opaque blobs;
- the files are named `.php` but do not begin with PHP.

**Evidence: the slugs this corpus contains that do not pin.** 104 distinct slugs appear in
the corpus; 70 do not appear in the lockfile. Among them, the ones whose names carry no
meaning:

```
plugins/  acajapa  achodaki  acokezha  acitoqy  aqygoqot
plugins/  woo-paypal-stripe-gateway-<7 random chars>
plugins/  cache-manager-<4 random chars>
themes/   <7 mixed-case random chars>          ← the worked example above
```

**Why it is a lead and not a rule.** There are legitimate reasons a slug will not pin, and
they are common:

- **premium plugins and themes** are not on the public directory at all — one such accounts
  for 947 rows in this corpus by itself, and is entirely legitimate;
- **client-specific and agency-built** plugins and child themes, which by definition exist
  nowhere public;
- **renamed directories**, including ones renamed *by* incident response;
- **the lockfile's own coverage**, which is a floor and not a ceiling: a slug missing from it
  may just mean nobody has pinned it yet.

So the raw signal has a false-positive rate that is not merely unmeasured but structurally
tied to how complete the lockfile is. That coupling is the thing to be careful about: the
rule would get *quieter* as the benign corpus grows, which is a strange property for a
detection and needs thinking about before it ships.

**The naming heuristic is the hard part, and I have a measurement of that.** A first attempt
at scoring slugs for "randomness" — length, absence of separators, vowel ratio, mixed case —
flagged four legitimate theme names as random and missed two obviously-generated ones, in a
single pass over 70 slugs. Name-shape scoring is not the reliable half of this candidate.
The reliable half is the set difference against the lockfile; the naming score should be
treated as a ranking aid for a human queue, not as a predicate.

**Suggested shape: an advisory, not a rule.** The coupling above is the deciding argument,
and it points somewhere specific.

Every other detection in this scanner has precision as a property of *the pattern*. This one
would have precision as a property of *the deployment's reference data*: two hosts running
an identical build would reach different verdicts on the same directory, and a user with no
lockfile would get nothing but noise. A severity-bearing finding that behaves that way is
not really a detection — it is a lookup wearing a detection's clothes.

Reframed as a **triage and reporting feature**, the problem dissolves. An advisory list —
*"these 14 plugin/theme directories match no known registry"* — is allowed to depend on
reference data, because that is what an advisory is. It carries no severity, does not enter
the detection counts, and cannot be a false positive in the sense the rest of the suite
means. It says "here is where to look first", which is exactly what it is good for.

Concretely: no rule ID, no severity, no contribution to precision or recall. A separate
report section listing unmatched directories, each with its file count, extension mix, and
whether any file's magic bytes disagree with its extension. Those secondary facts are what
separate a fake theme from a client's bespoke plugin, and they cost nothing once the
directory is already listed.

If it were ever promoted to a severity-bearing rule, **that** is when it needs the full FP
measurement across `trail-data/CMS`, the sanitised site corpus and every pinned tree — and
the coupling would need answering first, not the FP number.

### Kill condition — written before the review, deliberately

The unpinnable slugs are first in the human review queue because they are the highest-signal
part of the backlog. That review **is** this candidate's precision measurement: it will
establish what fraction of unpinnable slugs are genuine attacker staging, as against premium
plugins, agency-built plugins, child themes and directories renamed by incident response.

Recording the decision rule now, while nothing is at stake:

> **If the malicious fraction of unpinnable slugs is low, this candidate is dead, and the
> correct response is to close it — not to narrow it until it survives.**

"Low" here means the advisory would name mostly legitimate directories on a real host. A
sensible bar is **at least half** of unpinnable slugs being genuine staging; below roughly a
third, an operator learns to ignore the list, and an advisory nobody reads protects nothing.

The failure mode to guard against is specific and tempting. Once the data is in hand and the
fraction is disappointing, the instinct is to rescue the idea by adding conditions — restrict
it to slugs matching some name shape, exclude the premium ones, require a second signal, cap
it to directories under a certain file count. Each narrowing looks like a refinement. What it
actually does is fit the predicate to this corpus's particular attacker, and produce something
that will not generalise to the next incident while carrying the authority of a measured rule.

That is also precisely how a lookup ends up wearing a detection's clothes despite the
reframing above: the advisory becomes a rule again by accretion, one reasonable-sounding
condition at a time.

So: if the fraction comes out low, write the number here, mark the candidate closed, and
leave the slug enumeration as what it always was — **a triage aid for a human reading a
queue**, with no claim to precision at all. That is a genuinely useful thing to have, and it
does not need to be a detection to earn its place.

### A collection-scope note, worth keeping with this — **gap closed 2026-09-04**

Until the directory pass, the corpus held the four payload blobs from that directory but
**not** the `style.css` and `screenshot.png` that disguised it, because collection was driven
by the scan report and those two files matched no rule. The payload survived and the camouflage
did not.

That mattered for this candidate specifically: the camouflage is exactly what a placement-based
rule keys on, and it was the part the corpus was missing. Rule-driven collection captures what
the rules already find. Anything a new rule would need to see has to be collected on a different
basis — by directory, not by finding.

A directory-context pass before the host was wiped collected all 13 files. Three of them are
facts no rule would ever have surfaced, and all three are placement facts:

- the disguise is a **byte-exact copy** of a real commercial child theme's `style.css`
  (`Theme Name: FitnessBase`, `Template: consultstreet`) and a genuine 1000×750 PNG screenshot
  — not an imitation, a copy;
- the three legitimate files share an mtime of 2026-07-31, **three weeks older** than every
  payload in the directory (2026-08-28);
- **six of the thirteen files are zero bytes**, two of them under a second naming scheme
  (`ORVX-*.php`) that appears nowhere else.

The lesson survives the fix and is the reason the note stays: the corpus could only produce
those three facts because someone went back for the directory. Had the host been wiped on
schedule, the argument in this section would have stayed permanently unfalsifiable.

### Result — measured 2026-09-04. **The candidate is closed.**

The review is done. All 70 unpinnable slugs were decided by opening the directories and
reading the files, not by scoring the names.

| the directory is | slugs | |
|---|---|---|
| **attacker staging** — no upstream software of that name is in it, contents wholly hostile | **13** | **18.6%** |
| **legitimate** — recognisable upstream, commercial or agency software | 54 | 77.1% |
| **undecidable** — too little of the directory was collected to tell | 3 | 4.3% |

**18.6%**, against a bar of 50% to survive and roughly 33% below which an operator learns to
ignore the list. Even the most generous possible reading — counting all three undecidable
directories as staging — gives **22.9%**, still below the floor. The candidate does not
survive on any reading of its own numbers.

**What the 54 legitimate ones were**, because the shape of the miss matters more than the
count: premium plugins and themes absent from the public directory (Elementor Pro, WPML,
Slider Revolution, WPBakery, The7's core plugin, BeTheme, Bridge, Akeeba); agency-built
framework plugins and their child themes; and vendored library trees — the Freemius SDK and
Redux appear under a dozen different slugs and are the known `OBF025` false-positive family.
Every one of these is exactly the category §1 predicted would not pin. The prediction was
right; what was not known was the proportion, and it is three quarters.

### The fraction is not the real reason this dies. This is.

**Forty-one of the 54 legitimate directories contained a hostile file anyway.** A webshell
dropped into `revslider/`. Another into `pwa-for-wp/`. Another at
`wp-seopress/vendor/psr/log/index.php`. Four into `under-construction-page/themes/`. A
`goto`-obfuscated backdoor at `.pie.tif` inside a commercial theme. An `SC_TH` block appended
to a child theme's `functions.php` in a dozen accounts at once.

Every one of those directories is real, legitimate, vendor-shipped software. Every one of
them would have appeared on the advisory's list — not because of what the attacker did, but
because the slug does not happen to be in a lockfile. And on each of them the advisory's
sentence, *"this directory matches no known registry"*, would have been **true and
irrelevant**: the finding is not that the directory is the attacker's, it is that something
was put inside a directory that is not.

So the predicate fires on two populations that need opposite responses — *replace this
directory, it is not yours* and *this directory is yours, something is hiding in it* — and it
cannot tell them apart, because the thing it looks at is the same in both cases. **That is not
a weak signal that better tuning would sharpen. It is the wrong question.** A signal with a
disappointing precision figure can be improved; a signal that means one thing and fires on two
cannot be, because there is nothing in what it measures to separate them.

The 20% is worth having recorded, and the kill condition was right to demand it before the
data was in. But had the fraction come back at 80%, this finding would still have closed the
candidate — the advisory would have been right about four directories in five and still unable
to say which of the two things it had found. Measuring the fraction was the cheap way to reach
a conclusion that the structure of the predicate already implied.

A list that cannot make that distinction is, in practice, a list of every unpinned plugin on
the host — which on a real shared-hosting account is most of them.

**Not narrowed, deliberately.** The temptation §1's kill condition warned about was real and
specific: the 14 staging directories share visible traits — generated slugs, tiny file
counts, no readme, an extension that disagrees with the magic bytes. Adding any of those as
a condition would lift the fraction above 50% immediately. It would also be fitting the
predicate to this one attacker's tooling, and the next incident's staging directory will
have a plausible slug and a readme. The number stands as measured.

**What survives.** The set difference against the lockfile remains what §1 said it always
was — a triage aid for a human reading a queue. It ordered this review, it put the five
generated-slug directories at the top, and it was worth having. It is not a detection, it is
not an advisory with a severity, and it makes no claim to precision. Nothing further is owed
to it.

The 13 confirmed staging directories became corpus samples: 75 unique blobs, of which 67 ship
in `corpus/shards/malicious-staging-001` and 8 are held. See §2, which is what the review
turned up instead.

### One slug was reclassified after the fact, and the correction is instructive

`plugin-inmymine` was first counted as staging. It is not. The only file collected from it was
`install.php`, a JFIF/PHP "Priv8 Uploader By InMyMine" polyglot, and one hostile file in an
otherwise empty-looking directory reads as staging. The rest of the directory was sitting in a
quarantine tarball that had not been opened, **because §2.3 excludes archives as corpus data**.
Inside it is the wordpress.org plugin *Protect Uploads* by alticreation — `readme.txt`, GPLv2
`LICENSE.txt`, `includes/class-protect-uploads-*.php`, `class Alti_ProtectUploads`, stable tag
0.3 — complete and unmodified, with `install.php` replaced.

So the directory is a **renamed legitimate plugin**, which is one of the four reasons §1 already
listed for a slug failing to pin. The fraction moves from 20.0% to 18.6% and the 40 becomes 41:
the correction makes the candidate's case slightly worse, not better.

The transferable lesson is about §2.3, not about this slug. *Archives are not corpus data* and
*archives are not evidence* are different claims, and only the first is true. A quarantine
tarball is 24 KB of exactly the directory context §2.3b says to collect, and the rule that keeps
its contents out of the corpus should not also keep them out of the review.

---

## 2. A file whose magic bytes disagree with its extension, in a directory of media

**Status:** new, evidence below, **not implemented**. This replaces §1 as the thing the
unpinnable-slug review was actually worth doing for.

**Signal.** A file named `.png`, `.gif` or `.jpg`, sitting in a directory of images, whose
first bytes are not that format's magic — and whose content is a long run of base64-alphabet
characters rather than compressed image data.

**Evidence.** The five generated-slug plugin directories in this corpus contain, between
them, **40 files named `.png` or `.gif` in `assets/images/`. Not one is an image.** Every one
begins with a three-byte ASCII cover prefix — the literal characters `PNG` or `GIF`, not
`\x89PNG` or `GIF89a` — followed immediately by base64 text under a per-directory substituted
alphabet:

```
bamotem.png   67055 B   first bytes: 'PNGl9u...'     (ASCII "PNG", not 89 50 4E 47)
hotuhow.gif  213339 B   first bytes: 'PNGAtq...'     (named .gif, prefixed "PNG")
thijemy.gif  445031 B   first bytes: 'GIFG6d...'
```

The cover prefix does not even agree with the extension in several cases, which is a second
free signal. All 40 decode statically — no execution — to a working toolkit: a file manager,
a WooCommerce billing-and-card skimmer, an obfuscated JavaScript injector, and four
160,000-byte hash tables that are byte-identical across all five directories despite five
different alphabets.

**Measured detection: zero.** All 76 non-empty blobs across the 14 confirmed staging
directories were checked individually with `check`, which reads the file it is given:

```
  scanned and detected                :  10
  scanned and clean (a real miss)     :  66
  the scanner declined to read        :   0
```

Sixty-six real misses, none of them a walker or extension skip. The loader, the payloads and
the disguise are all present and all invisible.

**Why this candidate does not have §1's problem.** §1 was killed by coupling: its precision
was a property of the deployment's reference data, so two hosts running the same build would
disagree. This predicate reads only the file's own bytes — magic against extension, and the
character distribution after the prefix. It needs no lockfile, it behaves identically
everywhere, and it cannot get quieter as a benign corpus grows.

### The false-positive measurement, run 2026-09-04

§2 said the FP population was known in advance and not small. Measured, it is small — but
only for two of the three ways the signal can fire, and separating them is the whole result.

| population | image files | mismatches |
|---|---|---|
| `trail-data/CMS` (stock WordPress, Joomla, Magento) | 837 | **9** |
| `trail-data/CMS-ext` (86 pinned plugins, themes, cores) | 6,464 | **0** |
| `trail-data/Sites/demo-wp` (the sanitised real site) | 3,458 | **0** |
| the corpus's own undetected, unreviewed pool | 7,910 | **1** |

All nine hits in the stock trees are Magento **test fixtures** — `empty.jpg`, `not-a.png`,
`magento_additional_image_error.jpg`, a `logo.gif` under `_files/design/` — several of them
zero bytes, all deliberately-invalid images used as negative test data.

Every one of those nine, and the single corpus hit, comes from the *weakest* of the three
sub-signals: **`image-extension-no-image-magic`**, which fires on any image-named file that
does not start with a recognised image magic — including an empty file. The two sub-signals
that positively identify a disguise fire **zero times** across all 18,669 files:

- **`ascii-PNG-prefix`** — the bytes `PNG` in ASCII, which a real PNG never begins with (it
  begins `\x89PNG`);
- **`raw-zlib-stream`** — a `78 9c` deflate header where an image should be.

So the predicate to take forward is the positive-identification pair, not the mismatch alone,
and the FP number for it on these populations is **0 in 18,669**. The 40 known-malicious fake
images in `malicious-staging-001` all match `ascii-PNG-prefix`.

**A caution about that zero, from getting it wrong first.** The clustering pass that found
this originally reported **213** mismatched GIFs in the undetected pool. Every one was an
ordinary image. The feature tested `b[:3] in (b"PNG", b"GIF")` — and a real GIF *does* begin
with the ASCII bytes `GIF`, because `GIF89a` is its magic. Only PNG has a binary magic; for
GIF the tell is the version field, not the first three bytes. A feature written to support
this candidate was manufacturing evidence for it, and the 213 collapsed to 1 once the test
was corrected. The zero above is the corrected measurement.

**What it still needs before it ships.** A `.jpg` that is really a PNG because someone renamed it; `.gif` spacers that are
actually 1×1 PNGs; SVGs named `.png`; WebP served as `.jpg`. The discriminator has to be the
*second* half of the predicate — a long, high-entropy run drawn from the base64 alphabet
where image data should be — not the mismatch alone. Measure against `trail-data/CMS`, the
sanitised site corpus and every pinned tree, and report the number before writing the rule.

**Re-measured 2026-09-05, round 10, on a denominator eleven times larger.** Running the
corrected positive-identification predicate — ASCII `PNG` where `\x89PNG` belongs, or ASCII
`GIF` whose version field is neither `87a` nor `89a` — over `trail-data/CMS`, `CMS-ext` and
`Sites`, **207,311 files, 11,522 of them at risk** (files that are or claim to be PNG/GIF):

```
false positives   0        95% upper bound on the true rate among at-risk files: 0.026%
recall            40/40    every image-named payload in the five staging directories
```

This is the best-powered candidate in this file: the at-risk population is large and real,
so the zero means something. Two details worth carrying into the rule:

- **The predicate must be content-only.** The forged prefix does *not* track the file's own
  extension — `.png` files carrying a `GIF` prefix and the reverse both occur. Requiring the
  two to agree drops recall from 40/40 to 28/40. The extension is not part of the signal.
- **The naive form is not free.** Plain extension/magic mismatch matches **17** of the 11,522:
  eight JPEGs misnamed `.png`/`.gif`, five empty files, three Exif JPEGs and one PNG named
  `.gif`. All seventeen are ordinary content, and adopting the naive form would roughly
  triple the corpus's whole false-positive count to gain nothing — the positive-identification
  form already reaches all 40 samples.

**A note on where this came from.** These directories were collected *whole*, with their
siblings, because they sat in a staging tree that was copied wholesale — not because a rule
fired on them. Nothing in them fires a rule. Under the finding-driven collection that §2.3b
of `docs/tasks/CORPUS_PLAN.md` warns about, this entire family would have been invisible:
no rule matched, so nothing would have been collected, so the technique would never have
entered the corpus. This is the first concrete case of that principle paying for itself.

---

## 3. One filename, two letter-cases, one directory

**Status:** the behaviour is confirmed; the impact reported for it is **not** evidenced by
this corpus, and the difference matters.

**Signal.** A directory containing two files whose names differ only in case — `about.php`
and `about.PHP` — carrying the same sha256. Cheap to compute, needs no reference data, and
unlike §1 it enumerates nothing.

**What the corpus actually holds.** 176 paths named `about.php` and 47 named `about.PHP`,
223 in all, across one account's quarantined live tree. Forty-seven directories hold both
spellings, and in **all 47 the pair is byte-identical** — that part of the report is exact.
The 47 directories are scattered through the plugin tree, under a `wp-content` the attacker
had renamed with a hex suffix.

**But all 94 paired paths carry one sha256, and it is not a payload.** It is 894 bytes of
HTML: the 404 page of a public paste service, complete with that service's stylesheet links
and the requested path in the body. A dropper fetched a snippet into 47 plugin directories,
twice each; the snippet had already been deleted; what landed 94 times was the error page.
Nothing in the corpus references that host except these 94 identical files, so the payload
was never retrieved at all.

**Why that changes the reading.** The technique was reported as anti-remediation: two
spellings survive a case-insensitive cleanup, so a case-sensitive host keeps a live copy
after remediation looks complete. The mechanism is real and the reasoning is sound — but
*this* evidence does not demonstrate it, because the file that would have survived is inert.
What the corpus does demonstrate is the dropper's **behaviour**: it writes both spellings.
That is worth recording, and it is worth detecting, but the two claims should not be quoted
as one.

The remaining 129 `.php`-only paths are mostly the genuine article — stock WordPress
`about.php`, Yoast's admin page — with a handful of real webshells among them. **Those
webshells are all detected**, measured per sample with `check` on 2026-09-04:

| sha256 | bytes | paths | returns |
|---|---|---|---|
| `46269b88…` | 1,099,089 | 31 | `OBF015`, `OBF016`, `OBF018`, `OBF037` — the `goto` shell |
| `9cc75713…` | 1,102,493 | 4 | the same four — its sibling |
| `7c5eedd7…` | 6,992 | 4 | `OBF007` — the urldecode loader |
| `86fbaae9…` | 5,691 | 2 | `OBF006`, `OBF024`, `OBF025`, `OBF036` — the `gzuncompress` stager |

**"22 distinct blobs, 18 undetected" is a separate claim from the sentence above it, and the
word "payloads" in it was wrong.** Read together they say the four named shells are among the
18 that no rule catches. They are the four that *are* caught. This section had already written
down *the two claims should not be quoted as one* about its own case-collision finding, six
lines earlier, and the next reader quoted these two as one anyway — which is the argument for
putting the measurement in a table rather than in prose.

Of the 18 undetected blobs, **17 are not payloads at all** — none carries a single dangerous
construct, zero markers across all seventeen: 13 are stock WordPress `wp-admin/about.php`,
`user/about.php` and `network/about.php` across versions, six byte-identical to pinned cores
and nine already `verdict: benign` in the index; one is Yoast WPSEO 3.4's contributors page;
one is Codestar Framework's `views/about.php`; one is `e3b0c442…`, the empty file, which
occurs at 3,653 paths host-wide; and one is `c5cee2fb…`, the paste-service 404 already pinned
`must_not_detect`.

**One is real:** `79e638f4…`, 33,111 bytes at 12 `about.php` paths and 65 copies across nine
accounts, a password-gated file manager with a remote-code stage. It is now detected by
`OBF040`, `RCE015` and `WS010`.

**One more fact, which is a caution rather than a candidate.** The 94 files carry mtimes
spread over 2015–2018, on content that is provably from 2026. They are not stomped to match
their siblings — only 2 of 94 match a sibling exactly, none within an hour — so the dropper
set them from somewhere else. Any triage that ranks by mtime places these among the oldest,
most-settled files on the host. **mtime is not evidence of age on a compromised host**, and
nothing in this corpus should be ordered by it.

**The inert file names the payload that never arrived.** The 404 body carries the path the
dropper asked for: `/snippets/g8ofh3h3db/raw/alfapas.php`. So the campaign's intended payload
is identified even though it was never retrieved — and `alfapas` is a plausible reference to
the ALFA TEaM shell family, which would make this a fetch of a known off-the-shelf PHP
webshell rather than of bespoke code. Recorded as a lead, not a finding: the name is
suggestive and the bytes are gone, so nothing here confirms which shell it was. It is the
useful half of a null result — the drop failed, and the corpus still learned what was being
dropped.

**And the artefact is itself a signal of a different kind, which may be worth more than the
case collision.** A file in a plugin directory whose entire content is a paste service's error
page means *a dropper ran here and failed*. That detects a compromise with no payload present
— the class a content-based scanner is structurally blind to, because there is nothing
malicious to match. It has not been measured and is not a candidate yet; the FP population
would be saved error pages in general, which are rare in a plugin tree but not unheard of in
caches and test fixtures. Logged here so the idea is not lost with the artefact.

**What it needs before it ships.** An FP measurement, and the population to measure is not
images but *case-insensitive filename collisions in general*: `README.md`/`readme.md`,
`Makefile`/`makefile`, and vendored trees that legitimately ship both. That measurement has
not been run. Until it is, this is a triage query, not a rule.

**Evidence:** `manifest-incident.jsonl` holds all 223 rows. The artefact itself is published
in `corpus/shards/benign-attacker-artefacts-001` as a `must_not_detect` fixture — an
attacker-written file carrying no attacker-authored executable content is still not malware,
and pinning that is the point. "No code" would be loose: the page does hold `<script src>`
tags, but every one points at the paste service's own stylesheets and bundles. That is exactly
why it earns a fixture — it is the boundary case, and a rule taught to flag it would flag the
service's ordinary 404.

---

# Round 10: the five families that are 597 of the 638 known misses

Written for the agent that will implement rules, not for a reader of results. The five
families were characterised in descending order of size. For each: what is invariant across
**every** sample rather than merely common, which invariants a rule can key on, which are
incidental, and the population against which its false positives have to be measured.

All 605 rows in these six families were resolved to bytes and re-checked **individually**
with `check` — exhaustively, not sampled, so no power statement is needed for the miss
itself. The harness carries a control: two samples the suite records as detected are run
first, and the sweep aborts if they do not come back detected. That control earned its keep
immediately. The first version of the sweep passed all 605 paths to `check` in batches of
40; `check` takes **one** file, so every batch died on an argument-parse error, no batch
printed `No matches found`, and the harness reported **all 605 as detected** — the precise
inverse of the truth, with no error surfaced. It is the §11 inverted-status-check failure
reproduced exactly, and only a control that asserts the other direction catches it.

Result of the corrected exhaustive run: **604 missed, 1 detected**, and the 1 is the single
`woocommerce-card-skimmer` row that is *not* flagged `known_miss`. The index and the scanner
agree row for row.

## The count is not the opportunity: what the 604 actually are

Before any discriminator, the distribution has a property that changes what is worth
building. Classifying every known-miss row in these families by what the file *is*:

| role | rows | share |
|---|---|---|
| static HTML, presentation only | 493 | 81.6% |
| server-side code | 58 | 9.6% |
| encoded payload blob (data, not code) | 40 | 6.6% |
| text/data, translations, C source, native binaries, build artefacts | 13 | 2.2% |

**Only 58 of 604 are server-side code** — the thing a PHP/web rule engine exists to match.
And the row counts overstate the distinct material by a wide margin, in three different ways,
each of which was verified rather than assumed:

- **`seo-doorway-madxtube-2017`: 495 rows → 3 files.** Clustering the pages by tag skeleton
  (all text and attribute values stripped) yields exactly **three** classes, of sizes
  172 / 166 / 157, covering all 495. The three classes partition the family identically to
  the three campaign hosts. 495 rows are one generator's output in three templates.
- **`leaf-php-mailer-2.8`: 29 rows → 2 files.** 28 of the 29 differ **only** in bytes 22–32,
  an eleven-character password literal; normalising `$password = "…"` collapses them to one
  sha256. The 29th is a 98.7%-identical variant. This was flagged in advance and is
  confirmed here by measurement.
- **`phish-kit-verified-by-visa-2012`: 14 rows → 7 files → 1 exfil file.** Every file is
  present twice, once loose and once as a member of an archive in the same tree; the copies
  differ only in line-ending encoding (`\r\n` against a doubled `\r\r\n`), and normalising
  runs of `\r` before `\n` collapses 14 to 7 exactly. Of those 7, exactly **one** carries the
  exfiltration (`$_POST` + `mail()`); the other six are HTML presentation.

So the honest reading of "638 known misses across 27 families" is that the five largest
families contain, between them, on the order of **fifteen distinct pieces of attacker code**.
That is a much better prospect than 597 — it means a handful of rules can close most of the
number — and it is simultaneously a warning that closing the number is not the same as
closing a capability gap. A rule for Leaf moves 29 rows and represents one file.

> This is `known_miss_by_family` doing the job SOURCES.md built it for, one level deeper. A
> per-family rate stops one campaign dominating a figure that reads as capability; a
> per-*distinct-file* rate stops one file dominating a family.

## 4. The SEO triple — 495 rows, and the one to be most careful with

**Signal.** `<title>`, `meta[name=keywords]` and `meta[name=description]` all carry the
**same string**, exactly, case-insensitively.

**Recall: 495/495, no exceptions.** In 491 of the 495 that shared string is also the
filename with hyphens replaced by spaces. That is not a coincidence to be keyed on
separately — the generator, recovered from the same directory, contains
`$key = str_replace("-", " ", $keyfromurl)`, so the filename relation and the meta relation
are the same line of code seen from two ends.

**What is incidental and must not be keyed on:**

- *The campaign hosts.* No single one appears in more than **34.7%** of the family; the
  three partition it into 172 / 166 / 157. A host list is an IOC for one 2017 campaign, it
  covers a third of the family per entry, and it cannot get worse against a benign corpus
  by construction, so its 0% FP rate carries no information.
- *`meta[robots]`* — 66.5%, absent from a third of the family.
- *Absence of `<script>`* — 100% here, but it is a property of these three templates, not of
  doorway pages, and it costs nothing to omit.
- *Extensionlessness* — 490/495 are extensionless, and separately **0 of 728 extensionless
  benign files contain `<html>`**, which is a genuinely well-powered result (95% upper bound
  0.41%). It is worth having as a *triage* query. It is not the discriminator, because it
  keys on a deployment choice rather than on the artefact.

**The false-positive population, and why this candidate cannot be recommended yet.** The
right population for a rule about rendered page content is rendered page content. This
corpus does not contain any. Measured over `trail-data/CMS`, `CMS-ext` and `Sites` —
207,311 files — the triple matches **0**. That number is close to worthless, and
`fp-population.py` is built to say why: only **12 files in 207,311 carry both a keywords and
a description meta tag at all**, so the candidate was offered twelve chances to fail. The
rule-of-three bound on the true rate among at-risk files is **25%**.

Reporting "0 false positives in 207,311 files" here would be the §11 ritual in its purest
form: a denominator four orders of magnitude larger than the set that could ever have
matched.

**What would actually measure it**, and this is the actionable request: a tree of *rendered*
pages — a page-cache plugin's output directory (`wp-content/cache/`), a static-site
generator's output, or any webroot where an SEO plugin has written meta tags into saved
HTML. The failure mode to look for is specific and plausible: a site where the SEO fields
were left to auto-fill from the post title would produce the triple honestly. Until such a
source is pinned in `benign/sources.jsonl`, this candidate has 495/495 recall and **no
measured precision**, and it should not ship on the strength of the zero.

**A cheaper and better target exists in the same directory.** See §8.

## 5. A bundled mailer behind a hardcoded password literal — 29 rows, 2 files

**Signal.** A file that both bundles a mailer library (`PHPMailer`) and contains a
hardcoded `$password = "…"` literal.

**Recall 29/29. FP 0, against 230 at-risk files** (files bundling PHPMailer), 95% upper
bound 1.3%. That is a real measurement: the at-risk population is populated, because
bundling PHPMailer is ordinary plugin behaviour.

**Why the alternatives lose:**

- *The brand string* (`LeafMailer` / `Leaf PHP`, present in 29/29) gives 0 FPs too and is
  trivially cheap. It is rejected as the primary because it is a label: a one-token rename in
  the kit defeats it completely, and this kit is public, reused tooling that gets re-branded.
  Keep it as a cheap confirmatory that names the family in the finding; do not let it be the
  thing that decides.
- *Bundled PHPMailer alone* — **225 FPs in 207,311**, 0.17% of at-risk. 225 false positives
  to reach two files. This is the shape the round was warned about, and it is worth stating
  as a ratio: the discriminator is **more common in ordinary plugin code than in malware**.
  Rejected, and kept in `fp-population.py` as `REJECTED:embedded-phpmailer` so the rejection
  stays reproducible instead of having to be re-derived.

The password-literal conjunct is what turns a library into a gate, and a gate is the
behaviour worth detecting: a mailer nobody but the operator can invoke.

## 6. `mail()` reaching a hardcoded address — the phish kit's one live file

**Signal.** `mail(` **and** `$_POST[…]` **and** a quoted e-mail address literal, in one file.

**Recall 1/7 distinct files — and that is the correct target, not a shortfall.** Six of the
seven files are HTML presentation. The kit deliberately splits the harvest form from the
sender: the file carrying the card and identity field names contains no PHP logic, and the
file that mails contains no form. **No single-file rule can see both halves**, and a rules
agent should not spend effort trying to make one.

**FP 0 against 175 at-risk files** (files calling `mail(`), 95% upper bound 1.7%.

**Why the alternative loses, measured rather than cited.** The form-shaped candidate — a
`<form>` carrying card/CVV/SSN field names — was measured over the same trees:
**18 false positives to reach 1 distinct file**, a 90% false-positive rate, on Magento
checkout templates, a payment form partial, and a consent form definition. The failure is
structural, not a matter of tuning the field list: card field names in a `<form>` are what
e-commerce *is*. Rejected, and retained as `REJECTED:form-with-card-field`.

Dropping the address literal (`mail()` + `$_POST` alone) costs 30 FPs. The literal is what
distinguishes exfiltration to a fixed drop from a contact form mailing the site's own owner.

## 7. Card data reaching a remote-fetch sink — the WooCommerce skimmer

**Signal.** A CVC/CVV field name, a `$_POST`/`$_REQUEST` read, and a remote-fetch sink
(`file_get_contents`, `curl_exec`, `wp_remote_*`, `fsockopen`) in one file.

The skimmer is a convincing fake payment gateway whose `process_payment` builds an array of
card number, expiry, **CVC**, and the full billing and shipping record, then does
`file_get_contents($url . urlencode(json_encode($data)))`. The CVC is the discriminator that
matters: a legitimate gateway tokenises client-side and PCI DSS forbids retaining it, so
server-side CVC in transit is close to definitionally wrong.

**Recall 1/8 rows. FP 1, against 465 at-risk files.** The single false positive is a form
builder that bundles field definitions and HTTP helpers in one large file — a plausible
recurring shape, so expect this rule to need the sink and the source to be in the same
function, not merely the same file.

**Note what the other 7 rows are**: three translation catalogues, a 132-byte build artefact,
a JS bundle and two more classes. They are `known_miss` rows for files that carry no
detectable behaviour and never could. `ddos-flood-toolkit`'s 7 rows are the same story in a
harder form — two stripped ELF binaries, two C source files, a target list, a README and a
shell script, with **no PHP at all**. There is no per-file discriminator over a set whose
members share nothing but a directory, and a rules agent should be told so plainly rather
than left to discover it. Two of those seven additionally carry an IR-quarantine extension
that is not in the scanner's include list, so in a real scan they would never be opened —
that is a walker fact, not a rule gap, and the two must not be counted against a rule.

## 9. A `rename()` that undoes antivirus quarantine — **measured, and the strongest of these**

**Signal.** A `rename()` whose *source* carries a quarantine suffix and whose *target* is an
executable extension:

```php
if (file_exists("../oyptke.php.suspected")) rename("../oyptke.php.suspected", "../oyptke.php");
```

`.suspected` is the suffix cPanel and ImunifyAV append when they quarantine a file. This is
code whose purpose is to reverse an antivirus action. There is no honest reading of it: a
legitimate program has no reason to know that suffix exists, still less to undo it.

**Measured, to the same standard as §4–§7.**

| | value |
|---|---|
| recall | **3 of 3** — every deployer in the campaign directory |
| false positives | **0** across 207,311 files in the three benign trees |
| at-risk population | **343** files containing a `rename()` call |
| 95% upper bound on the true rate | **0.87%** (rule of three over 343) |

**The at-risk figure is what makes this shippable and §4 not.** The SEO triple also scored 0
false positives over the same 207,311 files, but only 12 of them could ever have matched, so
its bound is 25% and the zero says almost nothing. Here 343 files reached the first condition
and none passed the second, which bounds the rate under 1%. Same headline zero, two entirely
different amounts of evidence — and the at-risk column is where the difference lives.

**Why it generalises where §4 does not.** §4 keys on the *output* of one 2017 campaign: 495
rendered HTML pages from 3 templates, all of them presentation. This keys on an
anti-remediation *behaviour*, which is orthogonal to the campaign that happens to carry it.
The same three files also delete and replace `../.htaccess` and delete `../index.php`, so the
deployer's job is to re-establish itself after cleanup — a thing worth catching whoever wrote
it and whatever it re-establishes.

**What it needs before it ships.** The three matching files are currently `verdict:
unreviewed` and cannot become `must_detect` until a human rules on them (§4.1). They are
attacker-authored deployers in a quarantined kit directory, so the verdict is not in doubt,
but the judgement is not a tool's to record.

**Evidence:** `trail-data/Infected/07ef/goren/{old.php,new.php,old.txt}`. Reproduce with
`python3 corpus/fp-population.py --only unquarantine-rename <tree>...`, and run `--inject`
first — the candidate ships with a positive control and the tool fails any candidate that has
none.

## 8. The find: the campaign's executable half is unreviewed and unindexed as a family

The 495 doorway pages sit in one directory. **Nine files in that same directory are not in
the family**, carry `verdict: unreviewed` and **no family at all**, and are undetected. They
are the part of the campaign that actually executes:

- **three copies of the doorway generator**, ~28 KB of readable PHP each, staged with a
  `.txt` extension. Each contains a crawler-user-agent test against four bot tokens with two
  branches — render the spam page for a crawler, `header("Location: …")` to the campaign host
  for a human. That is textbook **SEO cloaking**, it is one of the 33 techniques the suite
  currently lists as having no tested sample, and it is far more generalisable than anything
  keyed on the generator's output.
- **two deployer scripts**, one of which restores a `.htaccess` and renames `*.php.suspected`
  back to `*.php` — undoing an incident responder's quarantine. Anti-remediation behaviour,
  detectable, and not represented anywhere in the corpus.
- one `.htaccess` fragment, and three keyword/template data files.

**Recommendation, and it is the highest-value item in this brief:** review those nine files
and write the rule against the generator and the deployer, not against the 495 pages. One
rule on the cloaking branch would cover the technique wherever it appears; a rule on the
pages covers one 2017 campaign's output and, per §4, cannot currently have its precision
measured at all.

This was not visible from the index, because the index is content-addressed and these nine
files were never grouped with the family they belong to. It was visible from listing the
directory — which is §2.3b's argument for collecting siblings, paying off a second time.

## What this brief deliberately does not do

It recommends no rule for `ddos-flood-toolkit` (§7), and it recommends **against** shipping
candidate 4 on its current measurement (§4). Both are results. A brief that returned five
discriminators for five families, one per family, would be reporting the shape of the request
rather than the shape of the evidence.
