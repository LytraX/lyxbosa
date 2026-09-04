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
| 2 | magic bytes disagreeing with the extension, in a media directory | open — evidence recorded, no FP measurement yet |

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

### A collection-scope note, worth keeping with this

The corpus holds the four payload blobs from that directory but **not** the `style.css` and
`screenshot.png` that disguised it — because collection was driven by the scan report, and
those two files matched no rule, so nothing collected them. The payload survives and the
camouflage does not.

That matters for this candidate specifically: the camouflage is exactly what a
placement-based rule keys on, and it is the part the corpus is missing. Rule-driven
collection captures what the rules already find. Anything a new rule would need to see has
to be collected on a different basis — by directory, not by finding.

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

**What it needs before it ships.** A real false-positive measurement, and the FP population
is known in advance and is not small: files with the wrong extension are common and usually
innocent. A `.jpg` that is really a PNG because someone renamed it; `.gif` spacers that are
actually 1×1 PNGs; SVGs named `.png`; WebP served as `.jpg`. The discriminator has to be the
*second* half of the predicate — a long, high-entropy run drawn from the base64 alphabet
where image data should be — not the mismatch alone. Measure against `trail-data/CMS`, the
sanitised site corpus and every pinned tree, and report the number before writing the rule.

**A note on where this came from.** These directories were collected *whole*, with their
siblings, because they sat in a staging tree that was copied wholesale — not because a rule
fired on them. Nothing in them fires a rule. Under the finding-driven collection that §2.3b
of `docs/tasks/CORPUS_PLAN.md` warns about, this entire family would have been invisible:
no rule matched, so nothing would have been collected, so the technique would never have
entered the corpus. This is the first concrete case of that principle paying for itself.
