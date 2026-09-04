# Rule candidates

Detections that the corpus work surfaced with evidence, but that are **not implemented**.
Each needs its own false-positive measurement against `trail-data/CMS`, the site corpus and
the pinned benign trees before it becomes a rule. Recorded here so the evidence is not lost
between the session that found it and the session that acts on it.

A candidate leaves this file in one of two ways: it becomes a rule with an FP number
attached, or it gets a written reason why it cannot.

---

## 1. An unpinnable plugin or theme slug is a lead

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

**Suggested shape if it is built.** Not a content rule. A *placement* check that emits a
low-severity informational finding — "plugin/theme directory `X` matches no known slug" —
carrying the directory's file count, the extension mix, and whether any file's magic bytes
disagree with its extension. Those secondary facts are what separate the fake theme above
from a client's bespoke plugin, and they cost nothing to compute once the directory has
already been flagged.

**Measure before shipping:** run it across `trail-data/CMS`, the sanitised site corpus and
every pinned tree, and count how many legitimate directories it names. A check that fires on
a real site's custom child theme on every scan will be switched off, and then it protects
nothing.

### A collection-scope note, worth keeping with this

The corpus holds the four payload blobs from that directory but **not** the `style.css` and
`screenshot.png` that disguised it — because collection was driven by the scan report, and
those two files matched no rule, so nothing collected them. The payload survives and the
camouflage does not.

That matters for this candidate specifically: the camouflage is exactly what a
placement-based rule keys on, and it is the part the corpus is missing. Rule-driven
collection captures what the rules already find. Anything a new rule would need to see has
to be collected on a different basis — by directory, not by finding.
