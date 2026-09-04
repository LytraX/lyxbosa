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
