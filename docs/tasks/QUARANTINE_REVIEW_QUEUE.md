# The quarantine/evidence review queue

Round 12. Generated evidence from `corpus/quarantine-queue.py`; the questions and the
consequences are authored. Nothing here is a verdict — every entry needs
`review.human_confirmed`, which no tool sets.

```
corpus/quarantine-queue.py --inject     # the control, run it first
corpus/quarantine-queue.py --lanes 25   # regenerate the evidence below
```

## State

| | |
|---|---|
| unreviewed rows in `quarantine/evidence` | 23,612 |
| distinct directories | 2,160 (2,222 account-and-directory pairs) |
| distinct containment operations | 177 |
| review lanes | 535 |
| **lanes covering 80% of the rows** | **9** |
| lanes covering 89% of the rows | 19 |

The unit is the **lane**: a containment operation crossed with what the file actually is,
read from magic bytes and structure rather than from its extension. A quarantine directory
is not a directory an attacker chose — it is one an incident responder created, and every
file under it arrived by one command. But one command moved upstream plugin code, customer
photographs and the attacker's dropper together, so the operation alone is too coarse.

Any row the collecting scan flagged is lifted out of its bulk lane into a `FLAGGED-BY-SCAN`
lane and is never closed by a bulk judgement.

## Both mechanical closure paths are exhausted. Measured, not assumed.

| mechanism | candidates | closable |
|---|---|---|
| byte-identical to a file in a pinned benign source (160,698 files hashed) | 23,612 | **0** |
| byte-identical to a file in the stock CMS tree (52,103 distinct hashes) | 23,612 | **0** |
| sha256 already carrying a reviewed verdict elsewhere in either index half | 23,612 | **0** |

Exhaustive over all 23,612 rows against all three sets — no sampling, so there is no power
to state. Round 11 already harvested this mechanism for 32,272 rows; re-running it now
closes nothing. **Every entry below is a human decision.**

## Read this first: two answers set the headline, in opposite directions

Detection stands at **172 / 774 = 22.2%**. Two entries in this queue move it, and the gap
between them is the whole figure:

| if the operator rules … malicious | detection becomes |
|---|---|
| nothing | 172 / 774 = 22.2% |
| **Q-FLAG, the 469 flagged code rows** | **641 / 1,243 = 51.6%** |
| **Q1, the 10,220-row generated text corpus** | **198 / 11,020 = 1.8%** |
| both | 667 / 11,489 = 5.8% |

Both are honest under §8 — detection is *supposed* to fall when a family nothing catches is
reviewed. But Q1 is 10,220 near-identical fragments emitted by one generator in four
minutes, and admitting them as 10,220 independent samples lets one campaign decide a number
that reads as capability. The corpus already met this and built a field for it:
`malicious_known_miss_by_family` exists because 495 of the known misses are a single 2017
campaign. **If Q1 is malicious it should enter as a family with a per-family rate, not as
10,220 samples.** That is the decision to take deliberately rather than discover.

---

## The queue, ordered by rows closed

### Q1 — 10,220 rows · 43.3% · generated doorway text corpus
`live-cleanup-batch3-quarantine-20260828-112000/moved/acct<NN>-imported`, one account,
**one flat directory**, 33.8 MB.

Evidence, exhaustive over all 10,246 files in the directory:

* every file carries the same eleven-tag template skeleton and begins with the same tag;
* **zero** occurrences of any of 26 code tokens — no `<?php`, no `<?`, no `<script`, no
  `eval`, no `base64_decode`, no superglobal;
* **zero** links, images, URLs, iframes, forms, inputs, event handlers, `<meta>` or hex
  entities. The element vocabulary is typographic only: headings, paragraphs, lists, tables;
* sizes 1,965–5,178 bytes; every file valid UTF-8; multilingual;
* **four distinct mtime minutes** across 10,246 files, in two bursts of about two minutes,
  three and a half months apart.

No links means these are not doorway *pages* — a doorway page exists to pass link equity.
They are the body-text corpus a generator injects into a template that supplies the rest.

The identifier gate reports 53 containment hits across 14 identifiers. **None is in a
hostname or path context**; all 53 sit in running prose, which is the collision class
`AGENTS.md` describes and not a leak. It is still 14 identifiers colliding, which is exactly
the population a genuine one would hide in, so publishing this lane needs a masking pass.

> **Q1. Is a directory of inert generated spam body-text malicious material, and if so does
> it enter the corpus as one family or as 10,220 samples?** See the table above before
> answering — this one decision is the difference between a 51.6% and a 1.8% headline.

26 rows are held out of this lane into `FLAGGED-BY-SCAN`; see Q-FP.

### Q2 — 2,637 rows · 11.2% · customer photographs
`acct<NN>-backup-validation-…/extracted/public_html/wp-content/uploads/<year>/<month>`,
10 directories, 173.6 MB. Every file is a JPEG or PNG by magic. Already tagged `content`.

An account's own backup, extracted to validate it. Uploads directories by year and month are
the site's media library.

> **Q2. Ordinary customer media swept in during containment — close as `benign` / `content`?**
> Closing changes no published figure: `content` is never publishable (§4.1), and benign rows
> are not in the detection denominator.

### Q3 — 1,976 rows · 8.4% · plugin PHP from one account's stale backup
`ir-quarantine-20260829/tmp_bak_stale/.backup_temp/acct<NN>/…/plugins`, 458 directories,
19 slugs, one account.

Every file is PHP by structure. 470 rows sit under a slug that has a pinned release, and
**248 of those sit at a path that release also contains** — same file, different version, so
`resolve-benign.py` cannot reach it by hash. The remaining slugs are the premium and
agency-built components `SOURCES.md` records as unpinnable: 32 versions across 27 slugs,
17,667 blobs no pinned source reaches.

Nine rows in this whole operation were flagged by the scan and are held out in `Q-FLAG`.

> **Q3. Is a stale `.backup_temp` copy of one account's own webroot ordinary content?**
> Note the honest limit: what remains in this lane is "material no rule fired on", and a
> lane enumerated that way cannot by itself say the rules were right (§11). The path
> attestation is the independent half, and it reaches 248 of 1,976.

### Q4 — 1,073 rows · 4.6% · analytics reports, and they carry personal data
`ir-quarantine-20260829/…/acct<NN>/cwp_stats/goaccess/{daily,weekly}`, 2 directories,
473.4 MB. Every file is HTML; 939 distinct mtime minutes across 1,073 files — one report
per period, written over about two and a half years.

Exhaustive over all 1,073 files:

* **1,072 contain at least one public IPv4 address**, 161,239 distinct address strings in
  total, plus a hostname in every file. These are visitor addresses — `pii` under §4.1;
* `<script>` and `fromCharCode` appear in all 1,073, because goaccess bundles minified JS;
* `eval(` in 14, `system(` in 5, `base64_decode` in 4. An analytics report of a compromised
  host quotes the attacker's request strings **as data**. That is content about malware, not
  malware.

> **Q4. Benign customer analytics output — close as `benign`, and set `pii` at the same time?**
> The sensitivity tag matters more than the verdict here. These rows are currently
> `sensitivity: ["unreviewed"]`. A pass that closed them `benign` / `clean` would make
> 161,239 visitor addresses publishable.

### Q5 and Q6 — 680 + 680 rows · 5.8% · per-account PHP-FPM pool configs
`ir-quarantine-20260901/open_basedir` and `…/per-account-tmp`, one flat directory each,
0.9 MB combined. Two snapshots of the same set, before and after an IR configuration change.

Every file is an FPM pool config by structure: one `[section]` naming one hosting account,
then `listen`, `user` and `group` lines **repeating that account name seven to twelve times
per file**. The two directories hold 695 rows each; 680 of each classify as pool configs and
30 rows in total are other text. 68 distinct accounts across all 1,390 files.

All 68 names are present in `account-mapping.json` — checked exhaustively, 68 of 68.

> **Q5/Q6. Hosting control-panel output, not site content and not attacker material —
> close as `benign` with `identity` + `path`?** The directory is named `open_basedir`, which
> reads like a hardening artefact worth reviewing; it is not. What makes these worth an
> operator's minute is the opposite risk: 1,390 files whose entire content is customer
> account names, currently carrying no sensitivity tag at all.

### Q7, Q8, Q11, Q13 — 1,796 rows · 7.6% · plugin and theme assets from the same stale backup
Images (647 + 216), JavaScript (627) and stylesheets (306) under
`ir-quarantine-20260829/…/acct<NN>/…/{plugins,themes}`. Same operation as Q3, same argument;
separate lanes only because the content class differs. All image rows already carry `content`.

> **Q7/Q8/Q11/Q13. Follow Q3.** If Q3 closes, these close with it and by a stronger
> attestation — an image is an image by magic, independent of any rule.

### Q9 — 395 rows · 1.7% · plugin PHP from the validated backup
`acct<NN>-backup-validation-…/…/plugins`, 10 slugs. **371 of 395 sit under a slug with a
pinned release and 294 sit at a path that release also has** — the strongest upstream
attestation in the queue.

> **Q9. Follow Q2's operation and Q3's argument, with 294 of 395 paths attested upstream.**

### Q10 — 375 rows · 1.6% · the lane with no attestation
`ir-quarantine-20260829/…/plugins`, content class `text-other` — text that is not source, not
markup and not a recognised data format. Only 4 rows sit at an upstream-attested path.

> **Q10. This is the lane to look at, not to close.** It is the only entry in the top eleven
> whose evidence line reads *no scanner-independent attestation*. Everything else in the
> queue has a second source; this one has the scanner's silence and nothing beside it.

### Q12 — 230 rows · 1.0% · archive containers, across every operation
Zip, gzip and tar by magic, 377.0 MB, 111 directories, 44 accounts. A further 30 containers are
flagged and sit in `Q-FLAG`, for 260 in the bucket.

§2.3 answers this without a judgement: members are the corpus data and the container never
is. **Nine of the 260 already carry the archive-container marker and 251 do not.**

> **Q12. Apply §2.3 to all 260 — one policy application, not 260 decisions.** This is the
> cheapest entry in the queue by rows per minute.

---

## Q-FLAG — 469 rows the scanner already detects
Spread across 55 operations; the largest clusters are 96, 51, 33, 21 and 21 rows.
387 are `critical` severity, 71 `high`, 3 `medium`, 8 `low`. Top rules: `OBF024` ×210,
`OBF037` ×160, `OBF015` ×153, `OBF036` ×143, `OBF025` ×91, `OBF006` ×73, `OBF016` ×70.

445 are PHP by structure — `gzuncompress`+`eval` self-decoders, `goto`-obfuscated payloads, a
base64 `@include` prepended to a core file, file-manager shells, PHP under a media extension
inside a core directory. Six are HTML flagged `SEO005`, five are `.htaccess` flagged `BD017`, and nine are binary.

**These are the only rows in the bucket that can raise detection**, because a row already
detected raises numerator and denominator together. Reviewing all 469 as malicious takes
detection from 22.2% to 51.6%.

> **Q-FLAG. Review individually, not in bulk.** They are already sorted by rule and by
> operation. This is the highest-value entry in the queue and it is nobody's bulk decision.

## Q-FP — 26 rows: the scanner firing on marketing prose
Inside Q1's directory. `PHI008` ×24, `OBF019` ×1, `DEFC001` ×1.

All 24 `PHI008` hits contain the same two-word phrase from casino know-your-customer
boilerplate, in running sentences. There is no form, no input, no link and no code anywhere
in the directory. Five of the 26 also carry `sensitivity_evidence: {"pii": ["form-field"]}`
where the bytes contain no form field — the words appear in prose.

> **Q-FP. Are these 26 false positives, and is the `form-field` evidence on 5 of them wrong?**
> If yes they are `known_fp` material under §8, and the sensitivity evidence is a case of
> exactly what `SOURCES.md` warns about: a gate that trusts a field is only as good as
> whatever wrote the field.

## Q-RISK — 19 rows that carry more risk than the other 23,593 together
`ir-quarantine-20260829/symlink_farm/…` and siblings. Only 19 rows, so it sorts near the
bottom of the queue and should not be answered last.

* **11 of the 19 carry `DB_PASSWORD`, `DB_USER` or WordPress auth keys**, for 11 distinct
  database names — harvested `wp-config.php` copies;
* **83 distinct `/home*/<account>/` names appear inside them**, the densest customer
  identifier material found in this bucket;
* 18 of the 19 are tagged `sensitivity: ["unreviewed"]`; one is `secret`, one is `c2`;
* the scan flags exactly **one** of the 19.

The technique is cross-account credential **read** through a symlink farm. The corpus knows
`cross-account-write` and `credential-harvest`; it does not know this one. Technique coverage
is 90 of 123, and §8 says a coverage number going down is the healthy outcome.

> **Q-RISK. Rule these `malicious`, tag `secret` + `identity` + `pii`, and hold permanently.**
> They are 19 rows whose bytes are eleven other customers' database credentials.

## Q-MISS — 105 rows a responder named hostile and the scanner does not flag
Under directories whose names assert hostility — cloaking evidence, dropper chains, webshell
sweeps, planted `.htaccess`, static payload trees. 216 rows in total: 104 archive containers (Q12) and
13 already flagged (Q-FLAG), 6 of which are both, leaving **105 that are neither**.
79 are text, 25 PHP, 1 binary.

The sample includes static slot-gambling doorway pages under a payload tree and an
`.htaccess` that disables the rewrite engine and adds a `FilesMatch` block.

> **Q-MISS. A human already labelled these attacker output by naming the directory.**
> This is the direct inverse of Q-FLAG and the honest half of §11's warning: Q-FLAG's
> membership was chosen by the scanner, so it cannot contain a counterexample. Q-MISS's was
> chosen by a person, so it can — every row here that reviews as malicious becomes a
> `known_miss`, and detection falls. That fall is the measurement working.
