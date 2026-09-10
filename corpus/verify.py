#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""§8 — the golden suite.

One command, machine-readable output, every past mistake permanent.

Three things this deliberately does differently from a naive suite:

  * **It does not report precision at all**, and that is a decision rather than a gap. See the
    long comment at the point where a naive suite would compute it.

  * **Detection and regression are separate lines.** Detection is over every reviewed
    malicious sample; regression is over the ones already known to be detected, and only that
    second one can be 100% by construction. Conflating them under the name "recall" is what
    used to put a tautology in the headline.

  * It reports detection and the false-positive rate **over the reviewed set**, and prints the
    held count beside them. A figure computed over a corpus that is mostly unreviewed, without
    saying so, is the difference between "convincing empirical evidence" and a number someone
    can check. `index-summary.json` is the denominator so the suite can state what it is *not*
    testing.

  * It reports **technique coverage**, which is the milestone that replaced "review N samples".
    The question worth answering is not "what percentage" but "does it catch the things we have
    seen", and that does not move when the benign corpus grows.

  * `known_miss` samples get their own column and never count as failures. A known miss that
    is still missed is the expected result; one that starts being detected is a *result*
    worth surfacing, not a broken test. Only a detected-then-missed sample is red.

    That marker covers **three** states and the column prints them apart, because only one of
    them is a miss: `rule-gap` is bytes read with no rule firing; `detected-not-shippable` is
    bytes read, rules firing, and no shard carrying them, so the suite has nothing to run the
    assertion against; `unverified` is bytes that are not on this machine. The line used to
    print the union under the word "misses" and reported 32 rows the scanner detects as rows
    it does not. The counts are read from `index-summary.json` so this line and the README
    cannot disagree - which they did, until `doc-figures.py` compared them.

  * **The false-positive figure is refused, not reported, when the scan did not cover the
    trees it was asked to cover.** The denominator used to be `totalFilesScanned` as the
    scanner counted it, and the scanner counts a file it could not open. So a file the host
    withheld sat in the denominator and, having no matches, was counted as clean - the suite
    asserting a file was clean without a byte of it read, which is the exact silent skip the
    scanner itself refuses to make. On Linux that was a handful of files; on Windows, where
    Defender quarantines samples during the scan, the withheld set is chosen by Defender and
    moves between runs. `coverage_refusal()` is the rule and says which channels refuse and
    which only disclose. CORPUS_PLAN section 11 lists this as the fourteenth instance of a
    denominator produced by the process it was meant to bound - in the tool that measures
    the other thirteen.

  * **A sample the scanner could not read is an error, never a verdict.** `check` exits 1 for
    it, and this suite used to read only the rule list off stdout, so an unreadable sample
    was an empty list: a miss on a `must_detect` row (red, wrong reason), *still missed* on a
    `known_miss` row (green, wrong), clean on a `must_not_detect` row (green, wrong), and
    *newly fixed* on a known false positive (a result, wrong). Now `classify_check()` reads
    the exit code first and an error is counted under `unscanned` and listed as a failure.

Usage:
  corpus/verify.py [--json] [--baseline FILE] [--update-baseline] [--skip-benign]
  corpus/verify.py --inject      controls, both directions; see inject()
"""
import json, os, re, sys, subprocess, argparse, collections, hashlib, tempfile, shutil

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
# The binary under test. Overridable, and that is the point: hardcoding it is what
# made two agents working this tree at once need a third build directory. If the
# suite can only ever read build-release, then anyone measuring a rule change has to
# rebuild the same binary the suite is reading, and a rebuild mid-run leaves the
# per-sample `check` calls straddling two binaries with nothing reporting an error.
# Point LYXBOSA_BIN at your own build instead.
SCANNER = os.environ.get("LYXBOSA_BIN") or os.path.join(ROOT, "build-release", "lyxbosa")

def control_scanner():
    """The binary `--inject` runs its end-to-end cases against.

    A control is not a measurement, and the two want different defaults. A published
    figure has to come from `build-release/` so that what is quoted is what was measured,
    and AGENTS.md forbids rebuilding that one mid-round for exactly that reason - so it
    is routinely older than the source, and a control that insisted on it would report
    the age of a build as a failure of the round being checked. A control only has to run
    against a scanner that can answer, and the freshest one on hand is `build/`.

    An explicit LYXBOSA_BIN still wins: naming a binary means that binary.
    """
    if os.environ.get("LYXBOSA_BIN"):
        return SCANNER
    dev = os.path.join(ROOT, "build", "lyxbosa")
    return dev if os.path.exists(dev) else SCANNER

def die(msg, code=2):
    print("error: %s" % msg, file=sys.stderr); sys.exit(code)

def classify_check(returncode, stdout, stderr=b""):
    """What one `check` run established, from its exit code first.

    `check` answers with three codes and they are three different facts: 0 is bytes read and
    nothing fired, 2 is bytes read and something fired, and 1 is that nothing was established
    - the file is missing, or the host would not let it be opened, or the configuration did
    not load. Reading the rule list off stdout alone collapses the third into the first,
    because an error prints no rules and no rules looks like clean.

    Returns {"outcome": "detected" | "clean" | "error", "rules": [...], "exit": rc,
    "said": <the first line the scanner printed>}.
    """
    rules = sorted(set(x.decode() for x in re.findall(rb"- ([A-Z]+\d+)", stdout)))
    text = (stdout or b"") + (stderr or b"")
    said = next((l.strip() for l in text.decode("utf-8", "replace").split("\n") if l.strip()), "")
    if returncode == 2:
        return {"outcome": "detected", "rules": rules, "exit": returncode, "said": said}
    if returncode == 0:
        return {"outcome": "clean", "rules": [], "exit": returncode, "said": said}
    return {"outcome": "error", "rules": [], "exit": returncode, "said": said}

def check_sample(path):
    """Per-sample check. Never a batch scan: a batch cannot distinguish 'not scanned'
    from 'scanned and clean' (CORPUS_PLAN §5.6, §8)."""
    r = subprocess.run([SCANNER, "check", "--no-ansi", path], capture_output=True)
    return classify_check(r.returncode, r.stdout, r.stderr)

def unscanned_failure(sample, chk, what="sample"):
    return {"sample": sample, "why": "%s could not be scanned (check exited %d): %s"
            % (what, chk["exit"], chk["said"][:120] or "no output")}

# --------------------------------------------------------------- benign coverage

# The refusal rule for the false-positive figure. One function, so the suite and its
# controls cannot disagree about it.
#
# REFUSED - no figure, a failure in its place - when the scan did not cover what it was
# asked to cover. The channels are not the same event and the reasons differ:
#
#   no report              the scanner exited before scanning, or crashed. A named root
#                          that is not there refuses the whole scan up front (exit 1, no
#                          file written), and until this rule existed the suite read that
#                          as zero benign samples and printed "n/a" with no failure.
#   rootsMissing           a root vanished while the scan ran: a whole tree is absent from
#                          the denominator and the report cannot say how large it was.
#   interrupted            the walk stopped early; the denominator is a prefix of the tree.
#   directoriesUnreadable  a directory the walk could not list. An UNKNOWN number of files
#                          never entered the denominator, so the shortfall cannot even be
#                          sized, let alone corrected for.
#   filesSkipped.unreadable
#                          a KNOWN number of files the host would not let the scanner open.
#                          Known is not enough. Which files a host withholds is the host's
#                          choice and not the suite's - Defender quarantines whatever looks
#                          malicious, which is precisely the population most likely to hold
#                          a false positive - so the files that remain are not a sample of
#                          the tree, and a rate over them is a rate over a population the
#                          host drew. It moves between runs as the host works through the
#                          tree, and a figure that moves without a rule or a source changing
#                          is not a measurement of the scanner.
#
# NOT refused, only disclosed beside the figure:
#
#   filesSkipped.size, filesSkipped.excluded
#                          the scanner's own policy, decided from the bytes and the names,
#                          identical on every run of the same tree. They leave the
#                          denominator - the rate is over files the scanner READ - and the
#                          counts are printed so a reader can see what policy left out.
#   archives.*             decided by the bytes: a corrupt member is corrupt on every host.
#
# The line between the two is who chose the shortfall. A shortfall the scanner chose is
# reproducible and belongs to the definition of the figure; a shortfall the host chose is
# neither, and the figure is withheld until the host is made to comply.
#
# And one more, which is not a shortfall but the inability to see one:
#
#   a channel absent      the report does not carry one of the keys above. A scanner built
#                         before it reported missing roots steps over one, exits 0, and
#                         writes a report that reads exactly like a clean scan of a tree
#                         that was there. Absence of the channel is not evidence of
#                         coverage, so a report that cannot say what it covered is refused
#                         for that reason - and the first run of this rule's own control
#                         against build-release/ is what found it: that binary predates
#                         `rootsMissing` and had reported a clean scan of nothing.
COVERAGE_REFUSAL_RULE = "who chose the shortfall: the scanner's policy discloses, the host's refusal refuses"

# The keys a report has to carry before its figure can be trusted. Each is a channel the
# rule reads; a report without one cannot say whether the event it reports happened.
COVERAGE_CHANNELS = ("interrupted", "filesSkipped", "directoriesUnreadable", "rootsMissing")

def coverage_refusal(report, returncode=None, stderr=b""):
    """The reasons the false-positive figure must be refused for `report`, or [] when the
    scan covered what it was asked to. `report` is the parsed JSON, or None when the scanner
    wrote none; `returncode` and `stderr` say why in that case."""
    if report is None:
        said = next((l.strip() for l in (stderr or b"").decode("utf-8", "replace").split("\n")
                     if l.strip()), "no output")
        return ["no report was written: the scanner exited %s before scanning (%s)"
                % (returncode, said[:160])]
    reasons = []
    absent = [k for k in COVERAGE_CHANNELS if k not in report]
    if absent:
        reasons.append("the report carries no %s, so this scanner cannot say whether it "
                       "covered the tree; it predates the channel - build from a source "
                       "that reports it" % ", ".join(absent))
    roots = report.get("rootsMissing") or []
    if roots:
        reasons.append("%d named root(s) vanished during the scan, so whole trees are absent "
                       "from the denominator: %s" % (len(roots), ", ".join(map(str, roots))[:200]))
    if report.get("interrupted"):
        reasons.append("the scan was interrupted; the denominator is a prefix of the tree")
    dirs = report.get("directoriesUnreadable", 0) or 0
    if dirs:
        reasons.append("%d directorie(s) could not be listed, so an unknown number of files "
                       "never entered the denominator" % dirs)
    skipped = report.get("filesSkipped")
    unreadable = skipped.get("unreadable", 0) if isinstance(skipped, dict) else 0
    if unreadable:
        reasons.append("%d file(s) the host would not let the scanner open; which files a "
                       "host withholds is the host's choice, so the rest are not a sample "
                       "of the tree" % unreadable)
    return reasons

def files_read(report):
    """The denominator of the false-positive rate: files whose bytes the scanner read.

    `totalFilesScanned` counts every file the walk reached, including the ones it then
    declined (over the size cap) or could not open. Neither has been read, and a file that
    has not been read cannot be clean. By the time this is called `coverage_refusal` has
    established that the unreadable count is zero, so what leaves here is policy."""
    skipped = report.get("filesSkipped")
    if not isinstance(skipped, dict):
        skipped = {}
    n = (report.get("totalFilesScanned", 0)
         - skipped.get("size", 0) - skipped.get("unreadable", 0))
    return max(n, 0)

def benign_sweep(scan_targets, report_path):
    """One scan of `scan_targets` to `report_path`. Returns (report or None, CompletedProcess)."""
    cmd = [SCANNER, "scan", "--recursive", "--force", "--dry-run", "--no-ansi",
           "-o", "json", "-O", report_path] + list(scan_targets)
    r = subprocess.run(cmd, capture_output=True)
    if not os.path.exists(report_path):
        return None, r
    return json.load(open(report_path)), r

def benign_figures(report, returncode=None, stderr=b""):
    """What the suite records from one benign sweep: the figure, or its refusal.

    Returns a dict for `res["benign"]`. When refused, `refused` carries the reasons and no
    sample is counted; when not, `files_read` is the denominator and the skipped counts sit
    beside it."""
    out = {"refused": None, "files_read": 0, "false_positives": 0, "clean": 0,
           "coverage": {}, "false_positive_rules": {}}
    if report is not None:
        skipped = report.get("filesSkipped", {})
        out["coverage"] = {
            "totalFilesScanned": report.get("totalFilesScanned", 0),
            "filesSkipped": skipped if isinstance(skipped, dict) else {"total": skipped},
            "directoriesUnreadable": report.get("directoriesUnreadable", 0),
            "rootsMissing": report.get("rootsMissing") or [],
            "interrupted": bool(report.get("interrupted")),
            "archives": report.get("archives"),
        }
    reasons = coverage_refusal(report, returncode, stderr)
    if reasons:
        out["refused"] = reasons
        return out
    matched = [f for f in report.get("files", []) if not f.get("skipped")]
    out["files_read"] = files_read(report)
    out["false_positives"] = len(matched)
    out["clean"] = out["files_read"] - len(matched)
    out["false_positive_rules"] = dict(collections.Counter(
        m["category"] for f in matched for m in f.get("matches", [])))
    return out

def unpack_shards(dest):
    shards = []
    sd = os.path.join(HERE, "shards")
    if not os.path.isdir(sd):
        return shards
    for f in sorted(os.listdir(sd)):
        if not f.endswith(".tar.zst"):
            continue
        out = os.path.join(dest, f[:-len(".tar.zst")])
        os.makedirs(out, exist_ok=True)
        src = os.path.join(sd, f)
        r = subprocess.run(["tar", "-C", out, "-I", "zstd", "-xf", src], capture_output=True)
        if r.returncode != 0:
            # `-I` is GNU tar's --use-compress-program. bsdtar - the tar Windows ships in
            # system32, and the one Python finds on PATH there - spells that
            # --use-compress-program too, but reads `-I` as --include, so the line above
            # becomes an inclusion pattern and fails with "Failed to open 'zstd'". bsdtar
            # links libzstd and decompresses .tar.zst from the magic without being told.
            # Retry that way rather than branching on the platform: the GNU form is tried
            # first and still decides the outcome wherever it works, so Linux is unchanged.
            r2 = subprocess.run(["tar", "-C", out, "-xf", src], capture_output=True)
            if r2.returncode != 0:
                die("could not unpack %s: %s / %s" % (f, r.stderr.decode()[:200],
                                                      r2.stderr.decode()[:200]))
        shards.append(out)
    return shards

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--baseline", default=os.path.join(HERE, ".baseline", "verify.json"))
    ap.add_argument("--update-baseline", action="store_true")
    ap.add_argument("--skip-benign", action="store_true",
                    help="skip the benign sweep (it is the slow half)")
    ap.add_argument("--inject", action="store_true",
                    help="controls on the coverage refusal and the check classification")
    a = ap.parse_args()
    if a.inject:
        return inject()

    if not os.path.exists(SCANNER):
        die("scanner not built: %s (cmake --preset release && cmake --build build-release)" % SCANNER)
    idx_p = os.path.join(HERE, "index.jsonl")
    sum_p = os.path.join(HERE, "index-summary.json")
    for p in (idx_p, sum_p):
        if not os.path.exists(p): die("missing %s" % p)
    index = [json.loads(l) for l in open(idx_p)]
    summary = json.load(open(sum_p))

    res = {"corpus": {"total_blobs": summary["total_blobs"],
                      "published": summary["published"],
                      "local_only": summary["local_only"],
                      "reviewed_fraction": round(summary["published"] / float(summary["total_blobs"]), 4)},
           "malicious": {"detected": 0, "missed": 0, "rule_exact": 0, "samples": 0},
           "benign": {"clean": 0, "false_positives": 0, "samples": 0},
           "vulnerable": {"detected": 0, "missed": 0, "samples": 0},
           "known_miss": {"expected": 0, "still_missed": 0, "newly_detected": 0, "samples": []},
           "techniques": {"known": len(summary.get("techniques_known", {})),
                          "covered_by_tested_samples": 0, "uncovered": []},
           "failures": [], "held": summary.get("local_only_blockers", {}),
           # Samples `check` could not read. Never a verdict: not a miss, not clean, not a
           # known miss still missed. Counted here and listed under failures.
           "unscanned": 0}
    tested_techniques = set()

    tmp = tempfile.mkdtemp(prefix="lyxbosa-corpus-")
    try:
        shard_dirs = unpack_shards(tmp)
        # ---- shipped samples ----
        for r in index:
            if not r.get("family"):
                continue
            # Select on the VERDICT, not on the presence of a family. A benign shipped sample
            # has a family too - the first one to exist, an attacker-written but inert artefact,
            # was scored here as a malicious sample that failed to be detected, which made the
            # suite red for exactly the right outcome. Benign shipped samples are checked on the
            # must_not_detect path below, where they belong.
            if r.get("verdict") != "malicious":
                continue
            # A row that is not publishable is not in a public shard - `shard-census.py`
            # fails the build on exactly that - so looking for it there and reporting its
            # absence as a failure is asking the wrong question. Two rows entered this state
            # when a round adjudicated them unpublishable and dropped their files: the rows
            # stay, with their family, their verdict and their `expect`, because a sample
            # that was reviewed does not stop having been reviewed. What changed is where
            # its bytes are, and this loop is about the bytes.
            #
            # It is NOT skipped silently. `held` below already carries the local-only
            # population, and the count is printed, so a family disappearing from the suite
            # is visible as a number rather than as nothing.
            if r.get("publishable") is not True:
                res["not_shipped"] = res.get("not_shipped", 0) + 1
                continue
            exp = r.get("expect") or {}
            want = sorted(exp.get("must_detect", []))
            known = bool(exp.get("known_miss"))
            path = None
            # match by the manifest's source_sha256, falling back to the family name
            for d in shard_dirs:
                mp = os.path.join(d, "MANIFEST.json")
                if not os.path.exists(mp): continue
                for m in json.load(open(mp)):
                    if m.get("source_sha256") == r["sha256"] or m.get("name") == r.get("family"):
                        path = os.path.join(d, m["file"]); break
                if path: break
            if not path:
                res["failures"].append({"sample": r.get("family"), "why": "not present in any shard"})
                continue
            chk = check_sample(path)
            if chk["outcome"] == "error":
                res["unscanned"] += 1
                res["failures"].append(unscanned_failure(r.get("family"), chk))
                continue
            got = chk["rules"]
            tested_techniques |= set(r.get("technique") or [])
            res["malicious"]["samples"] += 1
            if known:
                res["known_miss"]["expected"] += 1
                if got:
                    res["known_miss"]["newly_detected"] += 1
                    res["known_miss"]["samples"].append({"sample": r["family"], "now_detects": got})
                else:
                    res["known_miss"]["still_missed"] += 1
                continue
            if got:
                res["malicious"]["detected"] += 1
                if got == want:
                    res["malicious"]["rule_exact"] += 1
                else:
                    res["failures"].append({"sample": r["family"], "why": "wrong rule",
                                            "expected": want, "got": got})
            else:
                res["malicious"]["missed"] += 1
                res["failures"].append({"sample": r["family"], "why": "not detected",
                                        "expected": want})

        # ---- clean carriers: must_not_detect ----
        for d in shard_dirs:
            mp = os.path.join(d, "MANIFEST.json")
            if not os.path.exists(mp): continue
            for m in json.load(open(mp)):
                if m.get("expect", {}).get("must_not_detect") != ["*"]: continue
                chk = check_sample(os.path.join(d, m["file"]))
                if chk["outcome"] == "error":
                    # Not clean. An empty rule list off a file nobody read is not a verdict.
                    res["unscanned"] += 1
                    res["failures"].append(unscanned_failure(m["name"], chk, "benign carrier"))
                    continue
                got = chk["rules"]
                res["benign"]["samples"] += 1
                if got:
                    res["benign"]["false_positives"] += 1
                    res["failures"].append({"sample": m["name"], "why": "false positive", "got": got})
                else:
                    res["benign"]["clean"] += 1

        # ---- pinned false-positive fixtures ----
        # Every FP found in the field becomes a permanent must_not_detect fixture (§8). They
        # live in expect/ keyed by sha256 rather than as index rows, because they come from
        # the pinned benign trees rather than from the incident collection, and they are
        # resolved by hashing those trees - so the fixture survives a version bump only if
        # the bytes are genuinely unchanged.
        fp_path = os.path.join(HERE, "expect", "benign-false-positives.json")
        if os.path.exists(fp_path):
            want_fp = {f["sha256"]: f for f in json.load(open(fp_path))}
            found = {}
            for tree in (os.path.join(ROOT, "trail-data", "CMS"),
                         os.path.join(ROOT, "trail-data", "CMS-ext")):
                if not os.path.isdir(tree): continue
                for dp, dns, fns in os.walk(tree):
                    if "_archives" in dp: continue
                    for fn in fns:
                        fp = os.path.join(dp, fn)
                        if os.path.islink(fp): continue
                        try:
                            h = hashlib.sha256(open(fp, "rb").read()).hexdigest()
                        except OSError:
                            continue
                        if h in want_fp and h not in found:
                            found[h] = fp
            res["fp_fixtures"] = {"pinned": len(want_fp), "resolved": len(found),
                                  "unresolved": 0, "unscanned": 0, "known_still_firing": 0,
                                  "newly_fixed": 0, "regressed": 0, "newly_fixed_samples": []}
            for h, f in want_fp.items():
                if h not in found:
                    res["fp_fixtures"]["unresolved"] += 1
                    res["failures"].append({"sample": h[:12], "why":
                        "pinned FP fixture not found in any benign tree (run fetch-benign.sh)"})
                    continue
                chk = check_sample(found[h])
                if chk["outcome"] == "error":
                    # Neither "still firing" nor "newly fixed": a fixture nobody could read
                    # has said nothing about the rule it pins.
                    res["fp_fixtures"]["unscanned"] += 1
                    res["unscanned"] += 1
                    res["failures"].append(unscanned_failure(h[:12], chk, "pinned FP fixture"))
                    continue
                got = chk["rules"]
                known = bool(f.get("known_fp"))
                rules = f["expect"].get("must_not_detect_when_fixed") or \
                        f["expect"].get("must_not_detect") or []
                firing = sorted(set(got) & set(rules))
                if known:
                    # Symmetric to known_miss: a known FP that still fires is the EXPECTED
                    # result, not a failure. One that stops firing is a result worth
                    # surfacing - promote it to a plain must_not_detect and pin it fixed.
                    if firing:
                        res["fp_fixtures"]["known_still_firing"] += 1
                    else:
                        res["fp_fixtures"]["newly_fixed"] += 1
                        res["fp_fixtures"]["newly_fixed_samples"].append(
                            {"sample": h[:12], "rules": rules})
                elif firing:
                    res["fp_fixtures"]["regressed"] += 1
                    res["failures"].append({"sample": h[:12], "why":
                        "a fixed false positive has returned", "got": firing})

        # ---- benign half: fetched, not shipped ----
        if not a.skip_benign:
            trees = [os.path.join(ROOT, "trail-data", "CMS"),
                     os.path.join(ROOT, "trail-data", "CMS-ext")]
            trees = [t for t in trees if os.path.isdir(t)]
            if not trees:
                res["benign"]["note"] = ("no benign trees on disk; run corpus/fetch-benign.sh. "
                                         "Counted as NOT TESTED, not as clean.")
            else:
                # Scan the UNPACKED trees only. trail-data/CMS-ext/_archives holds the
                # downloaded zips themselves; scanning them yields ARC findings about our own
                # download cache, which are not false positives on benign content.
                scan_targets = []
                for t in trees:
                    for sub in sorted(os.listdir(t)):
                        if sub == "_archives":
                            continue
                        full = os.path.join(t, sub)
                        if os.path.isdir(full):
                            scan_targets.append(full)
                if not scan_targets:
                    scan_targets = trees
                rep = os.path.join(tmp, "benign.json")
                report, r = benign_sweep(scan_targets, rep)
                fig = benign_figures(report, r.returncode, r.stderr)
                res["benign"]["coverage"] = fig["coverage"]
                res["benign"]["refused"] = fig["refused"]
                if fig["refused"]:
                    # No sample is counted. A figure over what the host allowed is not the
                    # figure this suite says it measures, and the failure below is what
                    # stops a green run from being read as one.
                    res["failures"].append({"sample": "benign sweep", "why":
                        "false-positive figure REFUSED, the scan did not cover the trees: "
                        + "; ".join(fig["refused"])})
                else:
                    res["benign"]["samples"] += fig["files_read"]
                    res["benign"]["false_positives"] += fig["false_positives"]
                    res["benign"]["clean"] += fig["clean"]
                    res["benign"]["false_positive_rules"] = fig["false_positive_rules"]
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    known_t = set(summary.get("techniques_known", {}))
    res["techniques"]["covered_by_tested_samples"] = len(known_t & tested_techniques)
    res["techniques"]["uncovered"] = sorted(known_t - tested_techniques)

    mal = res["malicious"]; ben = res["benign"]
    tested_mal = mal["detected"] + mal["missed"]

    # Detection over EVERY reviewed malicious sample, which is the figure "recall" is normally
    # taken to mean. The suite used to print detected/(detected+missed), where the denominator
    # is the set carrying `must_detect` - and a sample carries `must_detect` because it was
    # detected. Anything known not to be detected gets `known_miss` and leaves the denominator,
    # so that figure was 100% by construction and could only ever report a regression. It was
    # the fourth instance of CORPUS_PLAN section 11 and it was the headline.
    #
    # This one moves in both directions: reviewing a new family that nothing catches lowers it,
    # which is correct, and it rises only when rules improve. It cannot be gamed by review
    # order either, because every reviewed malicious sample is in the denominator whether or
    # not it is detected.
    # The known_miss split, read from the summary rather than recomputed, because the summary
    # is the denominator the documents quote and two tools counting the same marker their own
    # way is how the suite and the README came to disagree before doc-figures existed. The
    # marker covers three states and only `rule-gap` is a miss; printing the union under the
    # word "misses" reported 32 rows the scanner detects as rows it does not.
    km_kind = summary.get("malicious_known_miss_by_kind") or {}
    res["detection"] = {
        "detected": summary.get("malicious_detected", 0),
        "reviewed": summary.get("malicious_reviewed", 0),
        "known_miss": summary.get("malicious_known_miss", 0),
        "known_miss_rule_gap": km_kind.get("rule-gap", 0),
        "known_miss_detected_not_shippable": km_kind.get("detected-not-shippable", 0),
        "known_miss_unverified": km_kind.get("unverified", 0),
        "known_miss_unclassified": km_kind.get("<unclassified>", 0),
        "verified_by_rerun": summary.get("malicious_detected_runnable", 0),
        "recorded_only": (summary.get("malicious_detected", 0)
                          - summary.get("malicious_detected_runnable", 0)),
        "no_expectation": summary.get("malicious_no_expectation", 0),
    }
    # RECONCILE THE RECORDED FIGURE AGAINST WHAT THIS RUN OBSERVED.
    #
    # Everything above comes out of index-summary.json, so the Detection line is a
    # RECORDED number, not a measured one - and for a long time it printed regardless of
    # what the binary did. Pointed at a build containing none of the current rules, this
    # suite reported `shard-run 7/95, 88 missed` and `Regression 7/95`, both correctly red,
    # and directly above them `Detection 169/774 (21.8%)` with the sub-line "95 verified by
    # re-running check" - when 7 had been verified and 88 had just failed. The headline
    # figure, the one a stranger reads first, could not deliver bad news about the
    # instrument. That is section 11 again, in the same place it was found the first time.
    #
    # The check is cheap because the two numbers are meant to be the same number: every row
    # the summary counts as detected-and-runnable is a row this run executed and expected to
    # detect. If they disagree, the recorded figure is not reproducible with this binary and
    # printing it unqualified would be asserting something this run did not establish.
    res["detection"]["observed_by_rerun"] = mal["detected"]
    res["detection"]["reconciles"] = (mal["detected"]
                                      == summary.get("malicious_detected_runnable", 0))
    res["detection"]["rate"] = (round(res["detection"]["detected"]
                                      / float(res["detection"]["reviewed"]), 4)
                                if res["detection"]["reviewed"] else None)
    # the old figure, kept under the name of what it actually is
    res["regression_check"] = {"expected": tested_mal, "still_firing": mal["detected"],
                               "broken": mal["missed"]}

    res["recall"] = round(mal["detected"] / float(tested_mal), 4) if tested_mal else None

    # False-positive RATE is the meaningful precision-side number here, because it is
    # computed within one population.
    res["false_positive_rate"] = (round(ben["false_positives"] / float(ben["samples"]), 6)
                                  if ben["samples"] else None)

    # This suite does NOT report precision, and the omission is deliberate and permanent.
    #
    # Precision is tp/(tp+fp). It is only meaningful when the malicious-to-benign ratio in the
    # measured set resembles the ratio an operator actually faces. On the production host this
    # corpus came from, that ratio was roughly 37 true findings in 1.3 M files - about 1 in
    # 35,000. Any hand-curated malicious set inflates it by orders of magnitude, so precision
    # computed here would be a number about the corpus's composition, not about the scanner.
    #
    # An earlier version withheld it until the two sets were "commensurate" in size. That was
    # the wrong repair, because reaching commensurability makes the figure worse rather than
    # better: it means shrinking the benign side to a few hundred files, putting the ratio near
    # 1:1 - tens of thousands of times more malicious than reality - and printing something
    # flattering that means nothing. Reporting it unconditionally is no better: at 472 malicious
    # samples and 8 false positives it reads 98.3%, and at 200 it reads 96%. The number moves
    # with how much reviewing has been done, not with how good the scanner is.
    #
    # False-positive rate and recall are reported instead, because each is computed WITHIN one
    # population and so does not depend on the ratio between the two. That is also why adding
    # sources to benign/sources.jsonl does not move the goalposts: the FP denominator grows, the
    # FP rate stays comparable, and recall is untouched.
    #
    # There is one place a precision figure is genuinely meaningful, and it is not here: a field
    # scan of a real host, which supplies the real ratio. See CORPUS_PLAN.md section 8.
    res["precision_not_reported"] = (
        "by design. Precision needs the malicious-to-benign ratio of a real host (measured here: "
        "about 1 in 35,000); a curated corpus cannot supply it, so the figure would describe the "
        "corpus's composition rather than the scanner. False-positive rate and recall are each "
        "computed within one population and are reported instead. Precision belongs to field "
        "measurement, against a named host and scan.")

    # ---- regressions, against the baseline ----
    base = None
    if os.path.exists(a.baseline):
        base = json.load(open(a.baseline))
    if base:
        # §8's own rule applies to this comparison. A recall figure computed over a set whose
        # membership changed is NOT comparable to the previous run's, and reporting a delta
        # as though it were is how a suite starts lying quietly. So the denominator is
        # compared first, and a bare delta is withheld when it moved.
        base_n = (base.get("malicious", {}).get("detected", 0)
                  + base.get("malicious", {}).get("missed", 0))
        n_delta = tested_mal - base_n
        reg = {
            "reviewed_malicious_now": tested_mal,
            "reviewed_malicious_before": base_n,
            "reviewed_malicious_delta": n_delta,
            "new_failures": len(res["failures"]) - len(base.get("failures", [])),
            "known_miss_newly_detected": res["known_miss"]["newly_detected"]
                                         - base.get("known_miss", {}).get("newly_detected", 0),
        }
        if n_delta != 0:
            reg["recall_delta"] = None
            reg["recall_delta_note"] = (
                "withheld: the reviewed malicious set changed by %+d samples (%d -> %d), so "
                "this run's recall is over a different population than the baseline's. The "
                "two figures are not comparable; re-baseline deliberately, or compare only "
                "the samples present in both runs."
                % (n_delta, base_n, tested_mal))
        else:
            reg["recall_delta"] = (None if (res["recall"] is None or base.get("recall") is None)
                                   else round(res["recall"] - base["recall"], 4))
            reg["recall_delta_note"] = None
        res["regressions"] = reg
    if a.update_baseline:
        os.makedirs(os.path.dirname(a.baseline), exist_ok=True)
        json.dump(res, open(a.baseline, "w"), indent=1, sort_keys=True)

    if a.json:
        print(json.dumps(res, indent=1, sort_keys=True))
    else:
        c = res["corpus"]
        print("Corpus  %d blobs · %d published · %d held local-only (%.1f%% reviewed)"
              % (c["total_blobs"], c["published"], c["local_only"], c["reviewed_fraction"] * 100))
        print()
        print("  shard-run    %6d / %-6d detected   %d missed   (samples the suite executed)"
              % (mal["detected"], tested_mal, mal["missed"]))
        print("  benign       %6d / %-6d clean      %d false positives"
              % (ben["clean"], ben["samples"], ben["false_positives"]))
        print("  rule-exact   %6d / %-6d matched the expected rule"
              % (mal["rule_exact"], mal["detected"]))
        if res.get("not_shipped"):
            # Printed rather than passed over: a reviewed family whose bytes were dropped
            # out of a shard leaves the suite testing less than the index describes, and the
            # only thing worse than that happening is it happening quietly.
            print("  not shipped  %6d          reviewed malicious row(s) adjudicated "
                  "unpublishable," % res["not_shipped"])
            print("                              so their bytes are in no shard and this "
                  "run could not execute them")
        print()
        d = res["detection"]
        print("  Detection      %4d / %-5d reviewed malicious samples detected   (%s)"
              % (d["detected"], d["reviewed"],
                 "%.1f%%" % (d["rate"] * 100) if d["rate"] is not None else "n/a"))
        if d.get("reconciles", True):
            print("                 %d verified by re-running `check`; %d held local-only, so the"
                  % (d["verified_by_rerun"], d["recorded_only"]))
            print("                 recorded result from the last rescan stands for those")
        else:
            print("                 NOT RECONCILED: the index records %d of these as runnable,"
                  % d["verified_by_rerun"])
            print("                 and this run detected %d of them. The figure above is read"
                  % d["observed_by_rerun"])
            print("                 from index-summary.json and is NOT what this binary does.")
            print("                 Rebuild, or point LYXBOSA_BIN at the build you mean.")
            res["failures"].append({"sample": "detection", "why": "recorded figure does not "
                                    "reconcile with this run",
                                    "expected": d["verified_by_rerun"],
                                    "got": d["observed_by_rerun"]})
        rc = res["regression_check"]
        print("  Regression     %4d / %-5d expected detections still firing"
              % (rc["still_firing"], rc["expected"]))
        if ben.get("refused"):
            print("  False-positive rate REFUSED - the benign scan did not cover the trees it")
            print("                 was asked to, so there is no population to report over:")
            for why in ben["refused"]:
                print("                   - %s" % why)
        else:
            print("  False-positive rate %s  (%d of %d benign files read)"
                  % ("%.4f%%" % (res["false_positive_rate"] * 100)
                     if res["false_positive_rate"] is not None else "n/a",
                     ben["false_positives"], ben["samples"]))
            cov = ben.get("coverage") or {}
            sk = cov.get("filesSkipped") or {}
            if sk.get("size") or sk.get("excluded"):
                print("                 %d over the size cap and %d excluded by policy were "
                      "reached and not read;" % (sk.get("size", 0), sk.get("excluded", 0)))
                print("                 they are not in the denominator (policy, the same on "
                      "every run)")
        if res.get("unscanned"):
            print("  UNSCANNED      %4d sample(s) `check` could not read - listed under "
                  "failures, counted nowhere else" % res["unscanned"])
        if "fp_fixtures" in res:
            f = res["fp_fixtures"]
            print("  Known FPs        %d expected · %d newly fixed"
                  % (f["known_still_firing"], f["newly_fixed"]))
            if f["regressed"]:
                print("  FP REGRESSIONS   %d fixed false positives have returned" % f["regressed"])
        d = res["detection"]
        print("  Known misses   %4d no rule fires · %d of them re-run here · %d newly detected"
              % (d["known_miss_rule_gap"], res["known_miss"]["expected"],
                 res["known_miss"]["newly_detected"]))
        # Printed every run, including at zero. These are the rows that carry the same marker
        # and are not misses; a line that appeared only when the count was non-zero would let
        # the number the README publishes and the number the suite prints drift apart in the
        # one state nobody would notice.
        print("                 %4d detected, but no shard carries the bytes, so the suite "
              "cannot assert a rule" % d["known_miss_detected_not_shippable"])
        print("                 %4d not re-measurable here: the bytes are not on this machine"
              % d["known_miss_unverified"])
        if d["known_miss_unclassified"]:
            print("                 %4d carry no measured kind - run "
                  "corpus/classify-known-miss.py --apply" % d["known_miss_unclassified"])
        t = res["techniques"]
        print("  Techniques       %d of %d known techniques covered by a tested sample"
              % (t["covered_by_tested_samples"], t["known"]))
        if t["known"] and t["covered_by_tested_samples"] == t["known"]:
            print("                   (a staleness signal, not completion: the denominator is")
            print("                    enumerated from the reviewed set, so it cannot see a")
            print("                    technique in the blobs still unreviewed. CORPUS_PLAN §11)")
        if "regressions" in res:
            r = res["regressions"]
            if r.get("recall_delta_note"):
                print("  Regressions      %+d failures · regression-rate delta withheld"
                      % r["new_failures"])
            else:
                print("  Regressions      %+d failures · regression-rate delta %s"
                      % (r["new_failures"],
                         "n/a" if r["recall_delta"] is None else "%+.4f" % r["recall_delta"]))
        print()
        print()
        print("  Precision is not reported. It is not withheld pending more data - it is the")
        print("  wrong measurement for a curated corpus. tp/(tp+fp) depends on the malicious-")
        print("  to-benign ratio, which on a real host is about 1 in 35,000 and here is chosen")
        print("  by whoever did the reviewing. Precision is a field-scan measurement, against a")
        print("  named host and scan; the corpus measures false-positive rate and recall, each")
        print("  computed within one population. See CORPUS_PLAN.md section 8.")
        if res.get("regressions", {}).get("recall_delta_note"):
            n = res["regressions"]
            print()
            print("  Regression rate not comparable to baseline: the executed set went %d -> %d "
                  "(%+d)." % (n["reviewed_malicious_before"], n["reviewed_malicious_now"],
                              n["reviewed_malicious_delta"]))
            print("  A figure over a set that grew is not the same measurement. Detection, above,")
            print("  is different: its denominator is every reviewed malicious sample, so a fall")
            print("  when a new family is reviewed is the correct reading, not an artefact.")
        print()
        print("  Detection is over the REVIEWED set only.")
        print("  %d blobs are held and untested; the largest reasons:" % c["local_only"])
        for k, v in sorted(res["held"].items(), key=lambda x: -x[1])[:4]:
            print("      %-64s %6d" % (k[:64], v))
        if res.get("fp_fixtures", {}).get("newly_fixed"):
            print()
            print("  NEWLY FIXED false positives (a result — promote to must_not_detect):")
            for x in res["fp_fixtures"]["newly_fixed_samples"]:
                print("      %-14s no longer fires %s" % (x["sample"], ",".join(x["rules"])))
        if res["known_miss"]["newly_detected"]:
            print()
            print("  NEWLY DETECTED (a result, not a failure — promote into must_detect):")
            for s in res["known_miss"]["samples"]:
                print("      %-34s now detects %s" % (s["sample"], ",".join(s["now_detects"])))
        if res["techniques"]["uncovered"]:
            print()
            print("  TECHNIQUES WITH NO TESTED SAMPLE (%d) — the milestone's open items:"
                  % len(res["techniques"]["uncovered"]))
            for x in res["techniques"]["uncovered"]:
                print("      %s" % x)
        if res["failures"]:
            print()
            print("  FAILURES (%d):" % len(res["failures"]))
            for f in res["failures"][:12]:
                print("      %-34s %s" % (str(f.get("sample"))[:34], f["why"]))
    return 1 if res["failures"] else 0

# --------------------------------------------------------------------------- controls

class _EndToEndStopped(Exception):
    """The end-to-end half cannot continue with the scanner at hand; the case that says
    why has already been recorded as a failure."""

def inject():
    """Both directions, for both halves.

    The refusal rule over synthesised reports first, one channel at a time and the two
    policy channels asserted NOT to refuse - a rule that refused everything would satisfy
    "an unreadable file refuses" and report no figure ever. Then the same rule against the
    real scanner over a real tree: a clean run must produce a figure, and the same tree
    with one file the user may not read must not. The check classification is asserted the
    same way: exit 1 is an error and specifically not clean.

    Two of the end-to-end cases need a path the current user cannot read, which root can
    always read; those say so and are counted as not observed rather than passed.
    """
    global SCANNER
    SCANNER = control_scanner()

    fails, cases, unobserved = [], [], []

    def case(label, ok):
        cases.append(label)
        print("  %-74s %s" % (label, "ok" if ok else "WRONG"))
        if not ok:
            fails.append(label)

    def not_observed(label, why):
        unobserved.append(label)
        print("  %-74s NOT OBSERVED (%s)" % (label, why))

    def report(**kw):
        d = {"files": [], "interrupted": False, "totalFilesScanned": 10,
             "filesSkipped": {"total": 0, "size": 0, "excluded": 0, "unreadable": 0},
             "directoriesUnreadable": 0, "rootsMissing": []}
        for k, v in kw.items():
            if k in ("size", "excluded", "unreadable"):
                d["filesSkipped"][k] = v
                d["filesSkipped"]["total"] += v
            else:
                d[k] = v
        return d

    print("=== the refusal rule, one channel at a time ===")
    case("a clean report is not refused", coverage_refusal(report()) == [])
    why = coverage_refusal(report(unreadable=1))
    case("one unreadable file refuses", len(why) == 1)
    case("  ...and the reason says the host chose it",
         bool(why) and "host" in why[0] and "1 file" in why[0])
    why = coverage_refusal(report(directoriesUnreadable=1))
    case("one unreadable directory refuses", len(why) == 1)
    case("  ...and the reason says the shortfall is unknown", bool(why) and "unknown" in why[0])
    why = coverage_refusal(report(rootsMissing=["/gone"]))
    case("a root that vanished refuses", len(why) == 1 and "/gone" in why[0])
    case("an interrupted scan refuses", len(coverage_refusal(report(interrupted=True))) == 1)
    why = coverage_refusal(None, 1, b"Error: 1 of the 2 directories to scan is not usable")
    case("no report at all refuses", len(why) == 1)
    case("  ...and quotes the exit code and what the scanner said",
         bool(why) and "exited 1" in why[0] and "not usable" in why[0])
    case("every channel at once is every reason, not the first one",
         len(coverage_refusal(report(unreadable=2, directoriesUnreadable=1,
                                     rootsMissing=["/a"], interrupted=True))) == 4)
    old = report(); del old["rootsMissing"]
    why = coverage_refusal(old)
    case("a report that lacks a channel is refused: absence is not coverage",
         len(why) == 1 and "rootsMissing" in why[0])
    old = report(); del old["filesSkipped"]; del old["directoriesUnreadable"]
    case("  ...naming every channel it lacks",
         any("filesSkipped" in w and "directoriesUnreadable" in w for w in coverage_refusal(old)))

    print()
    print("=== the channels that disclose and do NOT refuse ===")
    case("files over the size cap do not refuse", coverage_refusal(report(size=7)) == [])
    case("files excluded by policy do not refuse", coverage_refusal(report(excluded=3)) == [])
    case("an archive the bytes will not open does not refuse",
         coverage_refusal(report(archives={"opened": 2, "unreadable": 1})) == [])
    case("  ...but they leave the denominator: 10 reached, 7 over size -> 3 read",
         files_read(report(size=7)) == 3)
    fig = benign_figures(report(size=7, files=[{"path": "x", "matches": [{"category": "RCE004"}]}]))
    case("  ...and the figure is over the files read: 1 FP of 3, not of 10",
         fig["refused"] is None and fig["files_read"] == 3
         and fig["false_positives"] == 1 and fig["clean"] == 2)
    fig = benign_figures(report(unreadable=1))
    case("a refused sweep counts no sample, not even the readable ones",
         fig["refused"] and fig["files_read"] == 0 and fig["clean"] == 0)
    case("  ...and still records what the scanner reported, for the reader",
         fig["coverage"].get("filesSkipped", {}).get("unreadable") == 1)

    print()
    print("=== what one `check` established, by exit code ===")
    det = classify_check(2, b"File: x\nMatches: 1\n\n  [CRITICAL] eval (1:1) - RCE004\n")
    case("exit 2 with a rule line is detected, with the rule",
         det["outcome"] == "detected" and det["rules"] == ["RCE004"])
    case("exit 0 is clean", classify_check(0, b"No matches found in: x\n")["outcome"] == "clean")
    err = classify_check(1, b"Not scanned (unreadable): x\n")
    case("exit 1 is an error", err["outcome"] == "error")
    case("  ...and specifically NOT clean, though it printed no rule",
         err["outcome"] != "clean" and err["rules"] == [])
    case("  ...and specifically NOT detected", err["outcome"] != "detected")
    case("  ...and carries what the scanner said, so the failure line can",
         err["said"].startswith("Not scanned (unreadable)"))
    case("a missing file is the same error", classify_check(1, b"", b"Error: File not found: x")
         ["outcome"] == "error")
    f = unscanned_failure("fam", err)
    case("the failure a sample gets names the exit code and the reason",
         "exited 1" in f["why"] and "unreadable" in f["why"])

    print()
    print("=== and against the real scanner, over a real tree ===")
    # These are the cases that make the ones above worth having: a rule asserted only
    # against reports the control wrote itself is bounded by what the control imagined the
    # scanner writes.
    if not os.path.exists(SCANNER):
        case("scanner built at %s (set LYXBOSA_BIN)" % os.path.relpath(SCANNER, ROOT), False)
    else:
        root_why = ("running as root, which can read a mode-000 path, so no refusal can "
                    "be observed") if os.geteuid() == 0 else None
        tmp = tempfile.mkdtemp(prefix="verify-inject-")
        try:
            tree = os.path.join(tmp, "tree")
            os.makedirs(os.path.join(tree, "sub"))
            with open(os.path.join(tree, "clean.php"), "w") as fh:
                fh.write("<?php echo 'hello';\n")
            with open(os.path.join(tree, "sub", "also.php"), "w") as fh:
                fh.write("<?php echo 'there';\n")

            rep = os.path.join(tmp, "clean.json")
            report, r = benign_sweep([tree], rep)
            fig = benign_figures(report, r.returncode, r.stderr)
            absent = [k for k in COVERAGE_CHANNELS if k not in (report or {})]
            # Loud, not skipped. A scanner that predates a channel can produce no figure
            # at all, and the cases below cannot be observed with it. That is a stale
            # precondition - the same kind as a derived database that needs rebuilding -
            # and it is reported as a failure that says what to rebuild, because the
            # alternative is a control that passes on a binary the suite refuses.
            case("the scanner under test, %s, carries every coverage channel"
                 % os.path.relpath(SCANNER, ROOT), report is not None and not absent)
            if absent:
                case("  ...it lacks %s, and its figure is refused for exactly that"
                     % ", ".join(absent),
                     bool(fig["refused"]) and all(any(k in w for w in fig["refused"])
                                                  for k in absent))
                print("    the remaining end-to-end cases need a scanner that reports those")
                print("    channels; rebuild this one from a source that does, or point")
                print("    LYXBOSA_BIN at build/")
                # The one case that IS observable with it: a root that is not there, which
                # this scanner steps over and reports nothing about.
                rep = os.path.join(tmp, "missing-root.json")
                report, r = benign_sweep([tree, os.path.join(tmp, "not-there")], rep)
                fig = benign_figures(report, r.returncode, r.stderr)
                case("a root that is not there refuses the figure even so", bool(fig["refused"]))
                raise _EndToEndStopped()
            case("an ordinary clean run is not refused", fig["refused"] is None)
            case("  ...and reports 2 of 2 files read, 0 false positives",
                 fig["files_read"] == 2 and fig["false_positives"] == 0 and fig["clean"] == 2)

            chk = check_sample(os.path.join(tree, "clean.php"))
            case("`check` on a readable clean file is clean", chk["outcome"] == "clean")

            locked = os.path.join(tree, "locked.php")
            with open(locked, "w") as fh:
                fh.write("<?php echo 'unread';\n")
            os.chmod(locked, 0)
            try:
                if root_why:
                    not_observed("a file this user cannot read refuses the figure", root_why)
                    not_observed("`check` on a file this user cannot read is an error", root_why)
                else:
                    rep = os.path.join(tmp, "unreadable.json")
                    report, r = benign_sweep([tree], rep)
                    fig = benign_figures(report, r.returncode, r.stderr)
                    case("a file this user cannot read refuses the figure",
                         report is not None and bool(fig["refused"]))
                    case("  ...for that reason and no other",
                         len(fig["refused"] or []) == 1 and "1 file" in (fig["refused"] or [""])[0])
                    case("  ...and the readable files are not counted around it",
                         fig["files_read"] == 0 and fig["clean"] == 0)
                    chk = check_sample(locked)
                    case("`check` on a file this user cannot read is an error",
                         chk["outcome"] == "error" and chk["exit"] == 1)
                    case("  ...and not clean", chk["outcome"] != "clean")
            finally:
                os.chmod(locked, 0o644)
                os.remove(locked)

            shut = os.path.join(tree, "shut")
            os.makedirs(shut)
            with open(os.path.join(shut, "inside.php"), "w") as fh:
                fh.write("<?php echo 'inside';\n")
            os.chmod(shut, 0)
            try:
                if root_why:
                    not_observed("a directory this user cannot list refuses the figure", root_why)
                else:
                    rep = os.path.join(tmp, "shut.json")
                    report, r = benign_sweep([tree], rep)
                    fig = benign_figures(report, r.returncode, r.stderr)
                    case("a directory this user cannot list refuses the figure",
                         report is not None and bool(fig["refused"])
                         and any("unknown number" in w for w in fig["refused"]))
            finally:
                os.chmod(shut, 0o755)

            # Back to clean, so the tree is proven to produce a figure again once the
            # host complies - a refusal that stuck would be a suite that never reports.
            rep = os.path.join(tmp, "clean-again.json")
            report, r = benign_sweep([tree], rep)
            fig = benign_figures(report, r.returncode, r.stderr)
            case("the same tree with access restored is reported again",
                 fig["refused"] is None and fig["files_read"] == 3)

            # Two scanners can be under test here and they behave differently on a root
            # that is not there: one built from a source that refuses up front (exit 1, no
            # report), and one built before that, which steps over the root and writes a
            # report with no rootsMissing key. The figure has to be refused either way, and
            # the case asserts the path the binary actually took rather than assuming one -
            # the first run of this control against build-release/ took the second path and
            # exposed that the rule had not covered it.
            rep = os.path.join(tmp, "missing-root.json")
            report, r = benign_sweep([tree, os.path.join(tmp, "not-there")], rep)
            fig = benign_figures(report, r.returncode, r.stderr)
            case("a root that is not there refuses the figure (%s)"
                 % os.path.relpath(SCANNER, ROOT), bool(fig["refused"]))
            if report is None:
                case("  ...this scanner refused up front: exit 1 and no report",
                     r.returncode == 1)
                case("  ...and the reason quotes the scanner's own refusal",
                     bool(fig["refused"]) and "not usable" in fig["refused"][0])
            else:
                case("  ...this scanner stepped over it and reports no rootsMissing, which "
                     "is refused as a channel it lacks",
                     "rootsMissing" not in report
                     and any("rootsMissing" in w for w in fig["refused"]))
        except _EndToEndStopped:
            pass
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    print()
    print("cases: %d · passed: %d · failed: %d · not observed: %d"
          % (len(cases), len(cases) - len(fails), len(fails), len(unobserved)))
    for f in fails:
        print("FAIL:", f)
    for u in unobserved:
        print("NOT OBSERVED:", u)
    return 1 if fails else 0

if __name__ == "__main__":
    sys.exit(main())
