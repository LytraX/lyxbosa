#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""§8 — the golden suite.

One command, machine-readable output, every past mistake permanent.

Two things this deliberately does differently from a naive suite:

  * It reports precision and recall **over the reviewed set**, and prints the held count
    beside them. A figure computed over a corpus that is mostly unreviewed, without saying
    so, is the difference between "convincing empirical evidence" and a number someone can
    check. `index-summary.json` is the denominator so the suite can state what it is *not*
    testing.

  * `known_miss` samples get their own column and never count as failures. A known miss that
    is still missed is the expected result; one that starts being detected is a *result*
    worth surfacing, not a broken test. Only a detected-then-missed sample is red.

Usage:
  corpus/verify.py [--json] [--baseline FILE] [--update-baseline] [--skip-benign]
"""
import json, os, re, sys, subprocess, argparse, collections, hashlib, tempfile, shutil

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SCANNER = os.path.join(ROOT, "build-release", "lyxbosa")

def die(msg, code=2):
    print("error: %s" % msg, file=sys.stderr); sys.exit(code)

def check_rules(path):
    """Per-sample check. Never a batch scan: a batch cannot distinguish 'not scanned'
    from 'scanned and clean' (CORPUS_PLAN §5.6, §8)."""
    r = subprocess.run([SCANNER, "check", "--no-ansi", path], capture_output=True)
    return sorted(set(x.decode() for x in re.findall(rb"- ([A-Z]+\d+)", r.stdout)))

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
        r = subprocess.run(["tar", "-C", out, "-I", "zstd", "-xf", os.path.join(sd, f)],
                           capture_output=True)
        if r.returncode != 0:
            die("could not unpack %s: %s" % (f, r.stderr.decode()[:200]))
        shards.append(out)
    return shards

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--baseline", default=os.path.join(HERE, ".baseline", "verify.json"))
    ap.add_argument("--update-baseline", action="store_true")
    ap.add_argument("--skip-benign", action="store_true",
                    help="skip the benign sweep (it is the slow half)")
    a = ap.parse_args()

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
           "failures": [], "held": summary.get("local_only_blockers", {})}

    tmp = tempfile.mkdtemp(prefix="lyxbosa-corpus-")
    try:
        shard_dirs = unpack_shards(tmp)
        # ---- shipped samples ----
        for r in index:
            if not r.get("family"):
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
            got = check_rules(path)
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
                got = check_rules(os.path.join(d, m["file"]))
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
                                  "unresolved": 0, "known_still_firing": 0,
                                  "newly_fixed": 0, "regressed": 0, "newly_fixed_samples": []}
            for h, f in want_fp.items():
                if h not in found:
                    res["fp_fixtures"]["unresolved"] += 1
                    res["failures"].append({"sample": h[:12], "why":
                        "pinned FP fixture not found in any benign tree (run fetch-benign.sh)"})
                    continue
                got = check_rules(found[h])
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
                cmd = [SCANNER, "scan", "--recursive", "--force", "--dry-run", "--no-ansi",
                       "-o", "json", "-O", rep] + scan_targets
                subprocess.run(cmd, capture_output=True)
                if os.path.exists(rep):
                    d = json.load(open(rep))
                    scanned = d.get("totalFilesScanned", 0)
                    matched = [f for f in d.get("files", []) if not f.get("skipped")]
                    res["benign"]["samples"] += scanned
                    res["benign"]["false_positives"] += len(matched)
                    res["benign"]["clean"] += scanned - len(matched)
                    skipped = d.get("filesSkipped", {})
                    res["benign"]["skipped_breakdown"] = skipped if isinstance(skipped, dict) else {"total": skipped}
                    res["benign"]["false_positive_rules"] = dict(collections.Counter(
                        m["category"] for f in matched for m in f.get("matches", [])))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    mal = res["malicious"]; ben = res["benign"]
    tested_mal = mal["detected"] + mal["missed"]
    res["recall"] = round(mal["detected"] / float(tested_mal), 4) if tested_mal else None

    # False-positive RATE is the meaningful precision-side number here, because it is
    # computed within one population.
    res["false_positive_rate"] = (round(ben["false_positives"] / float(ben["samples"]), 6)
                                  if ben["samples"] else None)

    # Precision as tp/(tp+fp) is only meaningful when the malicious and benign sets are
    # commensurate. Right now they are not: a handful of shipped malicious samples against a
    # six-figure benign sweep produces a number that looks catastrophic and means nothing.
    # Emit it only when the malicious set is at least 1% the size of the benign set, and
    # otherwise say why, rather than printing a figure that would have to be explained away.
    tp = mal["detected"]; fp = ben["false_positives"]
    MIN_MAL, MIN_BEN = 30, 1000
    commensurate = (tested_mal and ben["samples"]
                    and tested_mal >= MIN_MAL and ben["samples"] >= MIN_BEN
                    and tested_mal >= 0.01 * ben["samples"])
    if commensurate:
        res["precision"] = round(tp / float(tp + fp), 4) if (tp + fp) else None
        res["precision_note"] = None
    else:
        res["precision"] = None
        res["precision_note"] = (
            "not reported: %d malicious samples against %d benign files. Precision needs both "
            "sets to be large enough to mean anything (at least %d malicious and %d benign) AND "
            "commensurate in size, or tp/(tp+fp) is dominated by the size difference rather than "
            "by detection quality. Use false_positive_rate, which is computed within one "
            "population." % (tested_mal, ben["samples"], MIN_MAL, MIN_BEN))

    # ---- regressions, against the baseline ----
    base = None
    if os.path.exists(a.baseline):
        base = json.load(open(a.baseline))
    if base:
        res["regressions"] = {
            "recall_delta": None if (res["recall"] is None or base.get("recall") is None)
                            else round(res["recall"] - base["recall"], 4),
            "new_failures": len(res["failures"]) - len(base.get("failures", [])),
            "known_miss_newly_detected": res["known_miss"]["newly_detected"]
                                         - base.get("known_miss", {}).get("newly_detected", 0),
        }
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
        print("  malicious    %6d / %-6d detected   %d missed"
              % (mal["detected"], tested_mal, mal["missed"]))
        print("  benign       %6d / %-6d clean      %d false positives"
              % (ben["clean"], ben["samples"], ben["false_positives"]))
        print("  rule-exact   %6d / %-6d matched the expected rule"
              % (mal["rule_exact"], mal["detected"]))
        print()
        print("  Recall            %s   (over %d reviewed malicious samples)"
              % ("%.2f%%" % (res["recall"] * 100) if res["recall"] is not None else "n/a",
                 tested_mal))
        if res["precision"] is not None:
            print("  Precision         %.2f%%" % (res["precision"] * 100))
        else:
            print("  Precision         not reported — see below")
        print("  False-positive rate %s  (%d of %d benign files)"
              % ("%.4f%%" % (res["false_positive_rate"] * 100)
                 if res["false_positive_rate"] is not None else "n/a",
                 ben["false_positives"], ben["samples"]))
        if "fp_fixtures" in res:
            f = res["fp_fixtures"]
            print("  Known FPs        %d expected · %d newly fixed"
                  % (f["known_still_firing"], f["newly_fixed"]))
            if f["regressed"]:
                print("  FP REGRESSIONS   %d fixed false positives have returned" % f["regressed"])
        print("  Known misses     %d expected · %d newly detected"
              % (res["known_miss"]["expected"], res["known_miss"]["newly_detected"]))
        if "regressions" in res:
            r = res["regressions"]
            print("  Regressions      %+d failures · recall delta %s"
                  % (r["new_failures"],
                     "n/a" if r["recall_delta"] is None else "%+.4f" % r["recall_delta"]))
        print()
        if res.get("precision_note"):
            print()
            print("  Precision withheld: %s" % res["precision_note"][:76])
            for extra in [res["precision_note"][i:i+76] for i in range(76, len(res["precision_note"]), 76)]:
                print("                      %s" % extra)
        print()
        print("  Recall is over the REVIEWED set only.")
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
        if res["failures"]:
            print()
            print("  FAILURES (%d):" % len(res["failures"]))
            for f in res["failures"][:12]:
                print("      %-34s %s" % (str(f.get("sample"))[:34], f["why"]))
    return 1 if res["failures"] else 0

if __name__ == "__main__":
    sys.exit(main())
