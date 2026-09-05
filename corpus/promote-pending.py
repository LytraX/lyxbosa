#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Apply `corpus/pending-promotions.jsonl` - the corpus side of the rules/corpus handoff.

A rules round measures which `known_miss` rows its new rules now detect and writes them
here; the corpus side applies them and deletes each row as it goes, so a non-empty file
means work is owed and an absent file means none is. See SOURCES.md.

THE FILE IS A HANDOFF, NOT AN AUTHORITY
---------------------------------------
Every row's `now_detects` is re-measured here with `check`, against the bytes the suite
will actually run - the shipped file in the shard, not the source blob - and a row whose
measurement disagrees with what it recorded is REFUSED rather than applied. That is not
distrust of the other side; it is that `expect.must_detect` is compared to `check`'s
output *exactly*, so a row applied with a rule set that is merely close turns a passing
suite red, and the failure names the sample rather than the handoff.

The specific trap this guards is a stale binary. A build without the round's rules returns
the empty set for every sample, which promotes nothing and reports zero newly detected -
a plausible-looking number rather than an error. So an empty measurement on a row the
handoff says now fires is a hard refusal that names the binary.

WHAT A PROMOTION IS
-------------------
`expect.known_miss` becomes `expect.closed_known_miss`, recording the date, the rule that
closed it, and the reason the row previously gave for being missed. `must_detect` becomes
the measured set. Nothing else on the row changes: a promotion is a statement about
detection, not about review, masking or publishability.

WHAT IT WILL NOT DO
-------------------
  * promote a row whose `publish_blockers` are non-empty, whatever else the row says. A
    blocker is resolved by doing the masking or the review, never by the applier;
  * promote a row in the local half. Its detection is real and its blockers are not about
    detection, which is why the file records the blocker rather than just the sha256;
  * touch `verdict`, `publishable`, `sensitivity` or `masking`.

Usage:
  corpus/promote-pending.py --stage-root DIR [--apply] [--pending F] [--index F]
  corpus/promote-pending.py --inject
"""
import argparse, datetime, hashlib, json, os, re, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
from indexio import read_jsonl, write_jsonl_atomic, index_lock, LockBusy   # noqa: E402

SCANNER = os.environ.get("LYXBOSA_BIN") or os.path.join(ROOT, "build-release", "lyxbosa")


def check_rules(path, scanner=None):
    """Per-sample, never a batch scan: a batch cannot say which rule fired on which file,
    and `expect.must_detect` is a per-file claim (CORPUS_PLAN section 8)."""
    r = subprocess.run([scanner or SCANNER, "check", "--no-ansi", path],
                       capture_output=True)
    return sorted(set(x.decode() for x in re.findall(rb"- ([A-Z]+\d+)", r.stdout)))


def read_pending(path):
    """Rows plus the leading comment block, which is documentation and must survive a
    partial application of the file."""
    header, rows = [], []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            if line.startswith("#"):
                header.append(line.rstrip("\n"))
            elif line.strip():
                rows.append(json.loads(line))
    return header, rows


def locate(stage_root, sha):
    """The shipped file for a source blob, and the shard carrying it."""
    for name in sorted(os.listdir(stage_root)):
        mp = os.path.join(stage_root, name, "MANIFEST.json")
        if not os.path.exists(mp):
            continue
        for e in json.load(open(mp, encoding="utf-8")):
            if e.get("source_sha256") == sha:
                return name, os.path.join(stage_root, name, e["file"]), e
    return None, None, None


def closed_expect(prev, rules, date):
    """`expect` for a row whose known miss has just closed.

    The shape follows the one already in the index from the previous round: the
    `known_miss` pair is replaced by a `closed_known_miss` record carrying the date, the
    rule, and verbatim the reason the row used to give for being missed.
    """
    out = {k: v for k, v in (prev or {}).items()
           if k not in ("known_miss", "known_miss_reason")}
    out["must_detect"] = sorted(rules)
    out.setdefault("must_not_detect", [])
    rec = {"date": date, "was": (prev or {}).get("known_miss_reason") or "no rule fired"}
    if len(rules) == 1:
        rec["rule"] = rules[0]          # the existing convention, one rule as a string
    else:
        rec["rules"] = sorted(rules)    # more than one: a list, and never a joined string
    out["closed_known_miss"] = rec
    return out


def adjudicate(pend, index, stage_root, scanner, date):
    """Decide every pending row. Returns (applied, refused, deferred).

    Nothing is written here; this is the whole decision, so --apply and a dry run see the
    same answer and a refusal cannot be a side effect of the write.
    """
    applied, refused, deferred = [], [], []
    for p in pend:
        sha = p["sha256"]
        # The blocker is checked FIRST and reported verbatim. Testing the half first
        # collapses every local row to "in the local half", which is the generic reason
        # hiding the specific, actionable one - the mistake SOURCES.md records about a
        # gate that stored only its first blocker.
        if p.get("publish_blockers"):
            deferred.append((p, "[%s half] %s" % (p.get("half"),
                                                  "; ".join(p["publish_blockers"]))))
            continue
        if p.get("half") != "published":
            refused.append((p, "handoff puts the row in the %s half but records no "
                               "blocker. A row that is not published has no shipped bytes "
                               "to promote, so one of the two fields is wrong"
                            % p.get("half")))
            continue
        r = index.get(sha)
        if r is None:
            refused.append((p, "sha256 is in no published index row"))
            continue
        if r.get("verdict") != "malicious":
            refused.append((p, "index verdict is %r, not malicious" % r.get("verdict")))
            continue
        if not r.get("publishable"):
            refused.append((p, "index row is not publishable"))
            continue
        exp = r.get("expect") or {}
        if not exp.get("known_miss"):
            refused.append((p, "index row does not carry expect.known_miss: "
                               "nothing to promote, or already promoted"))
            continue
        shard, path, entry = locate(stage_root, sha)
        if path is None:
            refused.append((p, "no shard in the stage carries these bytes; a published "
                               "malicious row with no shard is reported absent, not tested"))
            continue
        blob = open(path, "rb").read()
        if entry.get("masked") is False and hashlib.sha256(blob).hexdigest() != sha:
            refused.append((p, "shipped bytes claim masked:false but do not hash to the "
                               "source sha256"))
            continue
        got = check_rules(path, scanner)
        if not got:
            refused.append((p, "check returned NOTHING on bytes the handoff says now fire "
                               "%s. This is what a binary built before the rules looks "
                               "like: %s" % (",".join(p.get("now_detects") or []), scanner)))
            continue
        if got != sorted(p.get("now_detects") or []):
            refused.append((p, "measured %s, handoff recorded %s; must_detect is compared "
                               "exactly, so this would fail the suite"
                            % (",".join(got), ",".join(sorted(p.get("now_detects") or [])))))
            continue
        applied.append((p, r, shard, got, closed_expect(exp, got, date)))
    return applied, refused, deferred


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--stage-root", help="dir of unpacked shard dirs (each with MANIFEST.json)")
    ap.add_argument("--index", default=os.path.join(HERE, "index.jsonl"))
    ap.add_argument("--pending", default=os.path.join(HERE, "pending-promotions.jsonl"))
    ap.add_argument("--date", default=datetime.date.today().isoformat())
    ap.add_argument("--apply", action="store_true", help="write. Default is a dry run.")
    ap.add_argument("--inject", action="store_true",
                    help="positive control: assert every refusal can actually fire")
    a = ap.parse_args()

    if a.inject:
        return inject()
    if not a.stage_root:
        return ap.error("--stage-root is required (or --inject)")
    if not os.path.exists(SCANNER):
        sys.exit("scanner not found: %s" % SCANNER)

    header, pend = read_pending(a.pending)
    index = {r["sha256"]: r for r in read_jsonl(a.index)}
    applied, refused, deferred = adjudicate(pend, index, a.stage_root, SCANNER, a.date)

    print("scanner      : %s" % SCANNER)
    print("pending rows : %d" % len(pend))
    print("to promote   : %d" % len(applied))
    print("refused      : %d" % len(refused))
    print("deferred     : %d  (blocker unresolved; not this tool's to resolve)" % len(deferred))
    if refused:
        print()
        print("=== REFUSED ===")
        for p, why in refused:
            print("  %s  %s" % (p["sha256"][:12], why))
    if deferred:
        print()
        print("=== deferred, by reason ===")
        byreason = {}
        for p, why in deferred:
            byreason.setdefault(why, []).append(p)
        for why, ps in sorted(byreason.items(), key=lambda x: -len(x[1])):
            print("  %4d  %s" % (len(ps), why[:100]))
    if applied:
        print()
        print("=== promoting ===")
        byrule = {}
        for p, r, shard, got, _ in applied:
            byrule.setdefault((shard, ",".join(got)), 0)
            byrule[(shard, ",".join(got))] += 1
        for (shard, rules), n in sorted(byrule.items()):
            print("  %4d  %-30s now detect %s" % (n, shard, rules))

    if not a.apply:
        print()
        print("(dry run: nothing written. Pass --apply.)")
        return 1 if refused else 0

    done = {p["sha256"] for p, _, _, _, _ in applied}
    newexp = {p["sha256"]: exp for p, _, _, _, exp in applied}

    # Re-read inside the lock, immediately before writing. The rows read above are a
    # decision input; they are NOT what gets written. A full-file rewrite built on a read
    # taken outside the lock is how another writer's rows disappear with every gate still
    # passing (indexio.py).
    with index_lock(a.index):
        rows = read_jsonl(a.index)
        n = 0
        for r in rows:
            if r["sha256"] in newexp:
                r["expect"] = newexp[r["sha256"]]
                n += 1
        if n != len(done):
            sys.exit("refusing to write: %d rows to promote but %d found on re-read; the "
                     "index changed under us" % (len(done), n))
        write_jsonl_atomic(a.index, rows)
    print()
    print("index        : %d rows updated in %s" % (n, a.index))

    with index_lock(a.pending):
        _, cur = read_pending(a.pending)
        left = [p for p in cur if p["sha256"] not in done]
        if left:
            tmp = a.pending + ".new"
            with open(tmp, "w", encoding="utf-8") as fh:
                fh.write("\n".join(header) + "\n")
                for p in left:
                    fh.write(json.dumps(p, sort_keys=True) + "\n")
            os.replace(tmp, a.pending)
            print("pending      : %d applied and removed, %d rows still owed"
                  % (len(cur) - len(left), len(left)))
        else:
            os.unlink(a.pending)
            print("pending      : last row applied; %s removed" % a.pending)
    return 0


def inject():
    """Positive control. Every branch below is a refusal that has never fired in anger,
    which AGENTS.md says is not yet a check. Each case breaks exactly one input and
    asserts the matching refusal comes back - including the stale-binary case, which is
    the one that would otherwise report a plausible zero."""
    import shutil, tempfile
    tmp = tempfile.mkdtemp(prefix="promote-pending-inject.")
    fails = []
    try:
        blob = b"<?php eval($_POST['x']);"
        sha = hashlib.sha256(blob).hexdigest()
        stage = os.path.join(tmp, "stage", "shard-001")
        os.makedirs(os.path.join(stage, "samples"))
        open(os.path.join(stage, "samples", "s.php"), "wb").write(blob)
        json.dump([{"name": "f--%s" % sha[:8], "file": "samples/s.php", "sha256": sha,
                    "source_sha256": sha, "size": len(blob), "masked": False}],
                  open(os.path.join(stage, "MANIFEST.json"), "w"))
        root = os.path.join(tmp, "stage")

        row = {"sha256": sha, "verdict": "malicious", "publishable": True,
               "family": "f", "expect": {"known_miss": True, "known_miss_reason": "no rule fires",
                                         "must_detect": [], "must_not_detect": []}}
        pend = {"sha256": sha, "half": "published", "publish_blockers": [],
                "now_detects": ["ZZZ001"], "family": "f", "verdict": "malicious"}

        # A stand-in scanner, so the control does not depend on a real rule existing.
        def fake(rules):
            p = os.path.join(tmp, "fake-%s.sh" % ("-".join(rules) or "none"))
            body = "#!/bin/sh\n" + "".join('echo "  - %s"\n' % r for r in rules)
            open(p, "w").write(body)
            os.chmod(p, 0o755)
            return p

        good, stale, wrong = fake(["ZZZ001"]), fake([]), fake(["ZZZ002"])

        def run(p, idx, scanner, label, want, bucket="refused"):
            ap_, rf, df = adjudicate([p], idx, root, scanner, "2026-01-01")
            pool = {"refused": rf, "deferred": df}[bucket]
            hit = any(want in why for _, why in pool)
            print("  %-54s %s" % (label, "caught" if hit else "MISSED"))
            if not hit:
                fails.append(label)

        print("=== positive controls: each case must be CAUGHT ===")
        run(dict(pend), {sha: dict(row)}, stale,
            "a binary without the rule (the plausible zero)", "check returned NOTHING")
        run(dict(pend), {sha: dict(row)}, wrong,
            "measured rule set differs from the handoff", "measured ZZZ002")
        run(dict(pend), {}, good,
            "sha256 in no published index row", "in no published index row")
        r2 = dict(row); r2["verdict"] = "unreviewed"
        run(dict(pend), {sha: r2}, good, "index verdict is not malicious", "not malicious")
        r3 = dict(row); r3["publishable"] = False
        run(dict(pend), {sha: r3}, good, "index row is not publishable", "not publishable")
        r4 = dict(row); r4["expect"] = {"must_detect": ["ZZZ001"]}
        run(dict(pend), {sha: r4}, good, "row carries no known_miss to close", "nothing to promote")
        p2 = dict(pend); p2["sha256"] = "0" * 64
        run(p2, {"0" * 64: dict(row, sha256="0" * 64)}, good,
            "bytes are in no staged shard", "no shard in the stage")
        p3 = dict(pend); p3["publish_blockers"] = ["carries identity/secret but no masking"]
        run(p3, {sha: dict(row)}, good, "a blocker is unresolved", "no masking", bucket="deferred")
        p4 = dict(pend); p4["half"] = "local"
        run(p4, {sha: dict(row)}, good,
            "local half but no blocker recorded: an inconsistent handoff", "local half")
        p5 = dict(pend); p5["half"] = "local"
        p5["publish_blockers"] = ["verdict is unreviewed: nothing leaves that state"]
        run(p5, {sha: dict(row)}, good,
            "a deferral names its blocker, not just the half", "verdict is unreviewed",
            bucket="deferred")

        # The negative half: with everything consistent it must PROMOTE, or every
        # "caught" above could be a checker that refuses unconditionally.
        ap_, rf, df = adjudicate([dict(pend)], {sha: dict(row)}, root, good, "2026-01-01")
        ok = len(ap_) == 1 and not rf and not df
        print("  %-54s %s" % ("a consistent row is promoted", "ok" if ok else "FALSE REFUSAL"))
        if not ok:
            fails.append("false refusal on a consistent row")
        else:
            exp = ap_[0][4]
            shape = (exp["must_detect"] == ["ZZZ001"]
                     and exp["closed_known_miss"]["rule"] == "ZZZ001"
                     and exp["closed_known_miss"]["was"] == "no rule fires"
                     and "known_miss" not in exp)
            print("  %-54s %s" % ("promoted expect has the closed_known_miss shape",
                                  "ok" if shape else "WRONG: %s" % exp))
            if not shape:
                fails.append("closed_known_miss shape")

        # The multi-rule branch has no instance in the corpus yet, so it is exercised
        # here rather than discovered by the first row that needs it.
        multi = closed_expect({"known_miss": True, "known_miss_reason": "x"},
                              ["BBB002", "AAA001"], "2026-01-01")
        ok = (multi["must_detect"] == ["AAA001", "BBB002"]
              and multi["closed_known_miss"]["rules"] == ["AAA001", "BBB002"]
              and "rule" not in multi["closed_known_miss"])
        print("  %-54s %s" % ("two rules close a miss: a list, not a joined string",
                              "ok" if ok else "WRONG: %s" % multi))
        if not ok:
            fails.append("multi-rule shape")

        print()
        print("cases: 13 · passed: %d · failed: %d" % (13 - len(fails), len(fails)))
        for f in fails:
            print("FAIL:", f)
        return 1 if fails else 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except LockBusy as exc:
        sys.exit(str(exc))
