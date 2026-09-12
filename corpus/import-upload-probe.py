#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Import the operator-reviewed subset of a single-source upload-endpoint probe.

WHAT THIS COLLECTION IS, AND WHY IT IS HANDLED APART
----------------------------------------------------
An automated vulnerability scanner spent about three hours probing one hosting customer's
file-upload endpoint on 2026-09-08 and left a directory of artefacts, distinguishable from
genuine uploads by an id suffix the upload handler appends. The operator collected it, deleted
every real user upload swept in with it, swept the remainder for personal data (none: the only
addresses are at RFC 2606 reserved domains, the attacker's own synthetic data), and read it.
See the gitignored collection note for the full provenance.

Every row this writes therefore carries a `collection_frame`: one host, one directory, one
scanner, one window. A rate over these rows measures that source and never the scanner, and
`make-summary.malicious_by_collection_frame` reads the frame back so the movement a collection
causes is attributable in the denominator file rather than only in a changelog. This is
CORPUS_PLAN section 11's thirteenth instance, recorded at write time because by the time
anyone re-derives the frame the pool has changed.

WHAT IT IMPORTS, AND WHAT IT DELIBERATELY DOES NOT
--------------------------------------------------
The operator's review selected two byte-defined kinds out of the collection, keyed here by
sha256 (a content hash names nothing):

  * webshells the scanner detects today - real PHP command-execution shells. `expect.must_detect`
    is MEASURED here, under a name no name-rule reads, never asserted;
  * `.htaccess` files whose directive maps a data-file extension to the PHP handler - a real
    technique no rule here detects. These are recorded misses (`rule-gap`). NO RULE is written
    for them this round: a rule written to catch the sample that taught you the technique is
    measured on its own training data (CORPUS_PLAN section 11).

Everything else in the collection - probe payloads that are inert by content, and hostile
FILENAMES - is left out. The malice of a hostile filename lives in the name, which is
content-addressed away here and can itself be a live payload; that population is a name corpus,
already recorded in the gitignored hostile-filename note and the material the FN rules were
measured against, and importing it as content fixtures would measure those rules on their own
training data.

WHERE IT WRITES, AND WHAT IT REFUSES
------------------------------------
It appends to the LOCAL half only, under `indexio.index_lock` with a re-read inside the lock
(AGENTS.md, Index writes). Every row is `verdict: malicious` but `review.human_confirmed:
false` with a `local_only` hold: nothing leaves the unreviewed state, or reaches the published
half, without a human - this tool proposes, a person confirms with `publish-rows.py`.

It refuses rather than guessing:

  * bytes on disk that do not hash to the curated sha256;
  * a webshell the scanner does not detect under a neutral name (its `must_detect` cannot be
    measured, so the classification is wrong);
  * an `.htaccess` a content rule DOES fire on (it is not a miss, so `rule-gap` would be false);
  * bytes carrying any identifier from any pseudonym map (they would need masking and are not
    `clean`).

  corpus/import-upload-probe.py --collection DIR [--write]
  corpus/import-upload-probe.py --inject

`DIR` is the out-of-repo collection directory. This file is tracked and names it nowhere; the
customer label lives only in the gitignored map beside the collection.
"""
import argparse, hashlib, importlib.util, json, os, re, shutil, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
from indexio import read_jsonl, write_jsonl_atomic, index_lock            # noqa: E402
import gate_provenance                                                     # noqa: E402

LOCAL = os.path.join(HERE, "local", "index-local.jsonl")
SCANNER = os.environ.get("LYXBOSA_BIN") or os.path.join(ROOT, "build", "lyxbosa")

REVIEW_BY = "agent:claude-opus-4-8"
REVIEW_DATE = "2026-09-12"
AWAITING = ("verdict proposed 2026-09-12 from the operator's collection notes; awaiting human "
            "confirmation before publication")

# The sampling frame, recorded on every row. Measured, not implied.
FRAME_ID = "upload-probe-2026-09-12"
SOURCE_DISTINCT_BLOBS = 56      # distinct sha256 in the collection (267 files)
SOURCE_FILES = 267


def _vcm():
    spec = importlib.util.spec_from_file_location(
        "verify_content_mask", os.path.join(HERE, "verify-content-mask.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


VCM = _vcm()


def all_maps():
    """Every pseudonym map on this machine: the two required, and any collection's own under
    trail-data/incoming/*/private/. Discovered by glob so this tracked file names no source -
    a collection's directory carries its customer label and this file must not."""
    import glob
    required = [VCM.INCIDENT_MAP, VCM.LEGACY_MAP]
    found = sorted(glob.glob(os.path.join(
        ROOT, "trail-data", "incoming", "*", "private", "*-mapping.json")))
    seen, out = set(), []
    for p in required + found:
        ap = os.path.abspath(p)
        if ap not in seen and os.path.exists(ap):
            seen.add(ap)
            out.append(ap)
    return out

# The operator's review, keyed by sha256 - a content hash names nothing. `shape` describes the
# sample by its form and quotes no payload byte and no filename (AGENTS.md: describe collisions,
# do not quote them; a name here can be a live shell). `technique` and `family` are the review's;
# `must_detect` for a webshell is MEASURED below, never taken from here.
CURATED = {
    # --- webshells the scanner detects (real PHP command execution) ---
    "00e43e4de88e95b11ba7e88ab0baac7c6eaac8d9e002a609a64fc3be46d3d74c": {
        "kind": "webshell", "family": None, "technique": ["command-exec"],
        "shape": "a minimal single-statement PHP webshell passing one request parameter to a "
                 "shell-exec sink"},
    "e18cf8bb8d52e31b1d8d56ab80bb7366a2ebbb462f70ee33316f08d25fc62762": {
        "kind": "webshell", "family": None,
        "technique": ["command-exec", "gif89a-magic-prefix"],
        "shape": "a PHP webshell prefixed with an image-format magic signature, passing a "
                 "request parameter to a command sink"},
    "162b1162490269f2540c9d52c9733c1f2220b70ef9c20dca9b7175664de21457": {
        "kind": "webshell", "family": None, "technique": ["command-exec"],
        "shape": "a minimal PHP webshell carrying a comment marker, passing one request "
                 "parameter to a shell-exec sink"},
    "2fa74eb20b6ac9adab8826871893a6f7594225de671fb1915ef3534cdb4fd6ea": {
        "kind": "webshell", "family": None, "technique": ["command-exec"],
        "shape": "a minimal PHP webshell prefixing its output with a marker, passing a request "
                 "parameter to a shell-exec sink"},
    "712cd4e26c02e76a9a3a168b303d05321d36468232506a5edf76d6dcff23cf7c": {
        "kind": "webshell", "family": None, "technique": ["command-exec", "request-gate"],
        "shape": "a PHP arbitrary-command proof-of-concept gated on a request parameter, "
                 "passing it to a system sink and echoing the output"},
    # --- .htaccess handler-mapping: a real technique no rule detects (recorded miss) ---
    "b895c44c0601c7fce3922c422e38af93832244884ed5a921d7a4dda49fffb394": {
        "kind": "htaccess", "family": "htaccess-data-extension-executable",
        "technique": ["htaccess-data-extension-executable"],
        "shape": "an .htaccess directive mapping an archive-file extension to the PHP handler, "
                 "so an uploaded archive-named file executes as PHP"},
    "5fbf2ee95866050a3091037b0c9cc764d9c626a567a20988fe8d25e1ea3c8772": {
        "kind": "htaccess", "family": "htaccess-data-extension-executable",
        "technique": ["htaccess-data-extension-executable"],
        "shape": "an .htaccess directive mapping a database-file extension to the PHP handler, "
                 "so an uploaded database-named file executes as PHP"},
}

# The name each kind's bytes are measured under - one a name rule cannot read, so a name finding
# on the stored (hostile) copy cannot be mistaken for a finding about the bytes. `.htaccess` is
# its own safe name.
NEUTRAL_NAME = {"webshell": "sample.php", "htaccess": ".htaccess"}


def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()


def check(path):
    """(rules, min_severity) for the bytes at `path`, or raise if the read is not proven."""
    r = subprocess.run([SCANNER, "check", "--no-ansi", path], capture_output=True)
    pairs = re.findall(rb"\[(\w+)\] .*? - ([A-Z]+\d+)", r.stdout)
    proven = (r.returncode in (0, 2)) and (bool(pairs) or b"No matches found" in r.stdout)
    if not proven:
        raise RuntimeError("scanner did not prove it read the sample (rc=%d)" % r.returncode)
    rules = sorted({p[1].decode() for p in pairs})
    order = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0}
    sevs = [p[0].decode().upper() for p in pairs]
    top = max(sevs, key=lambda s: order.get(s, -1)) if sevs else None
    return rules, (top.lower() if top else None)


def measure(path, kind):
    """(rules, min_severity) over the bytes, under a name no name-rule reads."""
    tmp = tempfile.mkdtemp(prefix="import-upload-probe-")
    try:
        staged = os.path.join(tmp, NEUTRAL_NAME[kind])
        shutil.copyfile(path, staged)
        return check(staged)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def carries_identifier(data):
    """True if any pseudonym map's identifier appears in the bytes (would need masking)."""
    ids, keep = VCM.load_ids(all_maps())
    ok, _res = VCM.gate(data, ids, keep)
    return not ok


def classify(kind, rules):
    """(expect, family_ok_refusal). expect is the row's assertion; the refusal is None when the
    measurement agrees with the operator's kind, else the reason it does not."""
    if kind == "webshell":
        if not rules:
            return None, ("classified a detected webshell, but no rule fires on the bytes "
                          "under a neutral name")
        return {"must_detect": rules, "must_not_detect": []}, None
    # htaccess handler-mapping: a recorded miss. A content rule firing would make it not a miss.
    if rules:
        return None, ("classified a recorded miss, but a content rule fires on the bytes: %s"
                      % ",".join(rules))
    return {"must_detect": [], "must_not_detect": [], "known_miss": True,
            "known_miss_kind": "rule-gap",
            "known_miss_reason": ("no content rule fires; the .htaccess handler-mapping "
                                  "technique is undetected. Measured per sample under a name "
                                  "no name-rule reads.")}, None


def frame_block(rows_recorded):
    return {
        "single_source": True,
        "frame_id": FRAME_ID,
        "kind": "single-source-collection",
        "source": ("an automated vulnerability scanner probing one host's file-upload "
                   "endpoint; one directory, one ~3-hour window on 2026-09-08"),
        "source_distinct_blobs": SOURCE_DISTINCT_BLOBS,
        "source_files": SOURCE_FILES,
        "rows_recorded": rows_recorded,
        "note": ("every row under this frame is from one source; a detection rate over them "
                 "measures that source, not the scanner. See CORPUS_PLAN section 11."),
    }


def build_row(sha, data, count, stored_exts, spec, rules, min_sev, frame):
    row = {
        "sha256": sha,
        "size": len(data),
        "count": count,
        "verdict": "malicious",
        "sensitivity": ["clean"],
        "bucket": "upload-probe/incoming",
        "collected_from": ["upload-endpoint-probe"],
        "discovered_by": ["operator-report"],
        "discovered_by_reason": ("left by an automated vulnerability scanner probing a "
                                 "file-upload endpoint; collected as a directory, not selected "
                                 "by a scan"),
        "attacker_written": True,
        "collection_frame": frame,
        "origin": {
            "collection": FRAME_ID,
            "path": "/%s/%s" % (FRAME_ID, sha[:12]),
            "stored_extensions": stored_exts,
            "note": ("hostile upload filename withheld: an upload-probe name can carry a live "
                     "shell payload; the sample is identified by sha256"),
        },
        "technique": spec["technique"],
        "verdict_reason": spec["shape"] + ", left by an upload-endpoint probe",
        "reason": "upload-endpoint-probe-review",
        "review": {"by": REVIEW_BY, "date": REVIEW_DATE, "human_confirmed": False,
                   "basis": "operator collected, deleted the real uploads, swept for personal "
                            "data and read the sample; agent transcribed the ruling"},
        "local_only": AWAITING,
    }
    if spec["family"]:
        row["family"] = spec["family"]
    expect, refusal = classify(spec["kind"], rules)
    if refusal:
        return None, refusal
    row["expect"] = expect
    if spec["kind"] == "webshell":
        if min_sev:
            row["expect"]["min_severity"] = min_sev
    else:
        row["expect"]["known_miss_kind_measured"] = {
            "date": REVIEW_DATE, "binary": os.path.relpath(SCANNER, ROOT),
            "binary_sha256_12": _binary_id(), "rules": [], "ships_as_bytes": False}
    return row, None


def _binary_id():
    return hashlib.sha256(open(SCANNER, "rb").read()).hexdigest()[:12]


def resolve(collection):
    """{sha256: (bytes, count, sorted stored extensions)} over the curated shas, by hashing
    every file in `collection`. Paths are passed as argument lists and never to a shell; a
    filename in this collection can be a live shell payload."""
    found = {}
    for name in os.listdir(collection):
        p = os.path.join(collection, name)
        if os.path.islink(p) or not os.path.isfile(p):
            continue
        data = open(p, "rb").read()
        h = sha256_bytes(data)
        if h not in CURATED:
            continue
        ext = os.path.splitext(name)[1].strip()
        cur = found.get(h)
        if cur is None:
            found[h] = [data, 1, {ext} if ext else set()]
        else:
            cur[1] += 1
            if ext:
                cur[2].add(ext)
    return {h: (v[0], v[1], sorted(v[2])) for h, v in found.items()}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--collection", help="the out-of-repo collection directory")
    ap.add_argument("--write", action="store_true", help="append to the local index")
    ap.add_argument("--inject", action="store_true", help="controls, both directions")
    a = ap.parse_args()

    if a.inject:
        return inject()
    if not a.collection:
        return ap.error("--collection is required (or --inject)")
    if not os.path.exists(SCANNER):
        sys.exit("scanner not built: %s (cmake --build build)" % SCANNER)

    located = resolve(a.collection)
    missing = sorted(set(CURATED) - set(located))
    if missing:
        sys.exit("REFUSE: %d curated sha256 not found in the collection: %s"
                 % (len(missing), ", ".join(s[:12] for s in missing)))

    frame = frame_block(len(CURATED))
    rows, refused = [], []
    for sha in sorted(CURATED):
        data, count, stored_exts = located[sha]
        if sha256_bytes(data) != sha:
            refused.append((sha, "bytes do not hash to the curated sha256")); continue
        if carries_identifier(data):
            refused.append((sha, "carries a pseudonym-map identifier; not clean")); continue
        # measure on a temp copy, under a neutral name
        tmp = tempfile.mkdtemp(prefix="import-upload-probe-")
        try:
            src = os.path.join(tmp, "blob")
            open(src, "wb").write(data)
            rules, min_sev = measure(src, CURATED[sha]["kind"])
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        row, refusal = build_row(sha, data, count, stored_exts, CURATED[sha], rules,
                                 min_sev, frame)
        if refusal:
            refused.append((sha, refusal)); continue
        rows.append(row)

    print("collection curated shas : %d" % len(CURATED))
    print("resolved on disk        : %d" % len(located))
    print("rows built              : %d" % len(rows))
    for r in rows:
        exp = r["expect"]
        got = exp.get("must_detect") or (["known_miss:" + exp.get("known_miss_kind", "?")]
                                         if exp.get("known_miss") else [])
        print("  %s  size=%-4d count=%-2d  %s" % (r["sha256"][:12], r["size"], r["count"],
                                                  ",".join(got)))
    if refused:
        print("refused:")
        for sha, why in refused:
            print("  %s  %s" % (sha[:12], why))
        sys.exit("REFUSE: %d sample(s) did not classify as curated" % len(refused))

    if not a.write:
        print("\ndry run: pass --write to append to the local index")
        return 0

    # Lock across the whole read-modify-write; re-read INSIDE the lock (AGENTS.md).
    with index_lock(LOCAL):
        current = read_jsonl(LOCAL)
        have = {r["sha256"] for r in current}
        fresh = [r for r in rows if r["sha256"] not in have]
        skipped = len(rows) - len(fresh)
        if skipped:
            print("skipped %d row(s) already in the local half" % skipped)
        write_jsonl_atomic(LOCAL, current + fresh)
        print("local index: %d -> %d rows (+%d)" % (len(current), len(current) + len(fresh),
                                                     len(fresh)))
    print("\nnext: shard-gate.py corpus/local/index-local.jsonl --fix, then make-summary.py")
    return 0


# --------------------------------------------------------------------------- controls
def inject():
    """Both directions on the classification and the frame. Reads no collection and writes
    nothing: synthetic bytes are enough for the driver's own decisions."""
    fails, cases = [], []

    def case(label, ok):
        cases.append(label)
        print("  %-70s %s" % (label, "ok" if ok else "WRONG"))
        if not ok:
            fails.append(label)

    print("=== classify(): the measurement must agree with the operator's kind ===")
    exp, ref = classify("webshell", ["RCE008"])
    case("a detected webshell yields must_detect from the measured rules",
         ref is None and exp["must_detect"] == ["RCE008"])
    _, ref = classify("webshell", [])
    case("  ...a webshell nothing detects is REFUSED, not imported silently", ref is not None)
    exp, ref = classify("htaccess", [])
    case("an undetected .htaccess yields a rule-gap known_miss",
         ref is None and exp["known_miss"] and exp["known_miss_kind"] == "rule-gap")
    case("  ...and specifically asserts no rule", exp["must_detect"] == [])
    _, ref = classify("htaccess", ["BD008"])
    case("  ...an .htaccess a rule DOES fire on is REFUSED (not a miss)", ref is not None)

    print()
    print("=== the collection frame is recorded, single-source, and counts its rows ===")
    fr = frame_block(7)
    case("frame claims single_source", fr["single_source"] is True)
    case("  ...carries a frame_id", fr["frame_id"] == FRAME_ID)
    case("  ...records how many rows were written under it", fr["rows_recorded"] == 7)
    # The row a webshell produces lands under the frame, clean, malicious, held local.
    spec = {"kind": "webshell", "family": None, "technique": ["command-exec"], "shape": "x"}
    row, ref = build_row("a" * 64, b"<?php x", 1, [".php"], spec, ["RCE008"], "high", fr)
    case("a built row carries the collection_frame verbatim",
         ref is None and row["collection_frame"] == fr)
    case("  ...is malicious, clean, and held local pending confirmation",
         row["verdict"] == "malicious" and row["sensitivity"] == ["clean"]
         and row.get("local_only") and row["review"]["human_confirmed"] is False)
    case("  ...records no hostile filename, only a sha-keyed synthetic path",
         row["origin"]["path"].endswith("a" * 12) and "filename withheld"
         in row["origin"]["note"])
    # make-summary reads the frame back: prove the block is the shape it expects.
    import importlib.util as _il
    _s = _il.spec_from_file_location("ms", os.path.join(HERE, "make-summary.py"))
    ms = _il.module_from_spec(_s); _s.loader.exec_module(ms)
    case("make-summary reads this frame as single-source under its id",
         ms.collection_frame_id(row) == FRAME_ID)
    part = ms.malicious_by_collection_frame([row], [])
    b = part["single_source"].get(FRAME_ID, {})
    case("  ...and counts it: reviewed 1, detected 1, indexed 1",
         b.get("reviewed") == 1 and b.get("detected") == 1 and b.get("rows_indexed") == 1)
    case("  ...rows_recorded 7 vs 1 indexed flags the mismatch",
         b.get("recorded_rows_matches_indexed") is False)

    print()
    print("cases: %d · passed: %d · failed: %d"
          % (len(cases), len(cases) - len(fails), len(fails)))
    for f in fails:
        print("FAIL:", f)
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
