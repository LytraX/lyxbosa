#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Run §5.6's three checks over a batch of samples and record the result on their rows.

The masking pass is three independent checks and this is the thing that runs all three, in
the order §5.6 gives, and refuses to record a pass it did not measure:

  1. mask the bytes            `content_mask.py`, length-preserving by construction
  2. plaintext gate            `verify-content-mask.py`, shares no regex with the masker
  3. encoded-layer gate        the same gate, over every statically decoded layer
  4. detection parity          `lyxbosa check` PER SAMPLE, before and after

Each has caught something the others did not, so a row is only recorded as masked when all
of them are recorded, and a sample that fails any of them keeps its blocker.

WHY PARITY IS MEASURED THE WAY IT IS
------------------------------------
§5.6: "Parity must be measured with `check` per sample, never inferred from a batch scan.
This is a requirement, not a preference."  A batch scan cannot distinguish *the walker
declined to open this file* from *the scanner opened it and found nothing*, and during the
first masking pass two of fourteen flagged parity changes were masked copies whose extension
was not in the include allow-list.  They were never scanned at all and were indistinguishable
in the report from twelve archives whose detection had genuinely been destroyed.

So every `check` here is per sample, and every one of them carries a READ PROOF: an empty
rule set is only accepted as "scanned and clean" when the scanner also said so in as many
words.  An unproven read is a hard refusal, never an empty result.

And parity is measured between two files with the SAME NAME - the original bytes and the
masked bytes, staged side by side under identical basenames - so a filename-dependent rule
cannot appear as a masking effect.  The original is additionally measured at its collection
path, and any disagreement between the two is reported as a filename effect rather than
folded into the parity answer (§8: every count difference carries an attributed cause).

WHAT IT WILL NOT DO
-------------------
It does not compute `publishable`.  `shard-gate.py` is "the only thing allowed to compute it,
so the rule lives in exactly one place"; this writes `masking` and nothing else, and the gate
is run afterwards to recompute the boolean and the blockers from it.

It does not touch a row whose masking is recorded as not applicable.  §5.5: an archive
container is excluded from content masking entirely, because a length-preserving substitution
inside a tar header or a gzip stream does not rename a thing, it corrupts the container, and
every member-level detection disappears at once - measured, not predicted.

The worklist maps sha256 to a path on this machine and is therefore out of repo, like the
map.  This file is tracked and names nothing.
"""
import argparse, collections, hashlib, json, os, re, shutil, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

import incident_mask                                                     # noqa: E402
import content_mask                                                      # noqa: E402
from indexio import read_jsonl, write_jsonl_atomic, index_lock           # noqa: E402

import importlib.util                                                    # noqa: E402
_spec = importlib.util.spec_from_file_location(
    "verify_content_mask", os.path.join(HERE, "verify-content-mask.py"))
VCM = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(VCM)

SCANNER = os.environ.get("LYXBOSA_BIN") or os.path.join(ROOT, "build-release", "lyxbosa")


class NotRead(RuntimeError):
    """The scanner did not demonstrate that it read the file."""


def check_rules(path):
    """(rules, binary) for one file, or raise if the read cannot be proven.

    Exit codes are 0 = no matches, 1 = error, 2 = matches found.  "No findings" is accepted
    only when the scanner said "No matches found" about this file; an error, a crash or a
    silent skip raises instead of returning an empty set, because an empty set that means
    "not scanned" is exactly the failure §5.6 exists to close.
    """
    r = subprocess.run([SCANNER, "check", "--no-ansi", path], capture_output=True)
    rules = sorted(set(x.decode() for x in re.findall(rb"- ([A-Z]+\d+)", r.stdout)))
    proven = (r.returncode in (0, 2)) and (bool(rules) or b"No matches found" in r.stdout)
    if not proven:
        raise NotRead("scanner did not prove it read %s (rc=%d, stdout=%r)"
                      % (os.path.basename(path), r.returncode, r.stdout[:160]))
    return rules


def binary_id():
    h = hashlib.sha256(open(SCANNER, "rb").read()).hexdigest()[:12]
    return {"path": os.path.relpath(SCANNER, ROOT), "sha256_12": h}


def build_vocabulary(roots):
    """The collision reference.  A missing tree is a hard failure, never a quiet skip.

    §8 records `command -v zstd tar jq` reporting success while zstd was absent: "a check
    that looks like it verifies three things and verifies only some of them is worse than no
    check, because it converts an absent dependency into a silent fallback."  The vocabulary
    is what demotes an identifier that is also an ordinary stock-CMS token to positional
    masking, so running without it silently widens the masker.
    """
    vocab = set()
    for r in roots:
        if not os.path.isdir(r):
            sys.exit("vocabulary root %s is not a directory. It is what stops an identifier "
                     "that is also a stock CMS token from being rewritten inside working "
                     "code; running without it would silently widen the masker." % r)
        before = len(vocab)
        vocab |= incident_mask.vocabulary(r)
        if len(vocab) == before:
            sys.exit("vocabulary root %s contributed no tokens; refusing to continue on an "
                     "empty collision reference" % r)
    return vocab


def stage_pair(stage, sha, src, masked_bytes):
    """The original and the masked bytes under identical basenames, in sibling directories.

    Identical names on both sides so that a filename-dependent rule cannot show up as a
    masking effect.  The extension is carried over from the collected file, because it is
    the scanner's include allow-list that made two masked copies unscannable during the
    first pass and indistinguishable from destroyed detection.
    """
    ext = os.path.splitext(src)[1]
    name = sha[:12] + ext
    before_dir, after_dir = os.path.join(stage, "before"), os.path.join(stage, "after")
    os.makedirs(before_dir, exist_ok=True)
    os.makedirs(after_dir, exist_ok=True)
    b = os.path.join(before_dir, name)
    a = os.path.join(after_dir, name)
    shutil.copyfile(src, b)
    with open(a, "wb") as fh:
        fh.write(masked_bytes)
    return b, a


def process(row, src, m, vocab, stage, mask_ipv4=False, mask_hex=False):
    """One sample, all four steps.  Returns the `masking` block to store, and a work note."""
    raw = open(src, "rb").read()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != row["sha256"]:
        return None, {"result": "refused", "why": "bytes on disk do not hash to the row"}

    masked, detail = content_mask.mask_sample(raw, m, mask_ipv4=mask_ipv4,
                                              vocabulary=vocab, mask_hex_digests=mask_hex)
    if len(masked) != len(raw):
        return None, {"result": "refused", "why": "masking changed the sample's length"}

    before_path, after_path = stage_pair(stage, row["sha256"], src, masked)
    try:
        rules_origin = check_rules(src)
        rules_before = check_rules(before_path)
        rules_after = check_rules(after_path)
    except NotRead as exc:
        return None, {"result": "refused", "why": str(exc)}

    ids, keep = VCM.load_ids([incident_mask.MAP_PATH, VCM.LEGACY_MAP])
    _, gated = VCM.gate(masked, ids, keep)
    secret_ok, secret_res = VCM.secret_gate(raw, masked)

    # A row tagged `secret` whose credential-shaped literals came through unchanged has not
    # been masked in the sense its tag demands, whatever the identifier gates say. Recording
    # `applied: true` there would clear the blocker on a gate that never looked at secrets -
    # SOURCES.md's "a gate that trusts a field is only as good as whatever wrote the field",
    # one level down. The row keeps its blocker and the finding is returned.
    if "secret" in (row.get("sensitivity") or []) and not secret_ok:
        return None, {"result": "refused",
                      "why": "secret gate: %d credential-shaped literal(s) survived masking "
                             "unchanged (shapes: %s)"
                             % (secret_res["secret_literals_carried_over"],
                                ",".join(secret_res["shapes_carried_over"]))}

    survived = rules_after == rules_before
    block = {
        "applied": True,
        "c2_kept": True,
        "changes": detail["changes"],
        "change_kinds": detail["change_kinds"],
        "length_preserved": True,
        "masked_sha256": hashlib.sha256(masked).hexdigest(),
        "plaintext_gate": gated["plaintext_gate"],
        "encoded_layer_gate": gated["encoded_layer_gate"],
        "detection_survived": survived,
        "rules_before": rules_before,
        "rules_after": rules_after,
        "gate_categories": {k: gated[k] for k in
                            ("plaintext_finding", "encoded_layer_finding") if k in gated},
        "secret_gate": secret_res["secret_gate"],
        "secret_literals": {k: secret_res[k] for k in
                            ("secret_literals_before", "secret_literals_after",
                             "secret_literals_carried_over", "shapes_remaining")},
        "measured_with": binary_id(),
    }
    if gated["encoded_layer_gate"] != "PASS":
        block["encoded_layer_finding"] = gated["encoded_layer_finding"]
    if detail["encoded_regions"]:
        block["encoded_regions"] = _tally(detail["encoded_regions"])
    if detail["skipped"]:
        block["not_masked"] = detail["skipped"]

    note = {"result": "ok",
            "filename_effect": sorted(set(rules_origin) ^ set(rules_before)),
            "layers_decoded": gated["layers_decoded"],
            "layer_methods": gated["layer_methods"]}
    return block, note


def _tally(regions):
    c = collections.Counter("%s:%s" % (r["region"], r["action"]) for r in regions)
    return dict(c)


def apply_rows(index_path, blocks):
    """Write `masking` onto the named rows, and nothing else.

    The lock is held across the whole read-modify-write and the rows are re-read INSIDE it.
    Reading first and writing later is how another session's appends disappear with every
    gate still passing - `indexio`'s docstring, paid for on 2026-09-04.
    """
    with index_lock(index_path):
        rows = read_jsonl(index_path)
        before = len(rows)
        touched = 0
        for r in rows:
            b = blocks.get(r.get("sha256"))
            if b is None:
                continue
            r["masking"] = b
            touched += 1
        if len(rows) != before:
            sys.exit("row count moved %d -> %d; a masking pass must not add or drop rows"
                     % (before, len(rows)))
        if touched != len(blocks):
            sys.exit("expected to touch %d row(s), found %d in %s"
                     % (len(blocks), touched, index_path))
        write_jsonl_atomic(index_path, rows)
    return touched


# ---------------------------------------------------------------------------------------
# Controls.  The driver's own failure modes are not the masker's and not the gate's: it can
# record a pass it did not measure, and it can read an unscanned file as a clean one.
# ---------------------------------------------------------------------------------------
def inject(m, vocab, stage):
    """Prove the driver refuses in each of the three ways it is supposed to refuse."""
    import tempfile
    failures = []
    tmp = tempfile.mkdtemp(prefix="mask-samples-inject.", dir=stage)

    # 1. Detection parity must be able to say `false`.  A "masked" output that destroys the
    #    sample is the twelve-archives case, and the plaintext gate passes on all of them.
    src = os.path.join(tmp, "a.php")
    with open(src, "wb") as fh:
        fh.write(b"<?php eval(base64_decode($_POST['x'])); // " + b"A" * 400)
    real_rules = check_rules(src)
    destroyed = os.path.join(tmp, "destroyed.php")
    with open(destroyed, "wb") as fh:
        fh.write(b"<?php // " + b"A" * (os.path.getsize(src) - 9))
    after = check_rules(destroyed)
    ok = bool(real_rules) and after != real_rules
    print("   +  %-46s %s" % ("parity can report a destroyed detection",
                              "reports a change" if ok else "MISSED"))
    if not ok:
        failures.append("parity cannot see a destroyed detection")

    # 2. The read proof must refuse rather than return an empty set.
    try:
        check_rules(os.path.join(tmp, "does-not-exist.php"))
        print("   +  %-46s %s" % ("an unreadable file is refused", "RETURNED EMPTY"))
        failures.append("an unreadable file returned an empty rule set")
    except NotRead:
        print("   +  %-46s %s" % ("an unreadable file is refused", "refused"))

    # 3. A row whose bytes do not hash to it is refused rather than masked.
    row = {"sha256": "0" * 64, "size": 1}
    block, note = process(row, src, m, vocab, tmp)
    ok = block is None and note["result"] == "refused"
    print("   +  %-46s %s" % ("bytes that do not hash to the row are refused",
                              "refused" if ok else "ACCEPTED"))
    if not ok:
        failures.append("a mismatched sha256 was accepted")

    # 4. And the negative half: an honest sample must come back with parity intact.
    row = {"sha256": hashlib.sha256(open(src, "rb").read()).hexdigest(), "size": 1}
    block, note = process(row, src, m, vocab, tmp)
    ok = block is not None and block["detection_survived"] and block["length_preserved"]
    print("   -  %-46s %s" % ("an unchanged sample keeps its detection",
                              "parity holds" if ok else "REPORTED A CHANGE"))
    if not ok:
        failures.append("parity reported a change on an unmodified sample")

    shutil.rmtree(tmp, ignore_errors=True)
    print()
    if failures:
        print("FAIL: the driver got %d of its own controls wrong: %s"
              % (len(failures), ", ".join(failures)))
        return 1
    print("the driver refuses on a destroyed detection, on an unproven read and on a hash "
          "mismatch, and stays quiet on an honest sample")
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--worklist", help="jsonl of {sha256, path} for the samples to mask")
    ap.add_argument("--index", default=os.path.join(HERE, "local", "index-local.jsonl"))
    ap.add_argument("--stage", required=True, help="directory for the before/after copies")
    ap.add_argument("--vocabulary", action="append", default=[],
                    help="stock CMS tree, repeatable. Required to mask: see "
                         "build_vocabulary(). NOT required by --inject, which tests the "
                         "driver's refusals and never the collision reference")
    ap.add_argument("--map", default=incident_mask.MAP_PATH)
    ap.add_argument("--mask-ipv4", action="store_true",
                    help="also mask dotted quads outside comments. Off by default because "
                         "every candidate in this collection was adjudicated as a section "
                         "number or a reserved address; turn it on when a round has real ones")
    ap.add_argument("--mask-hex-digests", action="store_true",
                    help="also mask bare hex digests. Off by default: every one adjudicated "
                         "in this collection was an attacker marker, a help-text example or "
                         "a host-binding hash, and no row's secret evidence names one")
    ap.add_argument("--apply", action="store_true", help="write the rows; default is dry run")
    ap.add_argument("--inject", action="store_true")
    ap.add_argument("--json", default=None, help="write the per-sample record here")
    a = ap.parse_args()

    m = incident_mask.load_map(a.map)
    os.makedirs(a.stage, exist_ok=True)
    print("scanner                      : %s" % json.dumps(binary_id()))

    if a.inject:
        # A control suite that cannot run without pointing at a 158,675-file tree is a
        # control that gets skipped, and a skipped control is the state AGENTS.md is about.
        # None of the four cases below is about the vocabulary: they test parity, the read
        # proof and the hash check. So --inject synthesises one and says so. Masking still
        # refuses to run without a real tree, because there the collision reference is the
        # whole point.
        vocab = a.vocabulary and build_vocabulary(a.vocabulary) or {"admin", "index",
                                                                    "upload", "cache"}
        print("stock vocabulary tokens      : %d%s"
              % (len(vocab), "" if a.vocabulary else "  (synthetic; --inject reads no tree)"))
        print()
        return inject(m, vocab, a.stage)

    if not a.vocabulary:
        return ap.error("--vocabulary is required to mask; see build_vocabulary()")
    vocab = build_vocabulary(a.vocabulary)
    print("stock vocabulary tokens      : %d" % len(vocab))

    if not a.worklist:
        return ap.error("--worklist is required unless --inject")
    work = [json.loads(l) for l in open(a.worklist, encoding="utf-8") if l.strip()]
    rows = {r["sha256"]: r for r in read_jsonl(a.index)}
    print("worklist                     : %d" % len(work))

    blocks, notes, refused = {}, {}, []
    for w in work:
        row = rows.get(w["sha256"])
        if row is None:
            refused.append((w["sha256"], "not in %s" % os.path.basename(a.index)))
            continue
        existing = row.get("masking") or {}
        if existing.get("not_applicable_reason"):
            refused.append((w["sha256"], "masking recorded as not applicable"))
            continue
        block, note = process(row, w["path"], m, vocab, a.stage, a.mask_ipv4,
                              a.mask_hex_digests)
        if block is None:
            refused.append((w["sha256"], note["why"]))
            continue
        blocks[w["sha256"]] = block
        notes[w["sha256"]] = note

    tally = collections.Counter()
    for sha, b in blocks.items():
        tally["plaintext " + b["plaintext_gate"]] += 1
        tally["encoded " + b["encoded_layer_gate"]] += 1
        tally["parity " + ("held" if b["detection_survived"] else "CHANGED")] += 1
        tally["secret " + b["secret_gate"]] += 1
        if not b["rules_before"]:
            tally["parity has no power (no detection before)"] += 1
        tally["all three pass" if (b["plaintext_gate"] == "PASS"
                                   and b["encoded_layer_gate"] == "PASS"
                                   and b["detection_survived"]) else "held"] += 1
    print()
    print("samples masked               : %d" % len(blocks))
    print("samples refused              : %d" % len(refused))
    for sha, why in refused:
        print("    %s  %s" % (sha[:12], why))
    for k in sorted(tally):
        print("  %-28s %d" % (k, tally[k]))

    fn = [s for s, n in notes.items() if n["filename_effect"]]
    print("  %-28s %d" % ("filename-dependent rules", len(fn)))
    for s in fn:
        print("    %s  %s" % (s[:12], notes[s]["filename_effect"]))

    if a.json:
        with open(a.json, "w", encoding="utf-8") as fh:
            json.dump({"blocks": blocks, "notes": notes,
                       "refused": refused, "scanner": binary_id()}, fh,
                      indent=1, sort_keys=True)

    if a.apply:
        n = apply_rows(a.index, blocks)
        print()
        print("rows written                 : %d" % n)
        print("run `shard-gate.py --fix %s` next: publishability is computed there and "
              "nowhere else." % os.path.relpath(a.index, os.getcwd()))
    else:
        print()
        print("dry run: nothing written. Pass --apply to record these on the rows.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
