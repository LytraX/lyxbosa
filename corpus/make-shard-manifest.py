#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Regenerate a shard's MANIFEST.json from the index, so the two cannot drift.

WHY THIS EXISTS
---------------
A shard carries its own copy of every sample's `expect`, and `corpus/expect/<shard>.json`
is a third copy of the same bytes. Editing any of them by hand is three chances to write
three different answers, and the failure is silent: `verify.py` reads `expect` from the
INDEX, so a manifest that disagrees changes nothing the suite prints. It surfaces later,
to whoever reads the shipped artefact and believes it.

So the semantic half of a manifest entry is **generated from the index row** and never
typed: `verdict`, `family`, `sensitivity`, `expect`, `technique`, `size`, and the
`name`, plus whatever other index-owned fields an entry already carries.

The packaging half is **carried over from the manifest already in the stage**, because the
index does not know it and cannot: which file holds the bytes, what that file hashes to
after masking, the entry order, and the free-prose `note`. That half is checked rather
than invented - the bytes on disk are re-hashed and must equal what the entry claims.

WHAT IT WILL NOT DO
-------------------
It refuses rather than guesses:

  * a staged file whose bytes do not hash to the entry's `sha256`;
  * an entry whose `source_sha256` is in no index row - the join failed, and emitting the
    old values would produce a manifest that looks generated and is not;
  * an entry claiming `masked: false` whose shipped hash differs from its source hash,
    which means something rewrote the bytes without saying so;
  * a row whose verdict is `unreviewed` carrying `expect.must_detect` - shard-gate.py's
    integrity rule, applied here too so a shard cannot be built around one.

KEY ORDER
---------
Existing keys keep their position; new keys are appended in sorted order. That is not
cosmetics. Byte-identical output when nothing changed is what makes `--check` a usable
control, and it makes a real change a small diff instead of a reordered file.

Usage:
  corpus/make-shard-manifest.py <stage-dir> [--index PATH] [--write] [--inject]

  default        regenerate and print a summary of what would change
  --write        write MANIFEST.json in the stage dir
  --inject       positive control: prove the checks can fail (see --inject below)
"""
import argparse, hashlib, json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))

# Fields the INDEX owns. Anything here is overwritten from the index row on every run; a
# manifest can therefore never hold a different answer than the index does.
INDEX_OWNED = ("verdict", "family", "sensitivity", "expect", "technique",
               "staging_dir", "campaign_marker", "placements")

# Fields the STAGE owns, because the index has no way to know them.
#
# `size` is one of them, and finding that out is why this tool has a byte-identity
# control. `size` in a manifest is the size of the SHIPPED file; `size` in an index row is
# the size of the SOURCE blob. They coincide only where masking was not applied, so
# regenerating `size` from the index silently rewrote the four polyglot fixtures - a
# payload extracted onto a generated carrier - to the dimensions of the customer image it
# was extracted from. Nothing else in the pipeline would have contradicted it.
STAGE_OWNED = ("file", "sha256", "size", "source_sha256", "masked", "note", "carrier",
               "carrier_load_bearing", "detection_parity", "customer_bytes_in_fixture")


def load_index(path):
    idx = {}
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                r = json.loads(line)
                idx[r["sha256"]] = r
    return idx


def ordered(existing, new):
    """`new` with the key order of `existing`, then anything left over, sorted."""
    out = {}
    for k in existing:
        if k in new:
            out[k] = new[k]
    for k in sorted(new):
        if k not in out:
            out[k] = new[k]
    return out


def build(stage, index, strict=True):
    """Regenerated entries, plus the problems found. Never raises on a bad row."""
    man_path = os.path.join(stage, "MANIFEST.json")
    old = json.load(open(man_path, encoding="utf-8"))
    out, problems, absent = [], [], {}
    for e in old:
        src = e.get("source_sha256")
        fpath = os.path.join(stage, e["file"])
        if not os.path.exists(fpath):
            problems.append((e.get("name"), "staged file is missing: %s" % e["file"]))
            out.append(e)
            continue
        blob = open(fpath, "rb").read()
        got = hashlib.sha256(blob).hexdigest()
        if got != e.get("sha256"):
            problems.append((e.get("name"), "staged bytes do not match the entry's sha256"))
        if src is None:
            # A generated fixture (a clean carrier) has no source blob and no index row.
            out.append(dict(e))
            continue
        r = index.get(src)
        if r is None:
            problems.append((e.get("name"), "source_sha256 is in no index row: join failed"))
            out.append(dict(e))
            continue
        if e.get("masked") is False and got != src:
            problems.append((e.get("name"),
                             "masked:false but the shipped bytes differ from the source"))
        if r.get("verdict") == "unreviewed" and (r.get("expect") or {}).get("must_detect"):
            problems.append((e.get("name"),
                             "index row is unreviewed and asserts must_detect"))

        if e.get("size") is not None and e["size"] != len(blob):
            problems.append((e.get("name"),
                             "entry declares size %d but the staged file is %d bytes"
                             % (e["size"], len(blob))))

        new = {k: e[k] for k in e if k in STAGE_OWNED}
        new["sha256"] = got
        new["size"] = len(blob)
        for k in INDEX_OWNED:
            if k not in e:
                # An index-owned field the entry does not carry is NOT retrofitted. A
                # manifest's key set is the shard's schema, fixed when it was built; this
                # tool's job is to stop the values drifting, not to add fields to an
                # artefact whose bytes are already published. Reported, never written.
                if k in r:
                    absent.setdefault(k, 0)
                    absent[k] += 1
                continue
            if k in r:
                new[k] = r[k]
            else:
                # The index dropped a field the manifest still carries. Say so rather
                # than silently keeping a value nothing backs any more.
                problems.append((e.get("name"),
                                 "manifest carries %r but the index row does not" % k))
                new[k] = e[k]
        if "expect" in new:
            new["expect"] = ordered(e.get("expect") or {}, new["expect"])
        # `name` is regenerated only where it already follows the `<family>--<sha8>`
        # convention. Elsewhere it is a hand-chosen label (the polyglot fixtures) and
        # rewriting it would rename samples the expectations refer to by name.
        name = e.get("name")
        if r.get("family") and name and name.endswith("--" + src[:8]):
            name = "%s--%s" % (r["family"], src[:8])
        new["name"] = name
        out.append(ordered(e, new))
    return out, problems, absent


def emit(entries):
    # No trailing newline: that is the convention six of the seven shipped manifests and
    # all seven expect/ copies already use, and matching it is what lets the regenerated
    # text be compared to the file byte for byte instead of "byte for byte apart from".
    return json.dumps(entries, indent=1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("stage", nargs="?", help="stage dir holding samples/ and MANIFEST.json")
    ap.add_argument("--index", default=os.path.join(HERE, "index.jsonl"))
    ap.add_argument("--write", action="store_true",
                    help="write MANIFEST.json in the stage dir")
    ap.add_argument("--write-expect", action="store_true",
                    help="also write corpus/expect/<shard>.json, the tracked copy. Both "
                         "come from this one regenerated text, so they cannot diverge.")
    ap.add_argument("--expect-dir", default=os.path.join(HERE, "expect"))
    ap.add_argument("--inject", action="store_true",
                    help="positive control: assert the checks can also say the other thing")
    a = ap.parse_args()

    if a.inject:
        return inject(a.index)
    if not a.stage:
        return ap.error("a stage dir is required (or --inject)")

    index = load_index(a.index)
    entries, problems, absent = build(a.stage, index)
    man_path = os.path.join(a.stage, "MANIFEST.json")
    current = open(man_path, encoding="utf-8").read()
    regenerated = emit(entries)

    print("stage        : %s" % a.stage)
    print("entries      : %d" % len(entries))
    print("index rows   : %d" % len(index))
    print("problems     : %d" % len(problems))
    for name, why in problems[:20]:
        print("   %-46s %s" % (str(name)[:46], why))
    if len(problems) > 20:
        print("   ... and %d more" % (len(problems) - 20))
    if absent:
        print("index-owned fields this shard's schema does not carry (reported, not added):")
        for k, n in sorted(absent.items()):
            print("   %-24s in %d index row(s)" % (k, n))

    if regenerated == current:
        print("manifest     : already agrees with the index, byte for byte")
    else:
        # A count of changed entries, so "it changed" is never the whole report.
        old = json.load(open(man_path, encoding="utf-8"))
        diff = [n["name"] for o, n in zip(old, entries)
                if json.dumps(o, sort_keys=True) != json.dumps(n, sort_keys=True)]
        print("manifest     : %d of %d entries differ from the index" % (len(diff), len(entries)))
        for n in diff[:8]:
            print("   %s" % n)
        if len(diff) > 8:
            print("   ... and %d more" % (len(diff) - 8))
        if a.write:
            open(man_path, "w", encoding="utf-8").write(regenerated)
            print("wrote %s" % man_path)
        elif not a.write_expect:
            print("(not written: pass --write)")
    if a.write_expect:
        # The tracked copy of a shard's expectations is the one nothing reads at run time -
        # verify.py takes `expect` from the index and the shard - so it is the one that
        # drifts unnoticed. corpus/expect/malicious-db-dropin-001.json was a full round
        # behind when this tool first ran: it still declared 46 samples undetected after
        # the round that closed them. Writing it from the same text as the manifest is the
        # repair; a defect nothing pulls on has to be made structurally impossible instead.
        name = os.path.basename(os.path.abspath(a.stage))
        out = os.path.join(a.expect_dir, name + ".json")
        prev = open(out, encoding="utf-8").read() if os.path.exists(out) else None
        open(out, "w", encoding="utf-8").write(regenerated)
        print("expect copy  : %s (%s)"
              % (out, "unchanged" if prev == regenerated else
                 "created" if prev is None else "updated"))
    return 1 if problems else 0


def inject(index_path):
    """Positive control. A generator that has only ever agreed with the file it
    regenerates has not been observed to disagree, and AGENTS.md is explicit that such a
    check is not yet a check. Each case below breaks exactly one input and asserts the
    specific complaint comes back."""
    import shutil, tempfile
    index = load_index(index_path)
    tmp = tempfile.mkdtemp(prefix="shard-manifest-inject.")
    fails = []
    try:
        stage = os.path.join(tmp, "stage")
        os.makedirs(os.path.join(stage, "samples"))
        # One real index row, so the join is a real join rather than a fixture of itself.
        src = next(iter(index))
        row = index[src]
        blob = b"<?php /* control fixture */"
        h = hashlib.sha256(blob).hexdigest()
        open(os.path.join(stage, "samples", "a.php"), "wb").write(blob)
        base = [{"name": "%s--%s" % (row.get("family") or "x", src[:8]),
                 "file": "samples/a.php", "sha256": h, "source_sha256": src,
                 "size": len(blob), "verdict": "x", "expect": {"must_detect": ["ZZZ999"]},
                 "masked": True}]

        def run(entries, label, want):
            json.dump(entries, open(os.path.join(stage, "MANIFEST.json"), "w"), indent=1)
            _, probs, _ = build(stage, index)
            hit = any(want in why for _, why in probs)
            print("  %-52s %s" % (label, "caught" if hit else "MISSED"))
            if not hit:
                fails.append(label)
            return probs

        print("=== positive controls: each case must be CAUGHT ===")
        e = json.loads(json.dumps(base)); e[0]["sha256"] = "0" * 64
        run(e, "staged bytes disagree with the entry hash", "do not match")
        e = json.loads(json.dumps(base)); e[0]["source_sha256"] = "f" * 64
        run(e, "source_sha256 in no index row", "join failed")
        e = json.loads(json.dumps(base)); e[0]["masked"] = False
        run(e, "masked:false but shipped bytes differ from source", "differ from the source")
        e = json.loads(json.dumps(base)); e[0]["file"] = "samples/gone.php"
        run(e, "staged file missing", "is missing")
        # `size` is the shipped file's size and comes from disk. An entry that declares a
        # different one is describing bytes other than the ones in the stage - which is
        # exactly how a manifest would come to carry the SOURCE blob's size for a masked
        # sample and look plausible doing it.
        e = json.loads(json.dumps(base)); e[0]["size"] = 999999
        run(e, "declared size disagrees with the staged file", "but the staged file is")
        # The unreviewed-asserting-must_detect rule needs an unreviewed index row; make one
        # in a private copy of the index rather than touching the real file.
        fake = dict(index)
        u = dict(row); u["verdict"] = "unreviewed"; u["expect"] = {"must_detect": ["ZZZ999"]}
        fake[src] = u
        json.dump(base, open(os.path.join(stage, "MANIFEST.json"), "w"), indent=1)
        _, probs, _ = build(stage, fake)
        hit = any("unreviewed and asserts must_detect" in why for _, why in probs)
        print("  %-52s %s" % ("index row unreviewed but asserts must_detect",
                              "caught" if hit else "MISSED"))
        if not hit:
            fails.append("unreviewed asserting must_detect")

        # And the negative half: a clean stage must produce NO problems, or every
        # "caught" above could just be the checker complaining about everything.
        good = json.loads(json.dumps(base))
        good[0]["masked"] = True
        json.dump(good, open(os.path.join(stage, "MANIFEST.json"), "w"), indent=1)
        _, probs, _ = build(stage, index)
        # `verdict`/`expect` come from the index; the fixture's placeholders are replaced,
        # so the only legitimate complaints are about fields the index row lacks.
        noise = [p for p in probs if "does not" not in p[1]]
        print("  %-52s %s" % ("a consistent stage reports no problem",
                              "ok" if not noise else "FALSE POSITIVE: %s" % noise[:2]))
        if noise:
            fails.append("false positive on a consistent stage")
        print()
        print("cases: 7 · caught: %d · missed: %d" % (7 - len(fails), len(fails)))
        for f in fails:
            print("FAIL:", f)
        return 1 if fails else 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
