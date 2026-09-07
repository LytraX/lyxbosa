#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""§7.2, asked of the shards instead of the index that describes them.

WHY THIS IS NOT `shard-gate.py`
--------------------------------
`shard-gate.py` reads an index and asks whether its rows are internally consistent. It
never opens a shard. So it cannot see the one thing publication actually risks: a shard
carrying bytes the index does not account for, or bytes whose row has moved since the tar
was written. Both were present when this file was written - see the header of the round
that added it - and the published half gated PASS throughout, correctly, because the
question was never asked of the archives.

This file asks it of the archives. It unpacks every `corpus/shards/*.tar.zst`, hashes every
member, and resolves that hash to a published row. Anything it cannot resolve is reported
as an unaccounted member, which is the failure the apparatus exists to prevent.

THE SHIPPED BYTES ARE NOT ALWAYS THE ROW'S `sha256`, AND THAT IS BY DESIGN
--------------------------------------------------------------------------
A row's `sha256` is the blob as collected. What ships can legitimately differ, and the row
says so in one of three ways:

  * `masking.masked_sha256`             - masking rewrote the bytes; this is the output
  * `masking.remeasured.bytes_sha256`   - a re-measurement pass recorded the bytes it read
  * `fixture.fixture_sha256`            - the sample ships as a generated-carrier fixture

A census keyed only on `sha256` therefore reports false orphans: run against the eight
shards as they stood, it called 6 of 142 unaccounted when every one of them was named by
its row through one of the three keys above. That is §11's shape exactly - an enumeration
that bounds its own answer - so the resolver takes all four keys and `--inject` proves each
one is load-bearing by removing it.

`fixture` is the reason the round's premise ("a fixture is not an indexed row") is wrong,
and the mechanism is better than the premise: a fixture row records BOTH the collected
original and the bytes that ship, so the substitution is auditable rather than implicit.
The only members with no row at all are the four `carriers/` files, which are generated
clean inputs and are reported as their own class rather than as orphans.

WHAT IT CHECKS, AND WHY EACH ONE IS HERE
-----------------------------------------
  resolve      every `samples/` member resolves to a PUBLISHED row
  publishable  that row is `publishable: true` as it stands today, not as it stood when
               the tar was written - a shard built before a re-tag can carry a row that is
               now blocked, and the file does not announce it
  tags         no `pii` or `content` tag on any member (§7.2 bullet 2)
  expect       MANIFEST.json, `corpus/expect/<shard>.json` and the row agree per sample -
               three places one answer is written and two of them can be wrong
  gatebind     the row's recorded gate result describes the bytes that SHIP. A PASS
               computed over the collected original is not evidence about a fixture built
               from it, and §7.2 already rules that a gate's finding is evidence about the
               bytes.
  regate       (--regate) the identifier gates RE-RUN over the shipped bytes, delegated to
               `verify-content-mask.py`, which owns that question. This is the only check
               here that can disagree with a row rather than within it, and it is the one
               that found a published `staging-directory-review` row recording
               `plaintext_gate: PASS` whose bytes the current predicate refuses. 134 of the
               142 rows carry no `masking.provenance` at all, so nothing in the index dates
               their recorded result against the predicate that produced it - which is why
               the drift was invisible until the gate was pointed at the archives.

Every check is a census over every member. There is no sampling here and there should not
be: 142 samples is small enough that a sampled answer would only be quoting its own power.

  corpus/shard-census.py                 census over corpus/shards
  corpus/shard-census.py --json          machine-readable
  corpus/shard-census.py --inject        prove each check can fail, then exit
"""
import argparse, collections, hashlib, importlib.util, json, os, shutil, subprocess
import sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import credential_disposition                                           # noqa: E402

SHARDS = os.path.join(HERE, "shards")
EXPECT = os.path.join(HERE, "expect")
INDEX = os.path.join(HERE, "index.jsonl")

# The keys a row may use to name the bytes that actually ship, in the order a resolver
# should try them. Restated as data rather than as a chain of `or`s so `--inject` can drop
# one and assert the census notices; a resolver whose keys are inline cannot be tested that
# way, and a key silently going missing is how an orphan census comes to bound its own
# answer.
SHIPPED_KEYS = (
    ("sha256", lambda r: r.get("sha256")),
    ("masking.masked_sha256", lambda r: (r.get("masking") or {}).get("masked_sha256")),
    ("masking.remeasured.bytes_sha256",
     lambda r: ((r.get("masking") or {}).get("remeasured") or {}).get("bytes_sha256")),
    ("fixture.fixture_sha256", lambda r: (r.get("fixture") or {}).get("fixture_sha256")),
)

NEVER_PUBLISHED = ("pii", "content")


def sha256(b):
    return hashlib.sha256(b).hexdigest()


def load_index(path=INDEX):
    return [json.loads(l) for l in open(path)]


def shipped_map(rows, keys=SHIPPED_KEYS):
    """hash -> (row, which key named it). Later keys never displace an earlier one."""
    out = {}
    for r in rows:
        for name, get in keys:
            h = get(r)
            if h and h not in out:
                out[h] = (r, name)
    return out


def unpack(dest, shard_dir=SHARDS):
    """Every shard, unpacked. Returns {shard: {relpath: bytes-hash}}."""
    got = {}
    if not os.path.isdir(shard_dir):
        return got
    for f in sorted(os.listdir(shard_dir)):
        if not f.endswith(".tar.zst"):
            continue
        name = f[: -len(".tar.zst")]
        out = os.path.join(dest, name)
        os.makedirs(out, exist_ok=True)
        r = subprocess.run(["tar", "-C", out, "-I", "zstd", "-xf",
                            os.path.join(shard_dir, f)], capture_output=True)
        if r.returncode != 0:
            raise SystemExit("error: could not unpack %s: %s" % (f, r.stderr.decode()[:200]))
        got[name] = out
    return got


def _summary_shipped_set(path=None):
    """make-summary.py's SHIPPED set, imported rather than restated.

    Restating it here would make this a check that agrees with its own copy of the answer -
    §11's shape - so it is read from the file that uses it. Loaded by path because the
    filename is not an importable module name.
    """
    import importlib.util
    path = path or os.path.join(HERE, "make-summary.py")
    spec = importlib.util.spec_from_file_location("_make_summary", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.SHIPPED


def _norm_expect(e):
    e = e or {}
    return (sorted(e.get("must_detect") or []), sorted(e.get("must_not_detect") or []),
            e.get("min_severity"), bool(e.get("known_miss")))


def census(rows, shard_roots, expect_dir=EXPECT, keys=SHIPPED_KEYS):
    by_hash = shipped_map(rows, keys)
    res = {"samples": 0, "carriers": 0, "findings": collections.defaultdict(list),
           "by_reason": collections.Counter(), "by_shard": collections.Counter(),
           "resolved_via": collections.Counter(), "tags": collections.Counter()}

    for shard, root in sorted(shard_roots.items()):
        man_path = os.path.join(root, "MANIFEST.json")
        if not os.path.exists(man_path):
            res["findings"]["no manifest"].append(shard)
            continue
        man = {e["file"]: e for e in json.load(open(man_path))}
        tracked_path = os.path.join(expect_dir, shard + ".json")
        tracked = ({e["file"]: e for e in json.load(open(tracked_path))}
                   if os.path.exists(tracked_path) else None)
        if tracked is None:
            res["findings"]["no tracked expect file"].append(shard)

        for dirpath, _d, files in os.walk(root):
            for fn in sorted(files):
                p = os.path.join(dirpath, fn)
                rel = os.path.relpath(p, root)
                if rel == "MANIFEST.json":
                    continue
                h = sha256(open(p, "rb").read())
                is_sample = rel.split(os.sep)[0] == "samples"
                res["samples" if is_sample else "carriers"] += 1
                res["by_shard"][shard] += 1
                where = "%s/%s" % (shard, rel)

                entry = man.get(rel)
                if entry is None:
                    res["findings"]["member with no manifest entry"].append(where)

                hit = by_hash.get(h)
                if hit is None:
                    # A carrier is a generated clean input and legitimately has no row.
                    if is_sample:
                        res["findings"]["sample resolves to no published row"].append(where)
                    continue
                row, via = hit
                res["resolved_via"][via] += 1
                res["by_reason"][row.get("reason")] += 1
                for t in (row.get("sensitivity") or []):
                    res["tags"][t] += 1

                if row.get("publishable") is not True:
                    res["findings"]["shipped row is not publishable today"].append(
                        "%s  row %s  blockers=%s"
                        % (where, row["sha256"][:12], row.get("publish_blockers")))

                bad = set(row.get("sensitivity") or []) & set(NEVER_PUBLISHED)
                if bad:
                    res["findings"]["pii/content tag in a public shard"].append(
                        "%s  %s" % (where, sorted(bad)))

                if entry is not None:
                    a = _norm_expect(entry.get("expect"))
                    c = _norm_expect(row.get("expect"))
                    if a != c:
                        res["findings"]["expect: manifest disagrees with the row"].append(where)
                    if tracked is not None:
                        t_e = tracked.get(rel)
                        if t_e is None:
                            res["findings"]["expect: no tracked entry for this member"].append(where)
                        else:
                            b = _norm_expect(t_e.get("expect"))
                            if a != b:
                                res["findings"]["expect: manifest disagrees with the tracked copy"].append(where)
                            if b != c:
                                res["findings"]["expect: tracked copy disagrees with the row"].append(where)

                # gatebind: a recorded gate result is evidence about particular bytes.
                # `via == "sha256"` means the row's collected blob IS what ships, so the
                # gate that ran on the row ran on these bytes. Any other key means the
                # shipped bytes are a derivative, and a gate result is only evidence about
                # them if the row records it against those bytes.
                m = row.get("masking") or {}
                if is_sample and (m.get("plaintext_gate") or m.get("encoded_layer_gate")):
                    # Three keys IDENTIFY the shipped bytes by being what resolved them, and
                    # a fourth SAYS so: `masking.provenance.bytes_sha256` is written by
                    # `verify-and-stamp.py` as the digest of the bytes it re-ran the gate
                    # over. It is accepted only where it equals what actually shipped, so
                    # the field is evidence and not an assertion - a stamp naming other
                    # bytes leaves the finding standing. That is the route the four
                    # generated carriers take: the gate really was re-run over the fixture
                    # in the tar, and the row now records which bytes that was.
                    prov = m.get("provenance") or {}
                    named = via in ("sha256", "masking.masked_sha256",
                                    "masking.remeasured.bytes_sha256")
                    if not named and prov.get("bytes_sha256") == h:
                        named = True
                        res["resolved_via"]["+ masking.provenance.bytes_sha256"] += 1
                    if not named:
                        res["findings"]["gate result describes bytes other than the ones shipped"].append(
                            "%s  resolved via %s; gates recorded against %s"
                            % (where, via, row["sha256"][:12]))

    # The control `make-summary.py`'s own comment asked for and could not host. Its SHIPPED
    # set decides `published_shipped_as_bytes`, and it is a hand-maintained set of reason
    # codes: adding a code without adding it there reclassifies its rows as "reproducible
    # from a pinned source", which is the opposite of the truth, and nothing notices because
    # the summary still agrees with the index. Here the shards are open, so the set can be
    # compared against the reason codes that are demonstrably shipping.
    observed = {r for r in res["by_reason"] if r}
    declared = set(_summary_shipped_set())
    for missing in sorted(observed - declared):
        res["findings"]["reason code ships as bytes but make-summary.SHIPPED omits it"].append(
            "%s  (%d member(s)); published_shipped_as_bytes undercounts by that much"
            % (missing, res["by_reason"][missing]))
    for extra in sorted(declared - observed):
        res["findings"]["make-summary.SHIPPED names a reason code no shard ships"].append(extra)

    res["findings"] = {k: v for k, v in res["findings"].items() if v}
    for k in ("by_reason", "by_shard", "resolved_via", "tags"):
        res[k] = dict(sorted(res[k].items(), key=lambda kv: str(kv[0])))
    return res


def regate(rows, shard_roots, keys=SHIPPED_KEYS, tool=None):
    """Re-run the identifier gates over the bytes that ship, and diff against the row.

    Delegated to `verify-content-mask.py` rather than reimplemented: that file owns the
    predicate, carries its own `--inject`, and is inside `gate_provenance.TOOLS`, so a
    second copy of the rule here would be a second thing to keep in step and would not be
    covered by the provenance digest. `pre-push-check.py` delegates for the same reason.

    A row recording PASS whose bytes now FAIL is not evidence that the sample leaked - the
    predicate has been widened more than once and its own false-positive table is on every
    finding. It is evidence that the recorded result no longer describes the current gate,
    which is a human's question and is reported as a disagreement, never resolved here.
    """
    tool = tool or os.path.join(HERE, "verify-content-mask.py")
    by_hash = shipped_map(rows, keys)
    files, meta = [], {}
    for shard, root in sorted(shard_roots.items()):
        for dirpath, _d, fns in os.walk(root):
            for fn in sorted(fns):
                if fn == "MANIFEST.json":
                    continue
                p = os.path.join(dirpath, fn)
                files.append(p)
                meta[os.path.basename(p)] = (shard, os.path.relpath(p, root),
                                             by_hash.get(sha256(open(p, "rb").read())))
    if not files:
        return {"gated": 0, "disagreements": [], "failing": []}

    r = subprocess.run([sys.executable, tool] + files + ["--json"],
                       capture_output=True, cwd=os.path.dirname(HERE))
    out = r.stdout.decode()
    if "[" not in out:
        raise SystemExit("error: %s produced no JSON: %s" % (tool, (r.stderr.decode())[:300]))
    got = json.loads(out[out.index("["):out.rindex("]") + 1])

    # The credential half, and it is in here rather than in `census()` because the cost is
    # only paid for rows that record a keep - two today - and because this is the pass that
    # already has the shipped bytes in hand.
    #
    # `shard-gate.credentialDispositionViolations` checks the record against ITSELF: the
    # shape is well-formed, the count does not exceed the row's own evidence. That is an
    # index-side question and it cannot see whether the literal described is the literal in
    # the tar. This can, and it is the same split §7.3 draws for everything else - an index
    # is a description, a shard is what a stranger downloads.
    #
    # Both directions, because a matcher that can only report one of them is half a check:
    # a literal in the bytes with no disposition is a credential kept with nothing saying
    # why, and a disposition matching no literal is a keep recorded about bytes that no
    # longer carry it.
    creds = []
    want_creds = {p_ for p_, (_s, _r, hit) in
                  ((os.path.basename(f), meta[os.path.basename(f)]) for f in files)
                  if hit is not None
                  and credential_disposition.recorded(hit[0].get("masking"))}
    if want_creds:
        _cspec = importlib.util.spec_from_file_location(
            "vcm_census", os.path.join(HERE, "verify-content-mask.py"))
        _vcm = importlib.util.module_from_spec(_cspec)
        _cspec.loader.exec_module(_vcm)
        for f in files:
            base = os.path.basename(f)
            if base not in want_creds:
                continue
            shard, rel, hit = meta[base]
            row = hit[0]
            with open(f, "rb") as fh:
                lits = _vcm.secret_literals(fh.read())
            unrecorded, unmatched = credential_disposition.matches(row.get("masking"), lits)
            for u in unrecorded:
                creds.append("%s/%s  a %s literal of %d characters is kept with no "
                             "disposition recording why (row %s)"
                             % (shard, rel, u[0], u[1], row["sha256"][:12]))
            for u in unmatched:
                creds.append("%s/%s  a disposition describes a %s literal of %d characters "
                             "that these bytes do not carry (row %s)"
                             % (shard, rel, u[0], u[1], row["sha256"][:12]))

    dis, failing = [], []
    for g in got:
        shard, rel, hit = meta.get(g["file"], (None, g["file"], None))
        where = "%s/%s" % (shard, rel)
        for gate in ("plaintext_gate", "encoded_layer_gate"):
            if g[gate] != "PASS":
                failing.append("%s  %s=%s" % (where, gate, g[gate]))
            if hit is None:
                continue
            rec = (hit[0].get("masking") or {}).get(gate)
            if rec is not None and rec != g[gate]:
                dis.append("%s  %s: row records %s, the gate now returns %s "
                           "(row %s, provenance=%s)"
                           % (where, gate, rec, g[gate], hit[0]["sha256"][:12],
                              bool((hit[0].get("masking") or {}).get("provenance"))))
    return {"gated": len(got), "disagreements": dis, "failing": failing,
            "credentials": creds, "credential_rows": len(want_creds)}


def report(res):
    print("shard members")
    print("  samples                    : %d" % res["samples"])
    print("  carriers (no row by design): %d" % res["carriers"])
    print("  resolved via               : %s" % json.dumps(res["resolved_via"]))
    print("  reason codes               : %s" % json.dumps(res["by_reason"]))
    print("  sensitivity tags           : %s" % json.dumps(res["tags"]))
    print()
    if not res["findings"]:
        print("no finding: every sample resolves to a publishable row, the three expect")
        print("copies agree, and no gate result describes bytes other than the ones shipped.")
        return 0
    n = 0
    for k, v in sorted(res["findings"].items()):
        print("=== %s: %d" % (k, len(v)))
        for x in v:
            print("    %s" % x)
        n += len(v)
    print()
    print("REFUSE TO PUBLISH: %d finding(s) across the built shards." % n)
    return 1


# ---------------------------------------------------------------------------
# Controls. AGENTS.md: a check that has never been observed to fail is not yet a
# check. Each control plants exactly one defect into a synthetic shard tree and
# asserts this file names it - and the resolver keys get their own control,
# because dropping one is what turns this census into one that bounds its own answer.
def inject():
    ok = True

    def run(label, rows, tree, want, keys=SHIPPED_KEYS, expect_files=None):
        nonlocal ok
        with tempfile.TemporaryDirectory() as tmp:
            roots = {}
            for shard, files in tree.items():
                root = os.path.join(tmp, shard)
                for rel, data in files.items():
                    p = os.path.join(root, rel)
                    os.makedirs(os.path.dirname(p), exist_ok=True)
                    open(p, "wb").write(data)
                roots[shard] = root
            ed = os.path.join(tmp, "expect")
            os.makedirs(ed)
            for shard, blob in (expect_files or {}).items():
                open(os.path.join(ed, shard + ".json"), "wb").write(blob)
            res = census(rows, roots, expect_dir=ed, keys=keys)
            hit = want in res["findings"]
            print("  %-58s %s" % (label, "caught" if hit else "MISSED"))
            if not hit:
                ok = False
                print("      findings were: %s" % sorted(res["findings"]))

    payload = b"<?php /* sample */ eval($_POST['x']);"
    ph = sha256(payload)
    carrier = b"GIF89a-generated-carrier"

    def shard(man, extra=None):
        files = {"MANIFEST.json": json.dumps(man).encode(),
                 "samples/a.php": payload}
        files.update(extra or {})
        return files

    base_entry = {"file": "samples/a.php", "sha256": ph, "name": "a",
                  "expect": {"must_detect": ["X1"], "must_not_detect": []}}
    base_row = {"sha256": ph, "size": len(payload), "publishable": True,
                "reason": "undetected-pool-review", "sensitivity": ["clean"],
                "expect": {"must_detect": ["X1"], "must_not_detect": []}}
    man_blob = json.dumps([base_entry]).encode()

    print("resolution")
    run("a member no row names at all", [], {"s": shard([base_entry])},
        "sample resolves to no published row", expect_files={"s": man_blob})

    # Each shipped-bytes key, proved load-bearing: the row names the bytes ONLY through
    # that key, and the census must resolve it. Dropping the key must make it an orphan.
    fixture_row = dict(base_row, sha256="0" * 64,
                       fixture={"fixture_sha256": ph, "carrier_is_generated": True})
    run("fixture.fixture_sha256 dropped -> false orphan", [fixture_row],
        {"s": shard([base_entry])}, "sample resolves to no published row",
        keys=tuple(k for k in SHIPPED_KEYS if k[0] != "fixture.fixture_sha256"),
        expect_files={"s": man_blob})
    masked_row = dict(base_row, sha256="1" * 64, masking={"masked_sha256": ph})
    run("masking.masked_sha256 dropped -> false orphan", [masked_row],
        {"s": shard([base_entry])}, "sample resolves to no published row",
        keys=tuple(k for k in SHIPPED_KEYS if k[0] != "masking.masked_sha256"),
        expect_files={"s": man_blob})
    remeas_row = dict(base_row, sha256="2" * 64,
                      masking={"remeasured": {"bytes_sha256": ph}})
    run("masking.remeasured.bytes_sha256 dropped -> false orphan", [remeas_row],
        {"s": shard([base_entry])}, "sample resolves to no published row",
        keys=tuple(k for k in SHIPPED_KEYS if k[0] != "masking.remeasured.bytes_sha256"),
        expect_files={"s": man_blob})

    print("publishability and tags")
    run("a shipped row that is not publishable today",
        [dict(base_row, publishable=False, publish_blockers=["a gate did not pass"])],
        {"s": shard([base_entry])}, "shipped row is not publishable today",
        expect_files={"s": man_blob})
    for tag in NEVER_PUBLISHED:
        run("a %r tag in a public shard" % tag, [dict(base_row, sensitivity=[tag])],
            {"s": shard([base_entry])}, "pii/content tag in a public shard",
            expect_files={"s": man_blob})

    print("the three expect copies")
    run("manifest disagrees with the row",
        [dict(base_row, expect={"must_detect": ["X2"], "must_not_detect": []})],
        {"s": shard([base_entry])}, "expect: manifest disagrees with the row",
        expect_files={"s": man_blob})
    other = json.dumps([dict(base_entry,
                             expect={"must_detect": ["X3"], "must_not_detect": []})]).encode()
    run("tracked copy disagrees with the other two", [base_row],
        {"s": shard([base_entry])}, "expect: manifest disagrees with the tracked copy",
        expect_files={"s": other})
    run("no tracked entry for a member", [base_row], {"s": shard([base_entry])},
        "expect: no tracked entry for this member", expect_files={"s": b"[]"})

    print("gate binding")
    run("a gate result recorded against bytes other than the ones shipped",
        [dict(base_row, sha256="3" * 64,
              fixture={"fixture_sha256": ph, "carrier_is_generated": True},
              masking={"plaintext_gate": "PASS", "encoded_layer_gate": "PASS"})],
        {"s": shard([base_entry])},
        "gate result describes bytes other than the ones shipped",
        expect_files={"s": man_blob})

    # The other direction, which is what makes the new key evidence rather than a licence:
    # the SAME row, with a stamp naming the bytes that actually ship, must stop firing - and
    # a stamp naming anything else must not.
    def gatebind_row(bytes_sha):
        return dict(base_row, sha256="3" * 64,
                    fixture={"fixture_sha256": ph, "carrier_is_generated": True},
                    masking={"plaintext_gate": "PASS", "encoded_layer_gate": "PASS",
                             "provenance": {"tools": "0" * 12, "map": None,
                                            "at": "2026-01-01T00:00:00",
                                            "bytes_sha256": bytes_sha}})

    def gatebind_clean(label, row):
        nonlocal ok
        with tempfile.TemporaryDirectory() as tmp:
            root = os.path.join(tmp, "s")
            for rel, data in shard([base_entry]).items():
                q = os.path.join(root, rel)
                os.makedirs(os.path.dirname(q), exist_ok=True)
                open(q, "wb").write(data)
            ed = os.path.join(tmp, "expect")
            os.makedirs(ed)
            open(os.path.join(ed, "s.json"), "wb").write(man_blob)
            res = census([row], {"s": root}, expect_dir=ed, keys=SHIPPED_KEYS)
            hit = "gate result describes bytes other than the ones shipped" in res["findings"]
            print("  %-58s %s" % (label, "MISSED" if hit else "clean"))
            if hit:
                ok = False

    gatebind_clean("a stamp naming the bytes that shipped clears it", gatebind_row(ph))
    run("a stamp naming OTHER bytes does not", [gatebind_row("9" * 64)],
        {"s": shard([base_entry])},
        "gate result describes bytes other than the ones shipped",
        expect_files={"s": man_blob})

    print("manifest bookkeeping")
    run("a member the manifest does not list", [base_row],
        {"s": shard([base_entry], {"samples/b.php": b"<?php echo 1;"})},
        "member with no manifest entry", expect_files={"s": man_blob})

    print("make-summary's SHIPPED set")
    # Planted against a COPY of make-summary.py with the reason code removed, so the control
    # exercises the real import path. Asserting the live set instead would only ever restate
    # today's answer.
    with tempfile.TemporaryDirectory() as tmp:
        src = open(os.path.join(HERE, "make-summary.py")).read()
        stale = src.replace('"doorway-kit-review", "undetected-pool-review"}',
                            '"doorway-kit-review"}')
        assert stale != src, "control could not edit the SHIPPED set; update the control"
        sp = os.path.join(tmp, "make-summary.py")
        open(sp, "w").write(stale)
        got = _summary_shipped_set(sp)
        caught = "undetected-pool-review" not in got
        print("  %-58s %s" % ("a reason code missing from SHIPPED is visible",
                              "caught" if caught else "MISSED"))
        ok = ok and caught
        live = _summary_shipped_set()
        here = "undetected-pool-review" in live
        print("  %-58s %s" % ("the live set names the code the shards ship",
                              "correct" if here else "WRONG"))
        ok = ok and here

    print("regate")
    # The re-gate delegates, so its control plants the defect in the DELEGATE'S answer: a
    # stub standing in for verify-content-mask.py that returns FAIL where the row says
    # PASS. Without this the --regate path could return an empty disagreement list forever
    # and read as a green result, which is the exact failure AGENTS.md opens with.
    with tempfile.TemporaryDirectory() as tmp:
        root = os.path.join(tmp, "s")
        for rel, data in shard([base_entry]).items():
            p = os.path.join(root, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            open(p, "wb").write(data)
        stub = os.path.join(tmp, "stub.py")
        open(stub, "w").write(
            "import json,os,sys\n"
            "fs=[a for a in sys.argv[1:] if not a.startswith('--')]\n"
            "print(json.dumps([{'file':os.path.basename(f),'plaintext_gate':'FAIL',\n"
            "  'encoded_layer_gate':'PASS','layers_decoded':0,'layer_methods':[]}\n"
            "  for f in fs]))\n")
        row = dict(base_row, masking={"plaintext_gate": "PASS",
                                      "encoded_layer_gate": "PASS"})
        g = regate([row], {"s": root}, tool=stub)
        got_dis = len(g["disagreements"]) == 1
        got_fail = len(g["failing"]) == 1
        print("  %-58s %s" % ("a gate that now refuses a member recorded PASS",
                              "caught" if got_dis else "MISSED"))
        print("  %-58s %s" % ("a member failing the gate is reported as failing",
                              "caught" if got_fail else "MISSED"))
        ok = ok and got_dis and got_fail

        # ...and the other direction: agreement must NOT be reported as a disagreement,
        # or every clean run would read as a finding and the check would be noise.
        stub2 = os.path.join(tmp, "stub2.py")
        open(stub2, "w").write(
            "import json,os,sys\n"
            "fs=[a for a in sys.argv[1:] if not a.startswith('--')]\n"
            "print(json.dumps([{'file':os.path.basename(f),'plaintext_gate':'PASS',\n"
            "  'encoded_layer_gate':'PASS','layers_decoded':0,'layer_methods':[]}\n"
            "  for f in fs]))\n")
        g2 = regate([row], {"s": root}, tool=stub2)
        quiet = not g2["disagreements"] and not g2["failing"]
        print("  %-58s %s" % ("agreement is not reported as a disagreement",
                              "correct" if quiet else "WRONG"))
        ok = ok and quiet

    print("kept credentials, against the bytes rather than the record")
    # The index-side rule lives in `shard-gate` and can only check the record against
    # itself. This is the half that reads the tar, so its controls plant the defect in the
    # BYTES and in the RECORD separately - a literal nothing accounts for, and a keep about
    # a literal that is not there.
    with tempfile.TemporaryDirectory() as tmp:
        root = os.path.join(tmp, "s")
        credpay = b"<?php $u='http://h/x.php?pass=\'.$abcd.\''; $q=1;\n"
        files = {"MANIFEST.json": json.dumps([{"file": "samples/a.php",
                                               "sha256": sha256(credpay), "name": "a"}]).encode(),
                 "samples/a.php": credpay}
        for rel, data in files.items():
            q = os.path.join(root, rel)
            os.makedirs(os.path.dirname(q), exist_ok=True)
            open(q, "wb").write(data)
        stub3 = os.path.join(tmp, "stub3.py")
        open(stub3, "w").write(
            "import json,os,sys\n"
            "fs=[a for a in sys.argv[1:] if not a.startswith('--')]\n"
            "print(json.dumps([{'file':os.path.basename(f),'plaintext_gate':'PASS',\n"
            "  'encoded_layer_gate':'PASS','layers_decoded':0,'layer_methods':[]}\n"
            "  for f in fs]))\n")
        kept = {"shape": "quoted-credential", "keyword": "pass", "value_length": 7,
                "value_character_classes": ".$aaaa.",
                "disposition": "kept-as-indicator", "classification": "attacker",
                "ground": "read from the match", "about": "secret_gate"}
        crow = dict(base_row, sha256=sha256(credpay),
                    masking={"plaintext_gate": "PASS", "encoded_layer_gate": "PASS",
                             "secret_gate": "FAIL",
                             "credential_dispositions": [dict(kept)]})
        gc = regate([crow], {"s": root}, tool=stub3)
        clean = not gc.get("credentials")
        print("  %-58s %s" % ("a keep that matches the literal in the tar",
                              "clean" if clean else "MISSED"))
        ok = ok and clean

        wrong = dict(crow, masking=dict(crow["masking"],
                                        credential_dispositions=[dict(kept, value_length=9,
                                            value_character_classes=".$aaaaaa.")]))
        gw = regate([wrong], {"s": root}, tool=stub3)
        both = len(gw.get("credentials") or []) == 2
        print("  %-58s %s" % ("a keep describing a literal the bytes do not carry",
                              "caught" if both else "MISSED"))
        ok = ok and both

        # And the direction that is the whole reason the field exists: a credential in the
        # shipped bytes that no disposition accounts for. The row must record SOME keep or
        # this pass never looks at it, which is itself the gap `shard-gate` closes from the
        # index side - so the fixture records one about a different shape.
        gap = dict(crow, masking=dict(crow["masking"],
                                      credential_dispositions=[dict(kept, shape="bcrypt")]))
        gg = regate([gap], {"s": root}, tool=stub3)
        seen = any("no disposition recording why" in x for x in (gg.get("credentials") or []))
        print("  %-58s %s" % ("a literal in the tar that no disposition accounts for",
                              "caught" if seen else "MISSED"))
        ok = ok and seen

    print()
    # A carrier legitimately has no row; asserting that keeps the orphan rule from being
    # satisfied by calling everything a carrier.
    with tempfile.TemporaryDirectory() as tmp:
        root = os.path.join(tmp, "s")
        for rel, data in shard([base_entry], {"carriers/c.gif": carrier}).items():
            p = os.path.join(root, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            open(p, "wb").write(data)
        ed = os.path.join(tmp, "expect")
        os.makedirs(ed)
        open(os.path.join(ed, "s.json"), "wb").write(man_blob)
        res = census([base_row], {"s": root}, expect_dir=ed)
        good = (res["carriers"] == 1 and res["samples"] == 1
                and "sample resolves to no published row" not in res["findings"])
        print("  %-58s %s" % ("a carrier with no row is not an orphan",
                              "correct" if good else "WRONG"))
        ok = ok and good

    print()
    print("controls: %s" % ("all planted defects were caught" if ok
                            else "AT LEAST ONE CONTROL MISSED"))
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--inject", action="store_true",
                    help="prove each check can fail, then exit")
    ap.add_argument("--shards", default=SHARDS)
    ap.add_argument("--index", default=INDEX)
    ap.add_argument("--regate", action="store_true",
                    help="also re-run the identifier gates over the shipped bytes and diff "
                         "them against the rows. Minutes, not seconds: it decodes every "
                         "layer of every member.")
    a = ap.parse_args()

    if a.inject:
        return inject()

    rows = load_index(a.index)
    tmp = tempfile.mkdtemp(prefix="shard-census-")
    try:
        roots = unpack(tmp, a.shards)
        if not roots:
            print("no shards in %s" % a.shards)
            return 0
        res = census(rows, roots)
        if a.regate:
            res["regate"] = regate(rows, roots)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    if a.json:
        print(json.dumps(res, indent=1, sort_keys=True))
        rg = res.get("regate") or {}
        return 1 if (res["findings"] or rg.get("failing") or rg.get("credentials")) else 0
    rc = report(res)
    if a.regate:
        g = res["regate"]
        print()
        print("=== identifier gates RE-RUN over the shipped bytes (%d members) ===" % g["gated"])
        for label, key in (("failing the gate now", "failing"),
                           ("recorded result disagrees with the current gate", "disagreements")):
            print("  %-46s : %d" % (label, len(g[key])))
            for x in g[key]:
                print("      %s" % x)
        print("  %-46s : %d   (over %d row(s) recording a keep)"
              % ("kept credentials not matched in the shipped bytes",
                 len(g.get("credentials") or []), g.get("credential_rows", 0)))
        for x in (g.get("credentials") or []):
            print("      %s" % x)
        if g["failing"] or g["disagreements"] or g.get("credentials"):
            rc = 1
    return rc


if __name__ == "__main__":
    sys.exit(main())
