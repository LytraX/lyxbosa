#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Record, from the repository, that a sample is an archive container and cannot be masked.

WHY THIS IS A NEW TOOL AND NOT THE OLD WRITER BROUGHT IN
---------------------------------------------------------
`masking.not_applicable_reason` sits on 29 local rows and nothing in this tree writes it.
`mask-samples.py` READS it - it refuses a row that carries one - and never emits it, so the
current driver honours a claim it cannot produce. `stamp-legacy.py` dated the field to an
uncommitted state of `mask-samples.py` before that file's first commit.

The obvious repair was the one `sensitivity.py` got last round: find the untracked original
and reproduce it. **Measured, that repair is not available here, and the difference is the
finding.** `sensitivity.py` and `deobfuscate.py` are untracked *files that still exist* -
gitignored under `trail-data`, readable, hashable, runnable. This field's author is not a
file at all:

    grep -rl not_applicable --include=*.py <the whole machine's trail tree>   -> 0 writers
    git log --diff-filter=A -- corpus/mask-samples.py                         -> 2026-09-05

The first commit of `mask-samples.py` is the only version in git, no `.py` anywhere on this
machine writes the string, and the rows predate that commit by a day. **The writer was never
saved.** There is nothing to bring in, nothing to hash, and no behavioural-equality probe
that could be run against it. So the choice the brief offers - adopt the writer, or write the
field with a tracked tool - has one arm, and this is it.

That is the general shape rather than one case: "the author is not in the repository" is
three different conditions with three different repairs, and only `field-provenance.py`'s
census can tell them apart.

  * the author exists and is untracked      -> reproduce it, and prove the reproduction
                                               (`sensitivity.py`, `deobfuscate.py`)
  * the author is gone                      -> re-derive the CLAIM from the bytes and record
                                               who re-derived it (`stamp-legacy.py`, this)
  * the author never existed                -> the field is a convention, and the repair is
                                               to stop treating it as a measurement

WHAT IT WRITES, AND THE THREE THINGS IT DELIBERATELY DOES NOT
--------------------------------------------------------------
It writes `applied: false`, `not_applicable_reason`, and a `not_applicable` block naming the
author, the moment, the container magic re-read from the bytes and the sha256 those bytes
hashed to. The claim is testable without the original tool - `tar` writes `ustar` at offset
257 and gzip starts `1f 8b` - so the magic is re-read rather than asserted, using
`stamp-legacy.container_kind` rather than a second copy of the same table.

It does NOT write `plaintext_gate`, `encoded_layer_gate`, `detection_survived`, `changes`,
`change_kinds`, `length_preserved` or `c2_kept`, all seven of which the 29 legacy rows carry.
Those are measurements, and this tool takes none of them: a dry-run masker's `changes: 736`
and a `detection_survived: false` that means "nobody measured" are exactly the fields
`shard-gate.py` has a special case for. Writing them here to make the new rows look like the
old ones would be manufacturing a measurement, which §4.4 forbids and which is what put an
unprovenanced `PASS` on 6 rows in the first place. The population is deliberately not
homogeneous, and `--census` prints both shapes so the difference is visible rather than
discovered.

The reason string is the 29's own, verbatim except for its final sentence. That sentence is
`Held local-only.`, and these rows carry no `local_only` marker: copying it would put a hold
on the row that nobody recorded. Same field, same reason, one clause fewer, and the record
says which.

    corpus/mark-not-maskable.py --index corpus/local/index-local.jsonl \
        --sha <prefix> --sha <prefix> --bytes-map <out-of-repo json>
    corpus/mark-not-maskable.py ... --by cl --apply
    corpus/mark-not-maskable.py --inject
"""
import argparse, collections, copy, datetime, hashlib, importlib.util, json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from indexio import read_jsonl, write_jsonl_atomic, index_lock, LockBusy   # noqa: E402

_lspec = importlib.util.spec_from_file_location("stamp_legacy",
                                                os.path.join(HERE, "stamp-legacy.py"))
LEGACY = importlib.util.module_from_spec(_lspec)
_lspec.loader.exec_module(LEGACY)

FIELD = "not_applicable_reason"

# The 29 legacy rows' string, minus its final `Held local-only.` - see the docstring.
REASON = ("archive container: byte-level, length-preserving masking corrupts tar header "
          "checksums and gzip streams, so the container stops parsing and every "
          "member-level detection is lost. Masking is not applicable; per CORPUS_PLAN 2.3 "
          "archives are not corpus samples and fixtures are generated instead.")

WRITABLE = ("masking",)

# What the 29 legacy rows carry that this tool will not write. Named, so that a future reader
# comparing the two shapes finds the list rather than deriving it.
NOT_WRITTEN = ("plaintext_gate", "encoded_layer_gate", "detection_survived", "changes",
               "change_kinds", "length_preserved", "c2_kept")


def bytes_state(row, path):
    """('verified', data) | ('mismatch', None) | ('unavailable', None). Never two answers."""
    if not path or not os.path.exists(path):
        return "unavailable", None
    with open(path, "rb") as fh:
        data = fh.read()
    if hashlib.sha256(data).hexdigest() != row["sha256"]:
        return "mismatch", None
    return "verified", data


def build(row, data, by, at=None):
    """(after_row, refusal). Exactly one is None."""
    if not by or not by.strip():
        return None, "an author is required: a recorded decision has an owner"
    m = row.get("masking") or {}
    if m:
        return None, ("row already carries a masking block (%s); this tool creates one and "
                      "never edits one" % "/".join(sorted(m)))
    if data is None:
        return None, "the row's bytes were not verified, so the container claim is untested"
    kind = LEGACY.container_kind(data[:1024])
    if kind is None:
        return None, ("the bytes are not a recognised archive container, so §5.5 does not "
                      "exclude them and masking is owed rather than not applicable")
    after = copy.deepcopy(row)
    after["masking"] = {
        "applied": False,
        FIELD: REASON,
        "not_applicable": {
            "by": by.strip(),
            "at": (at or datetime.datetime.now().replace(microsecond=0)).isoformat(),
            "rule": "CORPUS_PLAN 5.5 - archives are excluded from content masking entirely",
            "claim_verified": "container magic read from the source bytes: %s" % kind,
            "bytes_sha256": hashlib.sha256(data).hexdigest(),
            "written_by": "corpus/mark-not-maskable.py",
            "differs_from_the_29_legacy_rows": (
                "those carry seven further masking keys (%s) written by a tool that is not "
                "in this repository and was never saved. This tool takes none of those "
                "measurements and therefore records none of them; the reason string is "
                "theirs verbatim except for a final `Held local-only.` these rows have not "
                "earned" % ", ".join(NOT_WRITTEN)),
        },
    }
    return after, None


def assert_additive(before, after):
    """None, or what changed that should not have."""
    moved = sorted({k for k in set(before) | set(after) if before.get(k) != after.get(k)})
    extra = [k for k in moved if k not in WRITABLE]
    if extra:
        return "changed %s, which is outside %s" % ("/".join(extra), "/".join(WRITABLE))
    if "masking" not in moved:
        return "masking did not move, so nothing was recorded"
    if before.get("masking"):
        return "an existing masking block was overwritten"
    if "publishable" in moved:
        return "wrote publishable, which only shard-gate.py may compute"
    return None


def census(rows):
    """(legacy_shape, this_shape) - the two populations, printed on every run.

    A single count of `rows carrying not_applicable_reason` would hide that they were
    written by two different things recording two different amounts of measurement.
    """
    legacy = this = 0
    for r in rows:
        m = r.get("masking") or {}
        if not m.get(FIELD):
            continue
        if "not_applicable" in m:
            this += 1
        else:
            legacy += 1
    return legacy, this


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--index", default=os.path.join(HERE, "local", "index-local.jsonl"))
    ap.add_argument("--sha", action="append", default=[], help="sha256 prefix; repeatable")
    ap.add_argument("--bytes-map", help="json of sha256 -> path, out of repo like the maps")
    ap.add_argument("--by", default=None)
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--inject", action="store_true")
    a = ap.parse_args()
    if a.inject:
        return inject()
    if not a.sha:
        return ap.error("--sha is required unless --inject")

    paths = json.load(open(a.bytes_map)) if a.bytes_map else {}
    rows = read_jsonl(a.index)
    legacy, mine = census(rows)
    print("rows carrying %s : %d" % (FIELD, legacy + mine))
    print("  written by the tool that is not in this repository : %d" % legacy)
    print("  written by corpus/mark-not-maskable.py             : %d" % mine)
    print()

    todo, refused = [], []
    for r in rows:
        if not any(r["sha256"].startswith(p) for p in a.sha):
            continue
        state, data = bytes_state(r, paths.get(r["sha256"]))
        after, refusal = build(r, data, a.by or "dry-run")
        if refusal:
            refused.append((r["sha256"], "%s [bytes %s]" % (refusal, state)))
            continue
        todo.append((r["sha256"], after["masking"]["not_applicable"]["claim_verified"],
                     sorted(r.get("sensitivity") or []), state))

    for sha, claim, tags, state in todo:
        print("  %s  %-34s tags=%s  [bytes %s]" % (sha[:12], claim, ",".join(tags), state))
    for sha, why in refused:
        print("  %s  REFUSED: %s" % (sha[:12], why))
    print()
    print("rows to mark              : %d" % len(todo))
    print("rows refused              : %d" % len(refused))
    print()
    print("This records that no masking pass is possible. It does NOT clear a blocker:")
    print("shard-gate's `carries <tag> but no masking has been applied` is driven by")
    print("`applied`, so a row carrying an unmaskable identifier stays unpublishable and")
    print("that is the correct end state, not an outstanding task.")

    if not a.apply:
        print()
        print("dry run: nothing written. Re-run with --by <who> --apply.")
        return 1 if refused else 0
    if not a.by:
        return ap.error("--by is required to write")
    if refused:
        sys.exit("refusing to write any row while %d are refused" % len(refused))

    want = {sha for sha, _c, _t, _s in todo}
    at = datetime.datetime.now().replace(microsecond=0)
    with index_lock(a.index):
        rows = read_jsonl(a.index)
        n_before = len(rows)
        written = 0
        for i, r in enumerate(rows):
            if r["sha256"] not in want:
                continue
            state, data = bytes_state(r, paths.get(r["sha256"]))
            after, refusal = build(r, data, a.by, at)
            if refusal:
                sys.exit("REFUSED on re-read under the lock: %s on %s"
                         % (refusal, r["sha256"][:12]))
            bad = assert_additive(r, after)
            if bad:
                sys.exit("refusing to write: %s on %s" % (bad, r["sha256"][:12]))
            rows[i] = after
            written += 1
        if len(rows) != n_before:
            sys.exit("row count moved %d -> %d" % (n_before, len(rows)))
        if written != len(want):
            sys.exit("expected to write %d row(s), wrote %d" % (len(want), written))
        write_jsonl_atomic(a.index, rows)
    print()
    print("rows written              : %d" % written)
    print("run `corpus/shard-gate.py --fix %s` next"
          % os.path.relpath(a.index, os.getcwd()))
    return 0


# ---------------------------------------------------------------------------------------
# Controls.
# ---------------------------------------------------------------------------------------

def inject():
    import gzip, io, shutil, tarfile, tempfile
    fails, ran = [], []

    def case(label, got, want):
        ok = got == want
        ran.append(label)
        print("  %-62s %-24s %s" % (label, str(got)[:24],
                                    "ok" if ok else "WRONG (wanted %s)" % (want,)))
        if not ok:
            fails.append(label)

    tmp = tempfile.mkdtemp(prefix="mark-not-maskable-inject.")
    try:
        def blob(data):
            return {"sha256": hashlib.sha256(data).hexdigest(), "verdict": "malicious",
                    "sensitivity": ["identity"]}

        gz = gzip.compress(b"CREATE TABLE x;" * 200)
        tarbuf = io.BytesIO()
        with tarfile.open(fileobj=tarbuf, mode="w") as tf:
            p = os.path.join(tmp, "x.txt")
            open(p, "w").write("hello" * 40)
            tf.add(p, arcname="x.txt")
        tar = tarbuf.getvalue()
        php = b"<?php eval($_POST['x']); // " + b"A" * 400

        print("=== it must REFUSE these ===")
        case("no author",
             "refused" if build(blob(gz), gz, " ")[1] else "written", "refused")
        case("bytes not verified",
             "refused" if build(blob(gz), None, "cl")[1] else "written", "refused")
        case("bytes that are not a container",
             "refused" if build(blob(php), php, "cl")[1] else "written", "refused")
        row = dict(blob(gz), masking={"applied": True})
        case("a row that already has a masking block",
             "refused" if build(row, gz, "cl")[1] else "written", "refused")

        print()
        print("=== and MARK these ===")
        after, refusal = build(blob(gz), gz, "cl")
        case("a real gzip", after["masking"][FIELD][:16] if after else refusal,
             "archive containe")
        case("and it names the magic it read",
             "gzip" in after["masking"]["not_applicable"]["claim_verified"], True)
        after_t, _ = build(blob(tar), tar, "cl")
        case("a real tar", "ustar" in after_t["masking"]["not_applicable"]["claim_verified"],
             True)
        case("applied is false", after["masking"]["applied"], False)
        case("the bytes' hash is recorded",
             after["masking"]["not_applicable"]["bytes_sha256"],
             hashlib.sha256(gz).hexdigest())

        print()
        print("=== and it must not manufacture a measurement ===")
        for k in NOT_WRITTEN:
            case("masking carries no %s" % k, k in after["masking"], False)

        print()
        print("=== the write must be additive and must not compute publishability ===")
        base = dict(blob(gz), publishable=True)
        after2, _ = build(base, gz, "cl")
        case("nothing outside masking moves", assert_additive(base, after2) or "clean",
             "clean")
        t = copy.deepcopy(after2)
        t["publishable"] = False
        case("writing publishable alongside is caught",
             "caught" if assert_additive(base, t) else "MISSED", "caught")
        t2 = copy.deepcopy(after2)
        t2["sensitivity"] = ["clean"]
        case("a change outside the allow-list is caught",
             "caught" if assert_additive(base, t2) else "MISSED", "caught")
        case("a row that did not move is caught",
             "caught" if assert_additive(base, copy.deepcopy(base)) else "MISSED", "caught")

        print()
        print("=== the bytes question has three answers, never two ===")
        good = os.path.join(tmp, "good.gz")
        open(good, "wb").write(gz)
        case("bytes that hash to the row", bytes_state(blob(gz), good)[0], "verified")
        bad = os.path.join(tmp, "bad.gz")
        open(bad, "wb").write(gzip.compress(b"something else entirely" * 40))
        case("bytes that do not hash to the row", bytes_state(blob(gz), bad)[0], "mismatch")
        case("no bytes at all", bytes_state(blob(gz), None)[0], "unavailable")

        print()
        print("=== the census must tell the two populations apart ===")
        pop = [{"sha256": "0" * 64, "masking": {FIELD: REASON}},
               {"sha256": "1" * 64, "masking": {FIELD: REASON, "not_applicable": {}}},
               {"sha256": "2" * 64, "masking": {"applied": True}},
               {"sha256": "3" * 64}]
        case("legacy rows / rows written here", census(pop), (1, 1))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print()
    print("cases: %d · passed: %d · failed: %d"
          % (len(ran), len(ran) - len(fails), len(fails)))
    for f in fails:
        print("FAIL:", f)
    return 1 if fails else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except LockBusy as exc:
        sys.exit(str(exc))
