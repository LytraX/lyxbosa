#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""`expect.known_miss` records one fact. This records which one.

`expect.known_miss` marks a row the **published suite asserts no rule for**: its absence
from the detected set is not a failure, and `promote-pending.py` will not turn it into
`must_detect`. That marker is correct for two populations that are not the same thing:

  * the scanner is given the bytes and no rule fires - a **miss**;
  * the scanner is given the bytes and rules **do** fire, but no shard carries them, so the
    suite has nothing to run the assertion against. That is a shipping gap, not a rule gap,
    and `promote-pending.py` refuses it for exactly the right reason.

Published as one number, the second population is reported to a stranger as the first. On
2026-09-08 `README.md` said *598 recorded known misses, 67 of them outside the rules' own
source material*, glossed as "recorded malware this version does not catch" - and 32 of
those 598, 29 of the 67, are files the scanner detects. This tool records the difference on
the row so the summary can report the two separately and neither can be quoted as the other.

`expect.known_miss` itself is left alone, and that is the choice rather than an omission.
Moving these rows to a key of their own would be mutually exclusive by construction, which
is the attractive half; the other half is that every consumer keys on `expect.known_miss` -
`verify.py`'s expected-miss column, `shard-census.py`, `make-summary.py`,
`promote-pending.py`, which refuses a row that does not carry it - and a row that changes
key leaves all of them **silently**. It would also assert something false: the suite is
still carrying the expectation. So the marker stays and gains a reason.

WHY THIS HASHES THE TREES INSTEAD OF READING THE BLOBMAP
--------------------------------------------------------
`family_evidence.SampleStore` resolves sample bytes through
`trail-data/incoming/2026-09-03/derived/blobmap-all.jsonl`, and its docstring says the 531
`predates_ruleset` rows' bytes "resolve to nothing here - all 531 of them". A round read
that as *not on this machine* and recorded, in a commit message, that 531 known misses were
unreachable and no claim could be made about them.

The blobmap indexes one collection tree. It contains 0 of those 531 rows and 67 of the 67
others - so `SampleStore` reports exactly the docstring's number, and would do so however
many of the files were sitting on disk. Hashing the trees finds 523 of the 531, in
`trail-data/Infected/`, which is the tree those rows came from and which was never in that
blobmap. The resolver's index bounded the answer, and the answer was read as the world:
CORPUS_PLAN section 11, in a new place. So this tool enumerates by hashing what is on disk
now, and reports what it could not reach as its own state rather than as "not detected".

THE STATES
----------
`rule-gap`                 bytes read, no rule fires. A miss, and the only kind that is one.
`detected-not-shippable`   bytes read, rules fire, no shard carries them. Not a miss.
`unverified`               the bytes are not on this machine. The recorded claim stands and
                           was not re-measured. It is NOT folded into either of the others;
                           an unreachable population quietly becoming "not detected" is how
                           the flattering direction gets published without evidence.

A known_miss row that is detected **and** whose bytes ship is refused rather than
classified. It is not a state to publish - it is a promotion `promote-pending.py` can apply,
and naming it `detected-not-shippable` would publish "nothing ships this" about a file that
ships. There are none today; `--inject` asserts the refusal is reachable anyway.

Usage:
  corpus/classify-known-miss.py             measure and report; writes nothing
  corpus/classify-known-miss.py --apply     write the kind onto every known_miss row
  corpus/classify-known-miss.py --check     exit non-zero if any row lacks a kind
  corpus/classify-known-miss.py --inject    controls, both directions

The binary is `$LYXBOSA_BIN`, defaulting to `build/lyxbosa`. Build your own and point at it;
see AGENTS.md, *Build directories*.
"""
import argparse
import collections
import datetime
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
from indexio import index_lock, read_jsonl, write_jsonl_atomic  # noqa: E402

SCANNER = os.environ.get("LYXBOSA_BIN") or os.path.join(ROOT, "build", "lyxbosa")
PUBLISHED = os.path.join(HERE, "index.jsonl")
LOCAL = os.path.join(HERE, "local", "index-local.jsonl")

# Where sample bytes may be. `trail-data/Infected` is first because it is the one the
# blobmap never indexed, which is the whole reason this scan exists.
TREES = ("trail-data", "corpus/local", "corpus/shards")

KIND_FIELD = "known_miss_kind"
MEASURED_FIELD = "known_miss_kind_measured"
KINDS = ("rule-gap", "detected-not-shippable", "unverified")

# The kind that counts as a miss. Named once, so the summary, the documents and this tool
# cannot drift into three opinions about which of the three states is the bad news.
MISS_KIND = "rule-gap"


# --------------------------------------------------------------------------- the decision

def classify(reachable, rules, ships_as_bytes):
    """(kind, refusal). Exactly one is None.

    Pure, and takes three booleans-worth of fact rather than a row, so `--inject` can reach
    every branch including the one no row is in.
    """
    if not reachable:
        return "unverified", None
    if not rules:
        return MISS_KIND, None
    if ships_as_bytes:
        return None, ("detected, and its bytes ship in a public shard. That is a promotion "
                      "for promote-pending.py, not a state to publish: calling it "
                      "detected-not-shippable would assert nothing ships a file that ships")
    return "detected-not-shippable", None


def is_known_miss(row):
    return bool((row.get("expect") or {}).get("known_miss"))


def select_rows(rows, shas):
    """(the rows whose sha256 is in `shas`, the listed sha256 that name none of them).

    A listed hash with no known_miss row is returned rather than dropped: a restriction that
    silently measured fewer rows than it was given would report "all current" about rows it
    never looked at.
    """
    want = set(shas)
    picked = [r for r in rows if r["sha256"] in want]
    have = {r["sha256"] for r in picked}
    return picked, sorted(want - have)


# --------------------------------------------------------------------------- measurement

def _check(path):
    r = subprocess.run([SCANNER, "check", "--no-ansi", path], capture_output=True)
    return sorted(set(x.decode() for x in re.findall(rb"- ([A-Z]+\d+)", r.stdout)))


# A NAME RULE HAS READ NONE OF THE BYTES, AND THIS TOOL IS A QUESTION ABOUT BYTES
# --------------------------------------------------------------------------------
# The scanner reads names as well as content: FN001-FN006 fire on a file called
# `x$(true)y.mdb` whatever is inside it. That is right for a scan and wrong here, because
# every state below is a statement about whether a rule fires on a row's BYTES, and the path
# this tool measures is whichever copy `resolve_bytes` happened to hash first - a name chosen
# by whoever stored the file, not by the row.
#
# It was not hypothetical. A known-miss row whose every copy was stored under a leading-dash
# name measured FN004 at that path, and the classifier read one rule firing as "rules fire,
# nothing ships them" - `detected-not-shippable`, a rule gap published as a shipping gap,
# about bytes no content rule matches under any of sixteen names tried.
#
# So a copy whose basename carries nothing a name rule reads is measured where it is, exactly
# as before, and every row measured before this existed measures the same now. A copy whose
# basename is outside that shape is measured as a copy named `sample<ext>`, keeping the
# extension, because content rules read it: the same NUL-bearing probe fires OBF036 as
# `.txt` and is silent as `.zip`. What the stored name fired is recorded beside the rules,
# never among them.
# A leading dot is allowed, so `.htaccess` is measured where it is; a leading dash is not.
SAFE_BASENAME = re.compile(r"^[A-Za-z0-9_.][A-Za-z0-9_.-]*$")
SAFE_EXTENSION = re.compile(r"^\.[A-Za-z0-9]{1,16}$")


def measured_name(path):
    """The basename `path`'s bytes are measured under: its own, or `sample<ext>`."""
    base = os.path.basename(path)
    if SAFE_BASENAME.match(base) and ".." not in base:
        return base
    ext = os.path.splitext(base)[1]
    return "sample" + (ext if SAFE_EXTENSION.match(ext) else "")


def check_rules(path):
    """Per-sample `check` over the BYTES at `path`, under a name no name rule reads.

    Never a batch scan: a batch cannot distinguish 'not scanned' from 'scanned and clean'
    (CORPUS_PLAN 5.6, 8). Returns (rules, stored_name_rules), where `stored_name_rules` is
    None when the copy was measured at its own path and otherwise what `check` reported
    under the stored name - evidence about the name, kept apart from the rules."""
    name = measured_name(path)
    if name == os.path.basename(path):
        return _check(path), None
    import shutil as _shutil
    tmp = tempfile.mkdtemp(prefix="classify-known-miss-name-")
    try:
        staged = os.path.join(tmp, name)
        _shutil.copyfile(path, staged)
        return _check(staged), _check(path)
    finally:
        _shutil.rmtree(tmp, ignore_errors=True)


def resolve_bytes(rows, extra_roots=(), out=sys.stderr):
    """{sha256: path} for every row whose bytes are on this machine, by hashing.

    Keyed on `size` first so the hash is computed only for candidates: the trees hold about
    511,000 files and the known-miss sizes select roughly 20,000 of them. The size index is
    an optimisation and never an answer - nothing is reported found without a sha256 match.

    `extra_roots` is how the UNPACKED shards get scanned, and it is not a convenience. The
    bytes in `corpus/shards` live inside `.tar.zst` archives, so walking that directory finds
    the archives and never their members: a row whose bytes existed only in a shard would be
    reported `unverified` - "not on this machine" - while the corpus was shipping it to
    strangers. No row is in that state today (all 36 known-miss rows that ship are also loose
    in the collection trees, which is why this was invisible), and a blind spot that is
    currently empty is still a blind spot.
    """
    sizes = collections.defaultdict(set)
    for r in rows:
        if r.get("size") is not None:
            sizes[r["size"]].add(r["sha256"])
    want = {r["sha256"] for r in rows}

    found, stat_seen, hashed = {}, 0, 0
    roots = [os.path.join(ROOT, t) for t in TREES] + list(extra_roots)
    for base in roots:
        if not os.path.isdir(base):
            continue
        for dirpath, _dirs, files in os.walk(base):
            for name in files:
                path = os.path.join(dirpath, name)
                if os.path.islink(path):
                    continue
                try:
                    size = os.stat(path).st_size
                except OSError:
                    continue
                stat_seen += 1
                if size not in sizes:
                    continue
                hashed += 1
                h = hashlib.sha256()
                try:
                    with open(path, "rb") as fh:
                        for chunk in iter(lambda: fh.read(1 << 20), b""):
                            h.update(chunk)
                except OSError:
                    continue
                digest = h.hexdigest()
                if digest in want and digest not in found:
                    found[digest] = path
    print("  files examined %d, hashed %d (size matched), resolved %d of %d rows"
          % (stat_seen, hashed, len(found), len(want)), file=out)
    return found


def unpack_shards(out=sys.stderr):
    """(every `source_sha256` a public shard carries as bytes, the directory they unpacked to).

    Read out of the shard tars rather than off the index: `publishable` is a decision and
    this question is about what is actually in the archive. `shard-census.py` fails the
    build when the two disagree, which is a different check from this one.

    The directory is returned rather than discarded so `resolve_bytes` can hash the members;
    see its docstring for why walking `corpus/shards` alone cannot see them.
    """
    shards = os.path.join(HERE, "shards")
    if not os.path.isdir(shards):
        print("  no shard directory; treating nothing as shipped", file=out)
        return set(), None
    ships = set()
    tmp = tempfile.mkdtemp(prefix="classify-known-miss-")
    for name in sorted(os.listdir(shards)):
        if not name.endswith(".tar.zst"):
            continue
        dest = os.path.join(tmp, name[:-len(".tar.zst")])
        os.makedirs(dest, exist_ok=True)
        r = subprocess.run(["tar", "-C", dest, "-I", "zstd", "-xf",
                            os.path.join(shards, name)], capture_output=True)
        if r.returncode != 0:
            sys.exit("could not unpack %s: %s" % (name, r.stderr.decode()[:200]))
        manifest = os.path.join(dest, "MANIFEST.json")
        if not os.path.exists(manifest):
            continue
        for entry in json.load(open(manifest, encoding="utf-8")):
            if entry.get("source_sha256"):
                ships.add(entry["source_sha256"])
    print("  %d distinct source blobs ship as bytes across %d shards"
          % (len(ships), len(os.listdir(shards))), file=out)
    return ships, tmp


def binary_id():
    """(path, sha256_12) of the binary the kinds were measured with.

    Recorded on the row in the shape `masking.measured_with` already uses. A kind measured
    by an unnamed binary is not reproducible, and this project has already had a detection
    figure taken across a changing one.
    """
    if not os.path.exists(SCANNER):
        sys.exit("scanner not built: %s (cmake --build build)" % SCANNER)
    h = hashlib.sha256()
    with open(SCANNER, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return os.path.relpath(SCANNER, ROOT), h.hexdigest()[:12]


def measure(rows, date, out=sys.stderr):
    """{sha256: (kind, measured_block)} plus the refusals, over every known_miss row.

    The shards are unpacked FIRST so their members are among the bytes `resolve_bytes` can
    reach. Doing it the other way round is what let a shipped row read as unreachable.
    """
    import shutil
    print("reading the shards", file=out)
    ships, shard_dir = unpack_shards(out)
    try:
        print("resolving bytes", file=out)
        located = resolve_bytes(rows, [shard_dir] if shard_dir else [], out)
        bin_path, bin_sha = binary_id()
        print("measuring with %s (sha256_12 %s)" % (bin_path, bin_sha), file=out)

        kinds, refused = {}, []
        for i, row in enumerate(sorted(rows, key=lambda r: r["sha256"])):
            sha = row["sha256"]
            path = located.get(sha)
            rules, stored_name_rules = check_rules(path) if path else ([], None)
            kind, refusal = classify(bool(path), rules, sha in ships)
            if refusal:
                refused.append((sha, row.get("family"), rules, refusal))
                continue
            if kind == "unverified":
                block = {"date": date, "bytes": "not on this machine"}
            else:
                block = {"date": date, "binary": bin_path, "binary_sha256_12": bin_sha,
                         "rules": rules, "ships_as_bytes": sha in ships}
                if stored_name_rules is not None:
                    # Only where the copy was renamed, so no row measured at its own path
                    # changes shape. The name is never recorded: it can be the payload.
                    block["measured_under"] = ("sample%s: the stored name carries a shape "
                                               "the name rules read"
                                               % os.path.splitext(measured_name(path))[1])
                    block["stored_name_rules"] = stored_name_rules
            kinds[sha] = (kind, block)
            if (i + 1) % 200 == 0:
                print("  %d/%d" % (i + 1, len(rows)), file=out)
        return kinds, refused
    finally:
        if shard_dir:
            shutil.rmtree(shard_dir, ignore_errors=True)


# --------------------------------------------------------------------------- apply

def apply_half(path, kinds, dry_run):
    """Write the kind onto this half's known_miss rows. Returns (changed, unchanged).

    The lock is held across the whole read-modify-write and the rows are re-read inside it,
    per AGENTS.md *Index writes*: a stale full-file rewrite drops another writer's rows with
    every gate still passing.
    """
    if dry_run:
        rows = read_jsonl(path)
        changed = sum(1 for r in rows if is_known_miss(r) and r["sha256"] in kinds
                      and (r["expect"].get(KIND_FIELD),
                           r["expect"].get(MEASURED_FIELD)) != kinds[r["sha256"]])
        return changed, sum(1 for r in rows if is_known_miss(r)) - changed

    with index_lock(path):
        rows = read_jsonl(path)
        changed = 0
        for row in rows:
            if not is_known_miss(row) or row["sha256"] not in kinds:
                continue
            kind, block = kinds[row["sha256"]]
            expect = row["expect"]
            if (expect.get(KIND_FIELD), expect.get(MEASURED_FIELD)) == (kind, block):
                continue
            expect[KIND_FIELD] = kind
            expect[MEASURED_FIELD] = block
            changed += 1
        write_jsonl_atomic(path, rows)
    return changed, sum(1 for r in rows if is_known_miss(r)) - changed


def survey(rows):
    """{kind: count} and {kind: count} restricted to the in-scope rows, off the index."""
    total = collections.Counter()
    in_scope = collections.Counter()
    for r in rows:
        kind = (r.get("expect") or {}).get(KIND_FIELD) or "<unclassified>"
        total[kind] += 1
        if not r.get("predates_ruleset"):
            in_scope[kind] += 1
    return total, in_scope


# --------------------------------------------------------------------------- controls

def inject():
    """Both directions, and the direction that matters most is the third.

    A classifier that answered `rule-gap` to everything would satisfy "a genuine miss is a
    miss" and be worthless. So every case asserts what the kind is AND asserts it is not one
    of the others - specifically, that a detected row is not counted as a miss and that an
    unreachable row is not counted as one either.
    """
    fails, cases = [], []

    def case(label, ok):
        cases.append(label)
        print("  %-72s %s" % (label, "ok" if ok else "WRONG"))
        if not ok:
            fails.append(label)

    print("=== the three states, each reachable and each not the others ===")
    gap, refusal = classify(reachable=True, rules=[], ships_as_bytes=False)
    case("bytes read, no rule fires                     -> rule-gap",
         gap == "rule-gap" and refusal is None)
    case("  ...and specifically NOT detected-not-shippable", gap != "detected-not-shippable")

    det, refusal = classify(reachable=True, rules=["PHI009"], ships_as_bytes=False)
    case("bytes read, a rule fires, nothing ships them  -> detected-not-shippable",
         det == "detected-not-shippable" and refusal is None)
    case("  ...and specifically NOT a miss", det != MISS_KIND)

    unk, refusal = classify(reachable=False, rules=[], ships_as_bytes=False)
    case("bytes not on this machine                     -> unverified",
         unk == "unverified" and refusal is None)
    case("  ...and specifically NOT a miss: an unreachable row is not evidence of one",
         unk != MISS_KIND)
    case("  ...and specifically NOT detected-not-shippable",
         unk != "detected-not-shippable")

    print()
    print("=== the state that is refused rather than published ===")
    kind, refusal = classify(reachable=True, rules=["PHI009"], ships_as_bytes=True)
    case("detected, and a shard carries the bytes       -> refused, no kind",
         kind is None and refusal is not None)
    case("  ...the refusal names promote-pending as the route",
         bool(refusal) and "promote-pending" in refusal)

    print()
    print("=== a rule list that is empty is not the same as bytes that are absent ===")
    # Both produce "no rules". Conflating them is the failure this whole round is about, so
    # it is asserted directly rather than left implied by the cases above.
    a, _ = classify(reachable=True, rules=[], ships_as_bytes=False)
    b, _ = classify(reachable=False, rules=[], ships_as_bytes=False)
    case("same empty rule list, different reachability  -> different kinds", a != b)

    print()
    print("=== bytes are found by content, and a shard member is reachable ===")
    # The blind spot this asserts is closed: shard bytes live inside .tar.zst archives, so
    # walking corpus/shards finds the archives and not their members, and a row shipping only
    # from a shard would have read "not on this machine". Both directions - the right bytes
    # are found, and bytes that merely have the right SIZE are not.
    import shutil as _shutil
    tmp = tempfile.mkdtemp(prefix="classify-known-miss-inject-")
    try:
        payload = b"<?php /* control */ echo 1; ?>"
        sha = hashlib.sha256(payload).hexdigest()
        with open(os.path.join(tmp, "unpacked-shard-member.php"), "wb") as fh:
            fh.write(payload)
        # Same length, different content: the size index must not be able to answer.
        decoy = bytes(len(payload))
        with open(os.path.join(tmp, "decoy.bin"), "wb") as fh:
            fh.write(decoy)
        row = {"sha256": sha, "size": len(payload)}
        found = resolve_bytes([row], [tmp], out=open(os.devnull, "w"))
        case("a file only under an extra root is resolved  -> found", sha in found)
        case("  ...and it is the file with the matching content, not the decoy",
             found.get(sha, "").endswith("unpacked-shard-member.php"))
        missing = {"sha256": hashlib.sha256(b"never written").hexdigest(),
                   "size": len(payload)}
        found2 = resolve_bytes([missing], [tmp], out=open(os.devnull, "w"))
        case("  ...while a row whose bytes are absent       -> not found",
             missing["sha256"] not in found2)
        case("  ...even though a file of exactly its size is right there",
             os.path.getsize(os.path.join(tmp, "decoy.bin")) == missing["size"])
    finally:
        _shutil.rmtree(tmp, ignore_errors=True)

    print()
    print("=== a name finding is not a finding about the bytes ===")
    # Pure half: which names are measured where they are. Both directions - a rule that renamed
    # everything would change every existing row's measurement, and one that renamed nothing
    # is the defect.
    for name, want in (("index.php", "index.php"), (".htaccess", ".htaccess"),
                       ("wp-config.php", "wp-config.php"), ("a_b.c-d.txt", "a_b.c-d.txt"),
                       # Synthetic shapes, one per character class the name rules read,
                       # none of them spelled as a name the collection actually holds.
                       ("-remap.htaccess", "sample.htaccess"),
                       ("x$(true)y.mdb", "sample.mdb"),
                       ("x;true;y.zip", "sample.zip"),
                       ("x.php\ny.mdb", "sample.mdb"),
                       ("x%00y.mdb", "sample.mdb"),
                       ("x.mdb ", "sample")):
        case("measured as %-24s <- %r" % (want, name[:28]),
             measured_name(os.path.join("/x", name)) == want)

    # End-to-end half, against the real scanner, because the property is about what `check`
    # reports and a stubbed `check` would only restate the assumption. Fails loudly rather
    # than skipping when there is no scanner, as verify.py's end-to-end section does.
    if not os.path.exists(SCANNER):
        case("a scanner to run the end-to-end cases against (%s)" % SCANNER, False)
    else:
        tmp = tempfile.mkdtemp(prefix="classify-known-miss-names-")
        try:
            remap = os.path.join(tmp, "-remap.htaccess")
            with open(remap, "wb") as fh:
                fh.write(b"AddType application/x-httpd-php .mdb\n")
            at_stored = _check(remap)
            rules, stored = check_rules(remap)
            kind, _ = classify(True, rules, False)
            # The power half first: without it the next case would pass on a scanner that
            # reads no names at all, and prove nothing about the repair.
            case("a leading-dash name fires a name rule at its stored path", bool(at_stored))
            case("  ...and the bytes under a neutral name fire nothing", rules == [])
            case("  ...so the row is a rule-gap, not detected-not-shippable",
                 kind == MISS_KIND)
            case("  ...and what the stored name fired is kept beside the rules",
                 stored == at_stored)

            shell = os.path.join(tmp, "x$(true)y.mdb")
            with open(shell, "wb") as fh:
                fh.write(b"<?php echo shell_exec($_GET['c']); ?>")
            s_rules, s_stored = check_rules(shell)
            s_kind, _ = classify(True, s_rules, False)
            case("a content rule under a hostile name still fires on the bytes",
                 bool(s_rules))
            case("  ...minus what only the name fired", bool(s_stored)
                 and set(s_rules) < set(s_stored))
            case("  ...so the row is NOT a rule-gap", s_kind == "detected-not-shippable")

            plain = os.path.join(tmp, "shell.php")
            with open(plain, "wb") as fh:
                fh.write(b"<?php echo shell_exec($_GET['c']); ?>")
            p_rules, p_stored = check_rules(plain)
            case("a safe name is measured where it is, with nothing recorded beside it",
                 p_stored is None and p_rules == s_rules)
        finally:
            _shutil.rmtree(tmp, ignore_errors=True)

    print()
    print("=== --sha-file narrows the rows, and says what it could not find ===")
    rows = [{"sha256": "a" * 64}, {"sha256": "b" * 64}]
    picked, missing = select_rows(rows, ["b" * 64, "c" * 64])
    case("a listed row that exists is measured", [r["sha256"] for r in picked] == ["b" * 64])
    case("  ...one that does not is returned, not dropped", missing == ["c" * 64])
    case("  ...and an unlisted row is not measured", "a" * 64 not in {r["sha256"] for r in picked})

    print()
    print("=== the vocabulary is closed ===")
    produced = set()
    for reach in (True, False):
        for rules in ([], ["X001"]):
            for ships in (True, False):
                k, _ = classify(reach, rules, ships)
                if k is not None:
                    produced.add(k)
    case("every kind classify() can produce is in KINDS", produced <= set(KINDS))
    case("every kind in KINDS is reachable from classify()", produced == set(KINDS))

    print()
    print("cases: %d · passed: %d · failed: %d"
          % (len(cases), len(cases) - len(fails), len(fails)))
    for f in fails:
        print("FAIL:", f)
    return 1 if fails else 0


# --------------------------------------------------------------------------- modes

def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--apply", action="store_true", help="write the kind onto the rows")
    ap.add_argument("--check", action="store_true",
                    help="exit non-zero if any known_miss row carries no kind")
    ap.add_argument("--inject", action="store_true", help="controls, both directions")
    ap.add_argument("--date", default=datetime.date.today().isoformat())
    ap.add_argument("--sha-file", default=None,
                    help="measure and apply only the known_miss rows whose sha256 is listed, "
                         "one per line. Without it every row is re-measured, and every block "
                         "records the binary it was measured with, so a full run restamps "
                         "every known_miss row in both halves")
    a = ap.parse_args()

    if sum([a.apply, a.check, a.inject]) > 1:
        sys.exit("--apply, --check and --inject are different questions; pass one")
    if a.inject:
        return inject()

    published, local = read_jsonl(PUBLISHED), read_jsonl(LOCAL)
    rows = [r for r in published + local if is_known_miss(r)]
    print("known_miss rows: %d (published %d, local %d)"
          % (len(rows), sum(1 for r in published if is_known_miss(r)),
             sum(1 for r in local if is_known_miss(r))))
    if a.sha_file and a.check:
        sys.exit("--check answers about every known_miss row; --sha-file would narrow it")

    if a.check:
        total, in_scope = survey(rows)
        bad = total.get("<unclassified>", 0)
        for kind in KINDS:
            print("  %-26s %5d  (%d outside the rules' own source material)"
                  % (kind, total.get(kind, 0), in_scope.get(kind, 0)))
        unknown = sorted(k for k in total if k not in KINDS and k != "<unclassified>")
        if unknown:
            print("rows carrying a kind outside the vocabulary: %s" % ", ".join(unknown))
        if bad:
            print("REFUSE: %d known_miss row(s) carry no %s. Run --apply." % (bad, KIND_FIELD))
        return 1 if (bad or unknown) else 0

    if a.sha_file:
        wanted = [l.strip() for l in open(a.sha_file, encoding="utf-8") if l.strip()]
        rows, missing = select_rows(rows, wanted)
        if missing:
            sys.exit("REFUSE: %d listed sha256 name no known_miss row: %s"
                     % (len(missing), ", ".join(s[:12] for s in missing)))
        print("restricted by --sha-file to %d row(s)" % len(rows))

    kinds, refused = measure(rows, a.date)
    counts = collections.Counter(k for k, _ in kinds.values())
    in_scope = collections.Counter(
        kinds[r["sha256"]][0] for r in rows if r["sha256"] in kinds
        and not r.get("predates_ruleset"))
    print()
    print("%-26s %6s %6s" % ("kind", "all", "in scope"))
    for kind in KINDS:
        print("%-26s %6d %6d" % (kind, counts.get(kind, 0), in_scope.get(kind, 0)))
    print("%-26s %6d %6d" % ("(total)", sum(counts.values()), sum(in_scope.values())))

    by_family = collections.Counter(
        r.get("family") for r in rows
        if kinds.get(r["sha256"], (None,))[0] == "detected-not-shippable")
    if by_family:
        print()
        print("detected, nothing ships the bytes - by family:")
        for family, n in by_family.most_common():
            print("   %-40s %d" % (family, n))

    if refused:
        print()
        print("REFUSED (%d) - these are promotions, not states to publish:" % len(refused))
        for sha, family, rules, why in refused:
            print("   %s %-34s %s" % (sha[:12], family, ",".join(rules)))
            print("      %s" % why)

    if a.apply:
        print()
        for path in (PUBLISHED, LOCAL):
            changed, unchanged = apply_half(path, kinds, dry_run=False)
            print("  %-38s %d row(s) written, %d already current"
                  % (os.path.relpath(path, ROOT), changed, unchanged))
        print()
        print("regenerate the summary and the documents: make-summary.py, doc-figures.py")
    else:
        print()
        print("nothing written. Pass --apply to record these on the rows.")
    return 1 if refused else 0


if __name__ == "__main__":
    sys.exit(main())
