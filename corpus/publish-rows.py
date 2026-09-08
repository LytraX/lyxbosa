#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Move rows from the local half of the index to the published half.

Publication had no tool. Every previous round that moved rows did it with a script written
for that round and thrown away, which is how four published rows came to carry `origin` - a
path on a customer host - because a promotion "built the new row out of the whole local
row". `shard-gate.py` catches that one now, after the fact. This refuses it before.

WHAT PUBLISHING A ROW IS, AND WHAT IT IS NOT
---------------------------------------------
It is one thing: the row moves from `corpus/local/index-local.jsonl` to
`corpus/index.jsonl`, and the fields the published half may not carry are dropped. It is
NOT a review, a masking pass, a clearance, or a decision that a held row may be released.
Every one of those is somebody else's act and this tool refuses rather than performing it:

  * a row carrying `local_only` is REFUSED. That marker is a hold somebody placed, and 757
    rows carry the specific hold "verdict proposed by an automated review pass ... awaiting
    human confirmation". Clearing it here would make the mover the confirmer.
  * a row that `shard-gate.evaluate()` does not find publishable TODAY is REFUSED, and the
    stored `publishable` flag is never read. A stored copy of a derived answer is exactly
    what `shard-gate.py`'s docstring is about; trusting it here would let a stale `true`
    publish a blocked row.
  * a row tagged `pii` or `content` is REFUSED, restated locally rather than inherited,
    because §7.2 bullet 2 is the one rule whose failure cannot be undone by a later round.

WHY `origin` IS DROPPED AND NOTHING ELSE IS
--------------------------------------------
`origin` records where a sample sat on a customer machine: an absolute path, an account, an
mtime. It is not verifiable by a stranger and it is not ours to publish. Every other field
survives, including `note`, `bucket` and `sensitivity_evidence`, because a published row
that explains itself is the point of the corpus.

The list is data (`STRIP`) rather than a `pop()` in the middle of the move, so `--inject`
can assert that a row is refused when a stripped field would have survived - and so that
adding a field to it is a one-line change with a control already watching it.

THE PUBLISHED-HALF FORM RULES ARE ASKED OF THE ROW AS IT WILL LAND
-------------------------------------------------------------------
`shard-gate.py` asserts two things about a published row that this tool can check first:
every `/home<n>/<x>/` has `<x>` in `acctNN` form, and `site`/`server` are `siteNN`/`srvNN`.
They are re-asked here over the row AFTER stripping, because the question is about what
lands in the published file and not about what was in the local one.

BOTH HALVES MOVE UNDER BOTH LOCKS, OR NEITHER DOES
---------------------------------------------------
A move is two writes and there is a moment between them. Taking both locks for the whole
read-modify-write, re-reading inside them, and writing the published half FIRST means the
only reachable interruption leaves a row in both halves - visible, and repairable by hand -
rather than in neither, which is a deleted sample with no record that it existed.

  corpus/publish-rows.py --sha-file F [--require-stage DIR] [--apply]
  corpus/publish-rows.py --inject
"""
import argparse, hashlib, json, os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
from indexio import index_lock, read_jsonl, write_jsonl_atomic          # noqa: E402

PUBLISHED = os.path.join(HERE, "index.jsonl")
LOCAL = os.path.join(HERE, "local", "index-local.jsonl")

# Fields the published half may not carry. See the docstring; kept as data so --inject can
# assert the strip actually happens rather than trusting that it was written correctly.
STRIP = ("origin",)

# §7.2 bullet 2. Restated rather than imported: the one rule that cannot be undone later
# should not be reachable only through another module's import succeeding.
NEVER_PUBLISHED = ("pii", "content")

HOME_RE = re.compile(r'/home\d*/([^/"]+)/')
ACCT_RE = re.compile(r'acct\d+$')
FORM = (("site", re.compile(r'^site\d+$'), "siteNN"),
        ("server", re.compile(r'^srv\d+$'), "srvNN"))


def _gate():
    """shard-gate's evaluator, imported by path because the filename has a hyphen."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "shard_gate", os.path.join(HERE, "shard-gate.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def stripped(row):
    """The row as it would land in the published half."""
    return {k: v for k, v in row.items() if k not in STRIP}


def form_violations(row):
    """The published-half form rules, asked of the row as it will land."""
    why = []
    for comp in HOME_RE.findall(json.dumps(row)):
        if not ACCT_RE.match(comp):
            why.append("a /home path component is not in acctNN form (%d chars)" % len(comp))
    for key, pat, want in FORM:
        val = row.get(key)
        if val is not None and not pat.match(str(val)):
            why.append("%s is not in %s form" % (key, want))
    return why


def adjudicate(shas, local, published, evaluate, stage=None):
    """(moving, refused). The whole decision, so a dry run and --apply agree.

    Nothing is written here and nothing raises: a refusal is a returned reason, because a
    tool that stops on the first bad row makes the operator re-run it once per problem.
    """
    lmap = {r["sha256"]: r for r in local}
    pmap = {r["sha256"]: r for r in published}
    moving, refused = [], []
    for sha in shas:
        r = lmap.get(sha)
        if r is None:
            refused.append((sha, "not in the local half"
                                 + (": already published" if sha in pmap else "")))
            continue
        if sha in pmap:
            refused.append((sha, "already in the published half"))
            continue
        if r.get("verdict") == "unreviewed":
            refused.append((sha, "verdict is unreviewed: nothing leaves that state "
                                 "without a human"))
            continue
        if r.get("local_only"):
            refused.append((sha, "marked local_only: %s. That is a hold somebody placed; "
                                 "releasing it is their act, not this tool's"
                            % r["local_only"]))
            continue
        tags = set(r.get("sensitivity") or [])
        bad = sorted(tags & set(NEVER_PUBLISHED))
        if bad:
            refused.append((sha, "tagged %s, which is never published" % ",".join(bad)))
            continue
        ok, why = evaluate(r)
        if not ok:
            refused.append((sha, "not publishable today: %s" % "; ".join(why)))
            continue
        out = stripped(r)
        viol = form_violations(out)
        if viol:
            refused.append((sha, "; ".join(viol)))
            continue
        if stage is not None and sha not in stage:
            refused.append((sha, "no staged shard member carries these bytes"))
            continue
        moving.append((sha, r, out))
    return moving, refused


def staged_sources(stage_root):
    """{source_sha256} over every MANIFEST.json under `stage_root`."""
    out = set()
    for name in sorted(os.listdir(stage_root)):
        mp = os.path.join(stage_root, name, "MANIFEST.json")
        if os.path.exists(mp):
            for e in json.load(open(mp, encoding="utf-8")):
                if e.get("source_sha256"):
                    out.add(e["source_sha256"])
    return out


def apply_move(moving):
    """Both halves, both locks, published written first. See the docstring."""
    moved = {sha for sha, _r, _o in moving}
    with index_lock(PUBLISHED), index_lock(LOCAL):
        pub = read_jsonl(PUBLISHED)          # re-read INSIDE the locks
        loc = read_jsonl(LOCAL)
        have = {r["sha256"] for r in pub}
        add = [o for sha, _r, o in moving if sha not in have]
        write_jsonl_atomic(PUBLISHED, pub + add)
        write_jsonl_atomic(LOCAL, [r for r in loc if r["sha256"] not in moved])
    return len(add)


# --------------------------------------------------------------------------- controls

def inject():
    """Every refusal, plus both directions on the strip. See AGENTS.md.

    The cases that matter are the ones asserting a row is REFUSED. A mover whose checks all
    passed vacuously would publish everything and report success, which is the shape of the
    404-read-as-success check AGENTS.md records.
    """
    rc = 0

    def case(name, got, want):
        nonlocal rc
        ok = got == want
        print("  %-64s %s" % (name, "caught" if ok else "MISSED"))
        if not ok:
            print("      got %r want %r" % (got, want))
            rc = 1

    def row(**kw):
        base = {"sha256": "a" * 64, "verdict": "malicious", "sensitivity": ["clean"],
                "publishable": True, "origin": {"path": "/root/INCIDENT/acct04/x.php"},
                "expect": {"must_detect": ["PHI009"]}}
        base.update(kw)
        return base

    def run(rows, published=(), evaluate=lambda r: (True, []), stage=None):
        moving, refused = adjudicate([r["sha256"] for r in rows], rows, list(published),
                                     evaluate, stage)
        return ("moved" if moving else refused[0][1])

    print("=== a row that should move ===")
    case("a clean, publishable, reviewed row moves", run([row()]), "moved")

    print("=== refusals: each must be reachable ===")
    got = run([row(verdict="unreviewed")])
    case("an unreviewed row is refused", got.startswith("verdict is unreviewed"), True)
    got = run([row(local_only="awaiting human confirmation")])
    case("a local_only hold is refused, not cleared", got.startswith("marked local_only"), True)
    for tag in NEVER_PUBLISHED:
        got = run([row(sensitivity=[tag])])
        case("a %s-tagged row is refused" % tag, got.startswith("tagged %s" % tag), True)
    got = run([row()], evaluate=lambda r: (False, ["secret gate did not pass"]))
    case("the gate's answer is used, not the stored flag",
         got == "not publishable today: secret gate did not pass", True)
    # The reason is asserted by the field and the form it names, not by the whole sentence:
    # a case that pins the prose fails on a reworded message and says nothing about the rule,
    # which is how `doc-figures.py --inject` spent six rounds red.
    got = run([row(site="acme-hosting")])
    case("a site that is not siteNN is refused",
         got.startswith("site is not") and "siteNN" in got, True)
    got = run([row(server="box17")])
    case("a server that is not srvNN is refused",
         got.startswith("server is not") and "srvNN" in got, True)
    got = run([row(note="found under /home2/notapseudonym/public_html/x")])
    case("a /home path that is not acctNN is refused",
         got.startswith("a /home path component is not in acctNN form"), True)
    got = run([row(note="found under /home2/acct04/public_html/x")])
    case("a /home path in acctNN form is allowed", got, "moved")
    got = run([row()], published=[{"sha256": "a" * 64}])
    case("a row already published is refused", got == "already in the published half", True)
    moving, refused = adjudicate(["b" * 64], [row()], [], lambda r: (True, []))
    case("a sha in neither half is refused", refused[0][1], "not in the local half")
    got = run([row()], stage=set())
    case("--require-stage refuses a row nothing stages",
         got == "no staged shard member carries these bytes", True)
    got = run([row()], stage={"a" * 64})
    case("--require-stage passes a row the stage carries", got, "moved")

    print("=== the strip, both directions ===")
    out = stripped(row())
    case("origin does not survive the move", "origin" in out, False)
    case("everything else does", sorted(out) == sorted(k for k in row() if k != "origin"), True)
    # The direction that matters: if STRIP were empty the move would carry a host path, and
    # the form check must be what catches it rather than nothing at all.
    leaked = {k: v for k, v in row().items()}
    case("an unstripped origin trips the form rule",
         bool(form_violations(dict(leaked, origin={"path": "/home2/realname/x.php"}))), True)

    print("=== the gate is the real shard-gate, not a stand-in ===")
    ev = _gate().evaluate
    case("shard-gate.evaluate refuses an unreviewed row",
         ev({"sha256": "a" * 64, "verdict": "unreviewed", "sensitivity": ["clean"]})[0], False)
    case("shard-gate.evaluate passes a clean reviewed row",
         ev({"sha256": "a" * 64, "verdict": "malicious", "sensitivity": ["clean"]})[0], True)

    print("controls: %s" % ("all cases behaved" if rc == 0 else "AT LEAST ONE MISSED"))
    return rc


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sha-file", help="one sha256 per line; # comments allowed")
    ap.add_argument("--require-stage", metavar="DIR",
                    help="refuse a row no staged shard member carries")
    ap.add_argument("--apply", action="store_true", help="write. Default is a dry run.")
    ap.add_argument("--inject", action="store_true", help="positive control")
    a = ap.parse_args()

    if a.inject:
        return inject()
    if not a.sha_file:
        return ap.error("--sha-file is required (or --inject)")

    shas = [l.split("#")[0].strip() for l in open(a.sha_file, encoding="utf-8")]
    shas = [s for s in shas if s]
    stage = staged_sources(a.require_stage) if a.require_stage else None

    published = read_jsonl(PUBLISHED)
    local = read_jsonl(LOCAL)
    moving, refused = adjudicate(shas, local, published, _gate().evaluate, stage)

    print("requested : %d" % len(shas))
    print("to publish: %d" % len(moving))
    print("refused   : %d" % len(refused))
    if refused:
        print()
        print("=== REFUSED ===")
        for sha, why in refused:
            print("  %s  %s" % (sha[:12], why))
    if moving:
        print()
        for sha, r, _o in moving[:3]:
            print("  %s  %s  %s" % (sha[:12], r.get("family"), r.get("reason")))
        if len(moving) > 3:
            print("  ... and %d more" % (len(moving) - 3))

    if not a.apply:
        print()
        print("(dry run: nothing written. Pass --apply.)")
        return 1 if refused else 0

    if refused:
        print()
        print("refusing to write while any row is refused: fix them or drop them from the "
              "list, so a partial publication is never a silent one")
        return 1
    n = apply_move(moving)
    print()
    print("published %d row(s); local half is %d shorter" % (n, len(moving)))
    print("now run: corpus/shard-gate.py corpus/index.jsonl --fix")
    return 0


if __name__ == "__main__":
    sys.exit(main())
