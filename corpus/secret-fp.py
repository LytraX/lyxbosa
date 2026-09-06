#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The stock-CMS null for the SECRET gate's shapes, per shape class rather than in aggregate.

WHY THIS EXISTS
---------------
`verify-content-mask.py --stock-fp` and `--base-rate` are both nulls for the IDENTIFIER
gates. They answer "how often does a customer-name predicate fire on files that contain no
customer of ours", and every identifier finding on a row cites one of them. The SECRET gate
had no such null at all: a row records `secret_literals_carried_over: 2` and there is nothing
to say whether two credential-SHAPED literals in a megabyte of vendored library code is a lot
or the number you get for free.

That asymmetry matters because the two gates fail for opposite reasons. An identifier finding
says *a name is present*; a secret finding says *a credential-shaped literal did not change
across masking*. Stock CMS trees carry no customer credential by construction, so every
`quoted-credential` literal in them is a shape false positive of exactly the kind a clearance
has to be argued against.

WHY IT IS NOT A FLAG ON `verify-content-mask.py`
------------------------------------------------
That file is in `gate_provenance.TOOLS`. Adding a mode to it moves the tools digest, and
moving the tools digest invalidates every human clearance and every stamp keyed to the old
one - 140 stamps and two clearances the last time it happened, for a repair that was worth
it. A null model is a measurement ABOUT the gate, not part of it, and it must not cost that.
So this imports the tracked predicate (`SECRET_SHAPES`, `secret_literals`) rather than
restating it - the thing measured is the real one - and lives outside the digest.

WHY THE CLASS BREAKDOWN AND NOT A TOTAL
----------------------------------------
AGENTS.md's rule for a false-positive argument is that the collision is named by SHAPE. A
total ("N literals across M stock files") cannot support a clearance on one literal, because
the clearance is about that literal's class: its shape, the keyword that fired, the length of
its value, and whether the value contains a space. That last one is the discriminator that
does the work - a credential does not usually contain a space and a UI message usually does -
and it is reported rather than assumed, because a null that has never been broken down is the
aggregate table this was written to replace.

Values never leave this file. Only counts, lengths and character-class counts do, which is
`secret_literals`' own contract restated one level up.

    corpus/secret-fp.py --sample 8000
    corpus/secret-fp.py --sample 2000 --no-layers      # plaintext only, much faster
    corpus/secret-fp.py --inject
"""
import argparse, importlib.util, json, os, random, re, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

_spec = importlib.util.spec_from_file_location(
    "vcm_secret_fp", os.path.join(HERE, "verify-content-mask.py"))
VCM = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(VCM)

# The keyword alternation inside the tracked `quoted-credential` pattern, restated ONLY to
# report which alternative fired. It is asserted against the tracked pattern in `inject()`
# rather than trusted: a copy that has drifted would mislabel every row it classifies.
KEYWORD = re.compile(rb"(?i)(password|passwd|pwd|pass|api_key|apikey|secret)")

LEN_BUCKETS = ((0, 7), (8, 15), (16, 31), (32, 63), (64, 1 << 30))


def _bucket(n):
    for lo, hi in LEN_BUCKETS:
        if lo <= n <= hi:
            return "len=%d-%s" % (lo, "inf" if hi > 1 << 20 else hi)
    return "len=?"                                                   # pragma: no cover


def classify(shape, value, whole=None):
    """The class of one literal, by shape only. Never the value.

    `has_space` is separated out because it is the discriminator a clearance rests on, and
    `keyword` because the widened alternation is what a `quoted-credential` finding is
    actually about.
    """
    kw = None
    if whole is not None:
        m = KEYWORD.match(whole)
        kw = m.group(1).decode("latin-1").lower() if m else None
    return {"shape": shape, "bucket": _bucket(len(value)),
            "keyword": kw, "has_space": b" " in value,
            "alnum_only": bool(re.fullmatch(rb"[A-Za-z0-9]+", value))}


def key(c):
    return "%s kw=%s %s space=%s" % (c["shape"], c["keyword"] or "-", c["bucket"],
                                     "yes" if c["has_space"] else "no")


def literals_with_context(data, with_layers=True):
    """(shape, value, whole_match) for every literal, over the plaintext and each layer.

    `secret_literals()` returns (shape, value) and deliberately drops the surrounding match,
    which is what names the keyword. This re-runs the SAME tracked patterns to recover it and
    asserts the two agree on the literal set, so the classification cannot be reported for a
    population the tracked predicate does not have.
    """
    blobs = [data]
    if with_layers:
        blobs += [b for _m, b in VCM.decode_layers(data)]
    out = []
    for blob in blobs:
        for shape, rx in VCM.SECRET_SHAPES:
            for m in rx.finditer(blob):
                out.append((shape, m.group(rx.groups) if rx.groups else m.group(0),
                            m.group(0)))
    return out


def census(roots, sample=8000, seed=4242, with_layers=True, min_size=200,
           max_size=2000000, files=None):
    """The null: every credential-shaped literal in a sample of files that have no credential
    of anyone's in them.

    Sampling mirrors `verify-content-mask.stock_fp` - same size window, same shuffle-then-
    take, its own seed - so the two nulls describe the same population and a reader can
    compare them without re-deriving what each one scanned.
    """
    if files is None:
        files = []
        for root in roots:
            for base, _dirs, names in os.walk(root):
                for n in names:
                    p = os.path.join(base, n)
                    try:
                        if min_size <= os.path.getsize(p) <= max_size:
                            files.append(p)
                    except OSError:
                        pass
        random.Random(seed).shuffle(files)
        files = files[:sample]
    by, by_shape = {}, {}
    scanned = hitfiles = total = 0
    for p in files:
        try:
            with open(p, "rb") as fh:
                data = fh.read()
        except OSError:                                              # pragma: no cover
            continue
        scanned += 1
        found = literals_with_context(data, with_layers)
        # The tracked predicate is the authority on WHICH literals exist; this only adds the
        # keyword. If they ever disagree the classification is describing something else.
        tracked = VCM.secret_literals(data, with_layers=with_layers)
        if {(s, v) for s, v, _w in found} != tracked:                # pragma: no cover
            sys.exit("re-run of the tracked patterns disagreed with secret_literals() on %s; "
                     "refusing to report a class breakdown of a different population" % p)
        if found:
            hitfiles += 1
        for shape, value, whole in found:
            total += 1
            k = key(classify(shape, value, whole))
            by[k] = by.get(k, 0) + 1
            by_shape[shape] = by_shape.get(shape, 0) + 1
    return {"files_scanned": scanned, "files_with_a_literal": hitfiles,
            "total_literals": total, "with_layers": with_layers,
            "by_shape": dict(sorted(by_shape.items(), key=lambda kv: -kv[1])),
            "by_class": dict(sorted(by.items(), key=lambda kv: -kv[1]))}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--stock-root", action="append",
                    default=[os.path.join("trail-data", "CMS"),
                             os.path.join("trail-data", "CMS-ext")])
    ap.add_argument("--sample", type=int, default=8000)
    ap.add_argument("--seed", type=int, default=4242)
    ap.add_argument("--no-layers", action="store_true",
                    help="plaintext only. Much faster, and a DIFFERENT null - a finding "
                         "inside a decoded layer must not be argued against it")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--inject", action="store_true")
    a = ap.parse_args()
    if a.inject:
        return inject()
    for r in a.stock_root:
        if not os.path.isdir(r):
            sys.exit("stock root %s is not a directory; a null over nothing is not a null" % r)
    r = census(a.stock_root, sample=a.sample, seed=a.seed, with_layers=not a.no_layers)
    if a.json:
        print(json.dumps(r, indent=1))
        return 0
    print("stock roots            : %s" % ", ".join(a.stock_root))
    print("files scanned          : %d" % r["files_scanned"])
    print("decoded layers included: %s" % r["with_layers"])
    print("files with a literal   : %d (%.2f%%)"
          % (r["files_with_a_literal"],
             100.0 * r["files_with_a_literal"] / max(r["files_scanned"], 1)))
    print("credential-shaped literals, none of them anyone's credential: %d"
          % r["total_literals"])
    print()
    print("by shape:")
    for k, v in r["by_shape"].items():
        print("  %-22s %d" % (k, v))
    print()
    print("by class (shape, keyword, value length, whether the value contains a space):")
    for k, v in r["by_class"].items():
        print("  %-52s %d" % (k, v))
    return 0


# ---------------------------------------------------------------------------------------
# Controls. A null that can only report a number is not a null: it has to be shown to count
# a planted literal, to NOT count a file that has none, and to be classifying the same
# population the tracked predicate sees.
# ---------------------------------------------------------------------------------------

def inject():
    import tempfile
    fails, ran = [], []

    def case(label, got, want):
        ok = got == want
        ran.append(label)
        print("  %-66s %-20s %s" % (label, str(got)[:20],
                                    "ok" if ok else "WRONG (wanted %s)" % (want,)))
        if not ok:
            fails.append(label)

    d = tempfile.mkdtemp()
    clean = os.path.join(d, "clean.php")
    with open(clean, "wb") as fh:
        fh.write(b"<?php\n// nothing credential-shaped here at all\n$x = 1;\n" + b"a" * 300)
    planted = os.path.join(d, "planted.php")
    with open(planted, "wb") as fh:
        # An assignment, not a PHP array key: the tracked pattern requires the keyword to
        # be followed by `=` or `:`, so `'password' => '...'` - keyword inside quotes - does
        # not match it. Using that as a control fixture would test a pattern nobody wrote.
        fh.write(b"<?php\n$password = 'hunter2xyz';\n" + b"b" * 300)
    spacey = os.path.join(d, "spacey.js")
    with open(spacey, "wb") as fh:
        fh.write(b'var t = {enterPassword:"Enter password!"};\n' + b"c" * 300)

    print("=== it must COUNT what is there ===")
    r = census(None, files=[planted], with_layers=False)
    case("a planted quoted-credential is counted", r["total_literals"], 1)
    case("  and its file is counted as having one", r["files_with_a_literal"], 1)
    case("  and it is classed as having no space", 
         [k for k in r["by_class"] if "space=no" in k] != [], True)
    case("  and the keyword that fired is named", 
         [k for k in r["by_class"] if "kw=password" in k] != [], True)

    print("=== it must say ZERO where there is nothing, not merely stay quiet ===")
    r0 = census(None, files=[clean], with_layers=False)
    case("a file with no credential shape contributes none", r0["total_literals"], 0)
    case("  and is not counted as a hit file", r0["files_with_a_literal"], 0)
    case("  and the census still reports the file as scanned", r0["files_scanned"], 1)

    print("=== the space discriminator must actually separate the two ===")
    rs = census(None, files=[spacey], with_layers=False)
    case("a UI message value is counted", rs["total_literals"], 1)
    case("  and classed as containing a space", 
         [k for k in rs["by_class"] if "space=yes" in k] != [], True)
    case("  which is a DIFFERENT class from the planted credential",
         set(rs["by_class"]) & set(census(None, files=[planted], with_layers=False)["by_class"]),
         set())

    print("=== the keyword copy must match the tracked pattern, not drift from it ===")
    tracked_qc = dict(VCM.SECRET_SHAPES)["quoted-credential"].pattern
    words = set(re.findall(r"[a-z_]+", 
                           tracked_qc.decode("latin-1").split("(?![A-Za-z0-9_])")[0]
                           .split("(?:")[-1]))
    mine = set(re.findall(r"[a-z_]+", KEYWORD.pattern.decode("latin-1")))
    case("every keyword the tracked pattern has is one this can name",
         words - mine - {"i"}, set())

    print("=== it must be classifying the population the tracked predicate sees ===")
    both = census(None, files=[planted, spacey, clean], with_layers=False)
    tracked_n = sum(len(VCM.secret_literals(open(p, "rb").read(), with_layers=False))
                    for p in (planted, spacey, clean))
    case("total matches secret_literals() over the same files",
         both["total_literals"], tracked_n)

    print("=== --no-layers must be a different question, and say so ===")
    import base64 as _b64
    nested = os.path.join(d, "nested.php")
    # An UNQUOTED key, for the same reason: `{"password":"x"}` puts a quote between the
    # keyword and the colon and the tracked pattern does not match it. The literal this null
    # was written to explain sits in exactly this JS-object form.
    inner = b'{password:"deadbeefcafe",note:"padding so the base64 run is long enough"}'
    with open(nested, "wb") as fh:
        fh.write(b"<?php $z='" + _b64.b64encode(inner) + b"';\n" + b"d" * 300)
    case("a literal only inside a decoded layer is invisible without layers",
         census(None, files=[nested], with_layers=False)["total_literals"], 0)
    case("  and visible with them",
         census(None, files=[nested], with_layers=True)["total_literals"] >= 1, True)

    import shutil
    shutil.rmtree(d, ignore_errors=True)
    print()
    print("%d control(s) run, %d failed" % (len(ran), len(fails)))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
