#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Build, check and benchmark the derived SQLite read index. The library is derived_db.py.

  corpus/derive-index-db.py             build corpus/local/index.db from both halves
  corpus/derive-index-db.py --check     freshness AND a full row-by-row reconciliation
  corpus/derive-index-db.py --inject    the controls, in both directions
  corpus/derive-index-db.py --bench     what it bought: build, size, three queries vs a scan

`--check` is useful and it is NOT the mechanism. The mechanism is `derived_db.open_ro()`,
which verifies freshness as part of opening the file and raises if it cannot, so a stale read
is unperformable rather than merely detectable. `index-summary.json` could sit stale until a
human ran `--check` and it did, twice; `make-summary.SHIPPED` carried the comment "nothing
catches a stale set" and nothing did. A check somebody has to remember is the failure mode,
not the repair.

AN UNRECOGNISED ARGUMENT IS AN ERROR, NEVER THE DEFAULT. The default action here writes a
file, and `make-summary.py` reached its write path on `--help` for exactly this reason.
`argparse` errors on anything it does not know and `--inject` asserts that it does.
"""
import argparse, collections, json, os, shutil, sqlite3, subprocess, sys
import tempfile, time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import derived_db                                                       # noqa: E402
from derived_db import (SCHEMA_VERSION, SOURCES, DB_REL, DerivedDbError,   # noqa: E402
                        DatabaseMissing, SchemaUnrecognised, DatabaseStale)
from indexio import index_lock, LockBusy, write_jsonl_atomic            # noqa: E402


def human(n):
    """Decimal MB, because that is what SOURCES.md and CHANGELOG.md already quote."""
    for unit in ("B", "kB", "MB", "GB"):
        if n < 1000 or unit == "GB":
            return "%.1f %s" % (n, unit) if unit != "B" else "%d B" % n
        n /= 1000.0


# ------------------------------------------------------------------------------------ build

def cmd_build(a):
    stats = derived_db.build(db_path=a.db, repo=REPO, log=(print if a.verbose else None))
    print("built %s" % os.path.relpath(stats["db_path"], REPO))
    for rel, s in sorted(stats["sources"].items()):
        print("  %-32s %7d rows  %6d tags  %6d paths  sha256 %s"
              % (rel, s["rows"], s["tags"], s["paths"], s["sha256"][:12]))
    print("  %-32s %7d rows  %6d tags  %6d paths"
          % ("total", stats["rows"], stats["tags"], stats["paths"]))
    print("  index lock held %.2fs of a %.2fs build; %s on disk"
          % (stats["read_s"], stats["build_s"], human(stats["db_bytes"])))
    return 0


# ------------------------------------------------------------------------------------ check

def reconcile(conn, repo=REPO, expected=None):
    """Re-read the JSONL and compare every row, column, tag and path against the database.

    Freshness is not correctness: a passing `open_ro` proves the database was built from
    exactly these bytes, not that the builder derived them faithfully. This is the check for
    the second question, and it costs a full JSONL parse - which is the thing the database
    exists to avoid, which is why it is a check and not something a consumer runs.
    """
    expected = expected or derived_db.present_sources(repo)
    findings, counts = [], collections.Counter()

    for rel in expected:
        half = derived_db.HALF[rel]
        with open(os.path.join(repo, rel), "rb") as fh:
            data = fh.read()
        lines = [(i + 1, ln.decode("utf-8"))
                 for i, ln in enumerate(data.split(b"\n")) if ln.strip()]

        db_rows = {r["line_no"]: r for r in conn.execute(
            "SELECT * FROM row WHERE half = ?", (half,))}
        counts["%s: jsonl rows" % half] = len(lines)
        counts["%s: db rows" % half] = len(db_rows)
        if len(lines) != len(db_rows):
            findings.append("%s: %d rows in the file, %d in the database"
                            % (rel, len(lines), len(db_rows)))

        db_tags = collections.defaultdict(list)
        for r in conn.execute(
                "SELECT t.kind, t.value, w.line_no FROM row_tag t JOIN row w "
                "ON w.id = t.row_id WHERE w.half = ?", (half,)):
            db_tags[r["line_no"]].append((r["kind"], r["value"]))
        db_paths = collections.defaultdict(list)
        for r in conn.execute(
                "SELECT p.field, p.path, w.line_no FROM row_path p JOIN row w "
                "ON w.id = p.row_id WHERE w.half = ?", (half,)):
            db_paths[r["line_no"]].append((r["field"], r["path"]))

        cols = ("half", "line_no", "sha256", "size", "bucket", "family", "staging_dir",
                "verdict", "publishable", "reason", "account_hash", "origin_path", "json")
        for line_no, raw in lines:
            got = db_rows.get(line_no)
            if got is None:
                findings.append("%s line %d has no database row" % (rel, line_no))
                continue
            row = json.loads(raw)
            want = (None,) + derived_db._extract(row, half, line_no, raw)
            for name, value in zip(cols, want[1:]):
                if got[name] != value:
                    counts["column mismatches"] += 1
                    if len(findings) < 20:
                        findings.append("%s line %d: column %s differs"
                                        % (rel, line_no, name))
            wt = sorted(derived_db._tags(row))
            if sorted(db_tags.get(line_no, [])) != wt:
                counts["tag mismatches"] += 1
                if len(findings) < 20:
                    findings.append("%s line %d: tags differ" % (rel, line_no))
            wp = sorted(derived_db._paths(row))
            if sorted(db_paths.get(line_no, [])) != wp:
                counts["path mismatches"] += 1
                if len(findings) < 20:
                    findings.append("%s line %d: paths differ" % (rel, line_no))
            counts["rows compared"] += 1
            counts["tags compared"] += len(wt)
            counts["paths compared"] += len(wp)

    return findings, counts


def cmd_check(a):
    db = a.db or os.path.join(REPO, DB_REL)
    t0 = time.perf_counter()
    try:
        conn = derived_db.open_ro(db, repo=REPO)
    except DerivedDbError as exc:
        print("REFUSED: %s" % exc)
        print("\nThis is the reader's own verdict, produced by the same call every consumer "
              "makes. --check has no separate opinion.")
        return 1
    open_s = time.perf_counter() - t0

    info = derived_db.describe(conn)
    print("opened %s in %.3fs (schema %s, built %s)"
          % (os.path.relpath(db, REPO), open_s, info["meta"].get("schema_version"),
             info["meta"].get("built_at")))
    for s in info["sources"]:
        print("  %-32s %7d rows  sha256 %s  verified" % (s["path"], s["rows"],
                                                          s["sha256"][:12]))

    proven, why = derived_db.definitely_stale(db, repo=REPO)
    print("  cheap fingerprint: %s"
          % ("PROVES STALE - %s" % "; ".join(why) if proven else
             "no proof of staleness (which is not a claim of freshness, and open_ro "
             "hashed anyway)"))

    t1 = time.perf_counter()
    findings, counts = reconcile(conn, repo=REPO)
    recon_s = time.perf_counter() - t1
    conn.close()

    print("\nreconciliation against the JSONL (%.2fs):" % recon_s)
    for k in sorted(counts):
        print("  %-28s %d" % (k, counts[k]))
    if findings:
        print("\n%d finding(s):" % len(findings))
        for f in findings[:20]:
            print("  - %s" % f)
        return 1
    print("\nFRESH and faithful: every row, column, tag and path in the database matches "
          "the JSONL it was derived from.")
    print("Counts above are for reconciliation only. No round quotes a figure from this "
          "database; the denominators are index-summary.json and the JSONL.")
    return 0


# ------------------------------------------------------------------------------------ bench

def scan_jsonl(repo=REPO, expected=None):
    """The status quo: parse both halves. What every tool does today, once per invocation."""
    expected = expected or derived_db.present_sources(repo)
    out = []
    for rel in expected:
        half = derived_db.HALF[rel]
        with open(os.path.join(repo, rel), encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    out.append((half, json.loads(line)))
    return out


def cmd_bench(a):
    db = a.db or os.path.join(REPO, DB_REL)
    print("=== build ===")
    stats = derived_db.build(db_path=db, repo=REPO)
    print("  index lock held %.2fs (read and hash only), total build %.2fs"
          % (stats["read_s"], stats["build_s"]))
    src_bytes = sum(os.path.getsize(os.path.join(REPO, r))
                    for r in derived_db.present_sources(REPO))
    print("  database %s from %s of JSONL (%.0f%%), %d rows, %d tags, %d paths"
          % (human(stats["db_bytes"]), human(src_bytes),
             100.0 * stats["db_bytes"] / src_bytes, stats["rows"], stats["tags"],
             stats["paths"]))

    print("\n=== queries ===")
    print("Every DB figure below is reconciled against the JSONL scan in the same run; a")
    print("query whose result set differs is reported as a failure, not as a speed-up.")

    # Pick the query subjects from the data rather than hard-coding them, and describe the
    # path prefix by shape: it is a masked customer path and this file is tracked.
    rows = scan_jsonl(REPO)
    fam = collections.Counter(r.get("family") for _, r in rows if r.get("family"))
    family = fam.most_common(1)[0][0]
    pre = collections.Counter()
    for _, r in rows:
        o = r.get("origin")
        if isinstance(o, dict) and isinstance(o.get("path"), str):
            parts = o["path"].split("/")
            if len(parts) > 4:
                pre["/".join(parts[:4])] += 1
    prefix, prefix_n = pre.most_common(1)[0]

    # The `keys` variant answers the same question without materialising the rows - what a
    # review app does to paint a result list. It is reported beside the full variant so the
    # index cost and the json.loads cost are not conflated, which is the whole difference on
    # a large result set.
    queries = [
        ("cluster: family = %s" % family,
         lambda c: derived_db.find_by_cluster(c, "family", family),
         "SELECT sha256 FROM row WHERE family = ?", (family,),
         lambda rs: [r for _, r in rs if r.get("family") == family]),
        ("tag: sensitivity contains c2",
         lambda c: derived_db.find_by_tag(c, "sensitivity", "c2"),
         "SELECT r.sha256 FROM row_tag t JOIN row r ON r.id = t.row_id "
         "WHERE t.kind = 'sensitivity' AND t.value = ?", ("c2",),
         lambda rs: [r for _, r in rs if "c2" in (r.get("sensitivity") or [])]),
        ("path prefix: a %d-character, 3-segment masked path prefix"
         % len(prefix),
         lambda c: derived_db.find_by_path_prefix(c, prefix),
         "SELECT DISTINCT r.sha256 FROM row_path p JOIN row r ON r.id = p.row_id "
         "WHERE p.path >= ? AND p.path < ?", (prefix, derived_db._prefix_upper(prefix)),
         lambda rs: [r for _, r in rs
                     if isinstance(r.get("origin"), dict)
                     and isinstance(r["origin"].get("path"), str)
                     and r["origin"]["path"].startswith(prefix)]),
    ]

    fails = []
    print("\n%-46s %8s %8s %8s %8s %8s %7s"
          % ("query", "rows", "scan", "db open", "db rows", "db keys", "speed-up"))
    print("-" * 100)
    for label, db_q, key_sql, key_args, scan_q in queries:
        t = time.perf_counter()
        want = scan_q(scan_jsonl(REPO))
        scan_s = time.perf_counter() - t

        t = time.perf_counter()
        conn = derived_db.open_ro(db, repo=REPO)
        open_s = time.perf_counter() - t
        t = time.perf_counter()
        got = db_q(conn)
        query_s = time.perf_counter() - t
        t = time.perf_counter()
        keys = [r[0] for r in conn.execute(key_sql, key_args)]
        keys_s = time.perf_counter() - t
        conn.close()

        ok = (sorted(r.get("sha256") or "" for r in got)
              == sorted(r.get("sha256") or "" for r in want) == sorted(keys))
        if not ok:
            fails.append("%s: db returned %d rows, keys %d, the scan %d"
                         % (label, len(got), len(keys), len(want)))
        print("%-46s %8d %7.3fs %7.3fs %7.3fs %7.3fs %6.1fx"
              % (label[:46], len(got), scan_s, open_s, query_s, keys_s,
                 scan_s / max(open_s + query_s, 1e-9)))
        print("%-46s %s" % ("", "reconciled against the scan, and the keys-only query "
                            "returns the same set" if ok else "MISMATCH"))

    print("\n'db open' is the freshness check: it hashes both halves every time and there is")
    print("no way to skip it. It is charged to the database in the speed-up because a")
    print("consumer pays it on every invocation, which is what makes the comparison honest.")
    print("'db rows' materialises every matching row through json.loads; 'db keys' answers")
    print("the same query without doing so. The gap between them is not index cost.")
    print("The speed-up column uses 'db rows', the pessimistic of the two.")
    if fails:
        print("\nFAILED:")
        for f in fails:
            print("  - %s" % f)
        return 1
    return 0


# ----------------------------------------------------------------------------------- inject

def _mini(tmp, pub_rows, loc_rows=None):
    """A miniature repo: corpus/index.jsonl and corpus/local/index-local.jsonl."""
    os.makedirs(os.path.join(tmp, "corpus", "local"), exist_ok=True)
    write_jsonl_atomic(os.path.join(tmp, "corpus", "index.jsonl"), pub_rows)
    if loc_rows is not None:
        write_jsonl_atomic(os.path.join(tmp, "corpus", "local", "index-local.jsonl"),
                           loc_rows)
    return os.path.join(tmp, DB_REL)


def _pub(i, **kw):
    r = {"sha256": "%064x" % i, "size": 100 + i, "bucket": "recovery/stock",
         "verdict": "benign", "publishable": True, "reason": "pinned-benign-hash",
         "sensitivity": ["clean"], "discovered_by": ["manual-sweep"],
         "an_unmodelled_field": {"nested": ["kept", i]}}
    r.update(kw)
    return r


def _loc(i, path, **kw):
    r = {"sha256": "%064x" % (10000 + i), "size": 200 + i, "bucket": "quarantine/evidence",
         "verdict": "malicious", "publishable": False, "sensitivity": ["unreviewed"],
         "discovered_by": ["manual-sweep"], "technique": ["webshell-eval"],
         "family": "fam-a", "publish_blockers": ["unreviewed"],
         "origin": {"path": path, "mode": "100644", "mtime": 1, "account_hash": "abcd"},
         "placements": {"live webroot: plugin or theme directory": 1}}
    r.update(kw)
    return r


class Cases(object):
    def __init__(self):
        self.fails = []
        self.n = 0

    def case(self, label, ok, detail=""):
        self.n += 1
        print("  %-64s %s%s" % (label[:64], "ok" if ok else "WRONG",
                                ("  (%s)" % detail) if detail and not ok else ""))
        if not ok:
            self.fails.append(label)

    def refuses(self, label, fn, want_exc, want_in=()):
        """The refusal must fire, be the right KIND, and NAME the thing that moved."""
        try:
            conn = fn()
            conn.close()
            self.case(label, False, "opened")
            return
        except Exception as exc:                                # noqa: BLE001
            kind_ok = isinstance(exc, want_exc)
            named = [w for w in want_in if w not in str(exc)]
            self.case(label, kind_ok and not named,
                      "raised %s%s" % (type(exc).__name__,
                                       "; message omits %s" % named if named else ""))

    def accepts(self, label, fn, expect_rows=None):
        try:
            conn = fn()
        except Exception as exc:                                # noqa: BLE001
            self.case(label, False, "refused: %s" % str(exc).splitlines()[0])
            return None
        if expect_rows is not None:
            got = conn.execute("SELECT COUNT(*) FROM row").fetchone()[0]
            self.case(label, got == expect_rows, "holds %d rows, wanted %d"
                      % (got, expect_rows))
        else:
            self.case(label, True)
        conn.close()
        return True


def cmd_inject(a):
    """Controls in both directions.

    A refusal that always fires and one that never fires look identical from a green run,
    and that shape has appeared three times in this repository. So every negative case here
    has a positive beside it, and the positive is not decoration: a reader that refused
    everything would satisfy every "must refuse" case in this file and be useless.
    """
    c = Cases()
    tmp = tempfile.mkdtemp(prefix="derived-db-inject.")
    try:
        pub = [_pub(i) for i in range(60)]
        loc = [_loc(i, "/home%d/acct%04d/public_html/wp-content/f%d.php"
                    % (2 + i % 2, i, i)) for i in range(40)]
        db = _mini(tmp, pub, loc)
        derived_db.build(db_path=db, repo=tmp)

        print("=== the positive direction: a fresh database opens ===")
        c.accepts("a database just built from both halves opens",
                  lambda: derived_db.open_ro(db, repo=tmp), 100)
        conn = derived_db.open_ro(db, repo=tmp)
        info = derived_db.describe(conn)
        c.case("it records the schema version it was built by",
               info["meta"].get("schema_version") == str(SCHEMA_VERSION))
        c.case("it records a build time and both sources with hashes and row counts",
               bool(info["meta"].get("built_at")) and len(info["sources"]) == 2
               and all(s["sha256"] and s["rows"] for s in info["sources"]))
        c.case("a field no column extracts survives verbatim in row.json",
               json.loads(conn.execute(
                   "SELECT json FROM row WHERE half='published' AND line_no=1"
               ).fetchone()[0]).get("an_unmodelled_field") == {"nested": ["kept", 0]})
        conn.close()

        # An index rewritten to identical bytes: new inode, new mtime, same content. The
        # contract is the content, so this MUST still open - the control on the refusal not
        # simply always firing.
        write_jsonl_atomic(os.path.join(tmp, "corpus", "index.jsonl"), pub)
        c.accepts("an index atomically rewritten to IDENTICAL bytes still opens",
                  lambda: derived_db.open_ro(db, repo=tmp), 100)

        print("\n=== a source that moved is refused, and the refusal names WHICH ===")
        pub2 = pub + [_pub(999)]
        write_jsonl_atomic(os.path.join(tmp, "corpus", "index.jsonl"), pub2)
        c.refuses("the published half gained a row", lambda: derived_db.open_ro(db, repo=tmp),
                  DatabaseStale, ["corpus/index.jsonl", "MOVED"])
        conn_msg = ""
        try:
            derived_db.open_ro(db, repo=tmp)
        except DatabaseStale as exc:
            conn_msg = str(exc)
        c.case("and it does NOT name the half that did not move",
               "index-local.jsonl" not in conn_msg)

        write_jsonl_atomic(os.path.join(tmp, "corpus", "index.jsonl"), pub)
        write_jsonl_atomic(os.path.join(tmp, "corpus", "local", "index-local.jsonl"),
                           loc[:-1])
        c.refuses("the local half lost a row", lambda: derived_db.open_ro(db, repo=tmp),
                  DatabaseStale, ["corpus/local/index-local.jsonl", "MOVED"])
        try:
            derived_db.open_ro(db, repo=tmp)
        except DatabaseStale as exc:
            c.case("and it does NOT name the published half", "corpus/index.jsonl:"
                   not in str(exc) and "corpus/index.jsonl MOVED" not in str(exc))

        write_jsonl_atomic(os.path.join(tmp, "corpus", "index.jsonl"), pub2)
        c.refuses("both halves moved: both are named",
                  lambda: derived_db.open_ro(db, repo=tmp), DatabaseStale,
                  ["corpus/index.jsonl", "corpus/local/index-local.jsonl"])
        write_jsonl_atomic(os.path.join(tmp, "corpus", "index.jsonl"), pub)
        write_jsonl_atomic(os.path.join(tmp, "corpus", "local", "index-local.jsonl"), loc)
        c.accepts("both restored to the built bytes: it opens again",
                  lambda: derived_db.open_ro(db, repo=tmp), 100)

        print("\n=== the one that matters: the reader cannot be talked into a stale read ===")
        # Byte-for-byte the same LENGTH, and the mtime and size restored to exactly what the
        # database recorded. Everything a cheap fingerprint can see says fresh.
        #
        # Rebuild first, so the recorded fingerprint is the file as it stands now. Without
        # this the atomic rewrites above have already moved the inode, `definitely_stale`
        # answers True for that reason, and the case would pass while proving nothing about
        # tampering - a control that cannot fail is the shape this repository keeps paying
        # for.
        loc_path = os.path.join(tmp, "corpus", "local", "index-local.jsonl")
        derived_db.build(db_path=db, repo=tmp)
        proven, why = derived_db.definitely_stale(db, repo=tmp)
        c.case("baseline: straight after a build the fingerprint proves nothing stale",
               proven is False, "; ".join(why))
        before = os.stat(loc_path)
        with open(loc_path, "rb") as fh:
            body = fh.read()
        i = body.index(b"malicious")
        tampered = body[:i] + b"benignXXX" + body[i + len(b"malicious"):]
        assert len(tampered) == len(body)
        with open(loc_path, "r+b") as fh:                 # in place: the inode is kept
            fh.write(tampered)
        os.utime(loc_path, ns=(before.st_atime_ns, before.st_mtime_ns))
        after = os.stat(loc_path)
        c.case("the tampered index has the recorded size, mtime AND inode",
               after.st_size == before.st_size and after.st_mtime_ns == before.st_mtime_ns
               and after.st_ino == before.st_ino)
        proven, _why = derived_db.definitely_stale(db, repo=tmp)
        c.case("the cheap fingerprint cannot prove it stale (so it must never be trusted)",
               proven is False)
        c.refuses("...and open_ro refuses it anyway, because it always hashes",
                  lambda: derived_db.open_ro(db, repo=tmp), DatabaseStale,
                  ["corpus/local/index-local.jsonl", "MOVED"])
        with open(loc_path, "r+b") as fh:
            fh.write(body)
        os.utime(loc_path, ns=(before.st_atime_ns, before.st_mtime_ns))
        c.accepts("restoring the bytes in place makes it fresh again",
                  lambda: derived_db.open_ro(db, repo=tmp), 100)

        # An index touched but not changed - the opposite error, a refusal that fires on
        # nothing. Content is the contract; a new mtime alone must not refuse.
        os.utime(loc_path, None)
        c.accepts("an index touched but not changed still opens (mtime is not the contract)",
                  lambda: derived_db.open_ro(db, repo=tmp), 100)

        print("\n=== schema version ===")
        for value, label in ((SCHEMA_VERSION + 1, "a NEWER schema version"),
                             (SCHEMA_VERSION - 1, "an OLDER schema version"),
                             ("v1", "a schema version that is not a number")):
            shutil.copy(db, db + ".alt")
            w = sqlite3.connect(db + ".alt")
            w.execute("UPDATE meta SET value = ? WHERE key = 'schema_version'",
                      (str(value),))
            w.commit()
            w.close()
            c.refuses("%s is refused" % label,
                      lambda: derived_db.open_ro(db + ".alt", repo=tmp), SchemaUnrecognised,
                      ["schema"])
        shutil.copy(db, db + ".alt")
        w = sqlite3.connect(db + ".alt")
        w.execute("DELETE FROM meta WHERE key = 'schema_version'")
        w.commit()
        w.close()
        c.refuses("no schema version recorded at all is refused",
                  lambda: derived_db.open_ro(db + ".alt", repo=tmp), SchemaUnrecognised)
        c.accepts("the unaltered copy at the right version still opens",
                  lambda: derived_db.open_ro(db, repo=tmp), 100)

        print("\n=== not a derived database ===")
        with open(db + ".alt", "wb") as fh:
            fh.write(b"this is not a database at all, it is 46 bytes.")
        c.refuses("a file that is not SQLite is refused",
                  lambda: derived_db.open_ro(db + ".alt", repo=tmp), SchemaUnrecognised)
        open(db + ".alt", "wb").close()
        c.refuses("a zero-length file is refused",
                  lambda: derived_db.open_ro(db + ".alt", repo=tmp), SchemaUnrecognised)
        w = sqlite3.connect(db + ".alt2")
        w.execute("CREATE TABLE something_else (x)")
        w.commit()
        w.close()
        c.refuses("a valid SQLite file that is some other database is refused",
                  lambda: derived_db.open_ro(db + ".alt2", repo=tmp), SchemaUnrecognised)
        # A plausible `meta` and none of the tables it implies. Without a guard this escaped
        # as a raw sqlite3.OperationalError, which no caller of open_ro would catch.
        w = sqlite3.connect(db + ".alt4")
        w.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        w.execute("INSERT INTO meta VALUES ('schema_version', ?)", (str(SCHEMA_VERSION),))
        w.commit()
        w.close()
        c.refuses("the right schema version with none of the tables it means is refused",
                  lambda: derived_db.open_ro(db + ".alt4", repo=tmp), SchemaUnrecognised,
                  ["does not have the tables"])
        c.refuses("no database at the path is refused, and says so distinctly",
                  lambda: derived_db.open_ro(os.path.join(tmp, "nope.db"), repo=tmp),
                  DatabaseMissing)

        print("\n=== the set of sources is part of the contract ===")
        loc_bak = loc_path + ".bak"
        os.rename(loc_path, loc_bak)
        c.refuses("a half that disappeared since the build is refused",
                  lambda: derived_db.open_ro(db, repo=tmp), DatabaseStale,
                  ["corpus/local/index-local.jsonl", "not present now"])
        os.rename(loc_bak, loc_path)
        pub_only = _mini(tmp + "-pubonly", pub)
        derived_db.build(db_path=pub_only, repo=tmp + "-pubonly")
        c.accepts("a published-only database is legitimate where there is no local half",
                  lambda: derived_db.open_ro(pub_only, repo=tmp + "-pubonly"), 60)
        shutil.copy(loc_path, os.path.join(tmp + "-pubonly", "corpus", "local",
                                           "index-local.jsonl"))
        c.refuses("...and is refused the moment a local half appears beside it",
                  lambda: derived_db.open_ro(pub_only, repo=tmp + "-pubonly"),
                  DatabaseStale, ["corpus/local/index-local.jsonl", "not built from it"])

        print("\n=== the database must hold what it says it holds ===")
        shutil.copy(db, db + ".alt")
        w = sqlite3.connect(db + ".alt")
        w.execute("DELETE FROM row WHERE half = 'local' AND line_no > 30")
        w.commit()
        w.close()
        c.refuses("rows removed from the database, source table untouched: refused",
                  lambda: derived_db.open_ro(db + ".alt", repo=tmp), DatabaseStale,
                  ["holds 30 rows"])

        print("\n=== consumers cannot write it ===")
        conn = derived_db.open_ro(db, repo=tmp)
        wrote = None
        try:
            conn.execute("INSERT INTO row (id, half, line_no, json) "
                         "VALUES (99999,'x',1,'{}')")
            conn.commit()
            wrote = True
        except sqlite3.OperationalError:
            wrote = False
        c.case("an INSERT through the reader's connection fails", wrote is False)
        try:
            conn.execute("DROP TABLE source")
            dropped = True
        except sqlite3.OperationalError:
            dropped = False
        c.case("so does a DROP", dropped is False)
        conn.close()
        side = [p for p in os.listdir(os.path.dirname(db))
                if p.startswith(os.path.basename(db)) and (p.endswith("-wal")
                                                           or p.endswith("-shm"))]
        c.case("reading leaves no -wal or -shm beside the database (never WAL mode)",
               side == [], "found %s" % side)

        print("\n=== the builder holds the lock, and a partial file is never on disk ===")
        with index_lock(os.path.join(tmp, "corpus", "index.jsonl"), quiet=True):
            try:
                derived_db.build(db_path=db, repo=tmp, lock_timeout=0.5)
                c.case("a build refuses to read an index another writer holds", False,
                       "it built anyway")
            except LockBusy:
                c.case("a build refuses to read an index another writer holds", True)
            c.accepts("and the existing database still opens while that lock is held",
                      lambda: derived_db.open_ro(db, repo=tmp), 100)

        before_ino = os.stat(db).st_ino
        held = derived_db.open_ro(db, repo=tmp)
        derived_db.build(db_path=db, repo=tmp)
        after_ino = os.stat(db).st_ino
        c.case("a rebuild replaces the file rather than truncating it (inode moves)",
               before_ino != after_ino)
        c.case("a connection opened before the rebuild still reads a whole database",
               held.execute("SELECT COUNT(*) FROM row").fetchone()[0] == 100)
        held.close()
        leftovers = [p for p in os.listdir(os.path.dirname(db)) if p.endswith(".tmp")]
        c.case("no temp database is left behind", leftovers == [], "found %s" % leftovers)

        print("\n=== the finders return what a JSONL scan returns ===")
        conn = derived_db.open_ro(db, repo=tmp)
        allrows = [("published", r) for r in pub] + [("local", r) for r in loc]
        want = sorted(r["sha256"] for _, r in allrows if r.get("family") == "fam-a")
        got = sorted(r["sha256"] for r in derived_db.find_by_cluster(conn, "family",
                                                                     "fam-a"))
        c.case("find_by_cluster matches the scan", got == want,
               "%d vs %d" % (len(got), len(want)))
        want = sorted(r["sha256"] for _, r in allrows
                      if "unreviewed" in (r.get("sensitivity") or []))
        got = sorted(r["sha256"] for r in derived_db.find_by_tag(conn, "sensitivity",
                                                                 "unreviewed"))
        c.case("find_by_tag matches the scan", got == want,
               "%d vs %d" % (len(got), len(want)))
        try:
            derived_db.find_by_cluster(conn, "verdict", "benign")
            c.case("find_by_cluster refuses a column that is not a cluster", False)
        except ValueError:
            c.case("find_by_cluster refuses a column that is not a cluster", True)

        # Prefix bounds: the range scan must not over-match a longer sibling, and must not
        # under-match the prefix itself. `/home2/acct0000` and `/home2/acct00000` differ by
        # one character and the second must not answer a query for the first.
        derived_db.build(db_path=db, repo=tmp)      # rebuild after the earlier rewrites
        extra = loc + [_loc(500, "/home2/acct0002x/public_html/deeper/x.php"),
                       _loc(501, "/home2/acct0002")]
        write_jsonl_atomic(loc_path, extra)
        derived_db.build(db_path=db, repo=tmp)
        conn.close()
        conn = derived_db.open_ro(db, repo=tmp)
        for prefix in ("/home2/acct0002", "/home2/acct0002/", "/home2/", "/", "/nothing"):
            want = sorted(r["sha256"] for r in extra
                          if r["origin"]["path"].startswith(prefix))
            got = sorted(r["sha256"] for r in derived_db.find_by_path_prefix(conn, prefix))
            c.case("find_by_path_prefix at depth %d matches the scan (%d rows)"
                   % (prefix.count("/"), len(want)), got == want,
                   "%d vs %d" % (len(got), len(want)))
        conn.close()

        print("\n=== reconcile() can say the other thing ===")
        conn = derived_db.open_ro(db, repo=tmp)
        findings, _ = reconcile(conn, repo=tmp)
        c.case("a faithful database reconciles clean", findings == [],
               "%d findings" % len(findings))
        conn.close()
        shutil.copy(db, db + ".alt3")
        w = sqlite3.connect(db + ".alt3")
        w.execute("UPDATE row SET family = 'fam-z' WHERE half='local' AND line_no = 3")
        w.execute("DELETE FROM row_tag WHERE row_id = "
                  "(SELECT id FROM row WHERE half='local' AND line_no = 4)")
        w.commit()
        w.close()
        alt = sqlite3.connect(derived_db._ro_uri(db + ".alt3"), uri=True)
        alt.row_factory = sqlite3.Row
        findings, counts = reconcile(alt, repo=tmp)
        alt.close()
        c.case("a database with one column edited and one row's tags dropped is caught",
               counts["column mismatches"] == 1 and counts["tag mismatches"] == 1,
               "columns %d tags %d" % (counts["column mismatches"],
                                       counts["tag mismatches"]))

        print("\n=== argument dispatch: an unknown flag is an error, not the default ===")
        # `--inject` is deliberately not among these: re-entering it from a subprocess
        # recurses without bound. Ask the dispatch the question instead of running the mode.
        def run(argv):
            p = subprocess.run([sys.executable, os.path.join(HERE, "derive-index-db.py")]
                               + argv + ["--db", os.path.join(tmp, "unused.db")],
                               capture_output=True, cwd=tmp, timeout=120)
            return p.returncode, os.path.exists(os.path.join(tmp, "unused.db"))

        for argv in (["--halp"], ["--chekc"], ["--check", "--bench"], ["nonsense"]):
            rc, built = run(argv)
            c.case("%-26s is rejected without building" % (" ".join(argv)),
                   rc != 0 and not built, "exit %d, built %s" % (rc, built))
        # `-h` short-circuits argparse before the mutually-exclusive group is validated, so
        # it exits 0 rather than erroring. That is the SAFE direction and it is the property
        # worth asserting: the thing `make-summary.py` got wrong was `--help` reaching the
        # write path, not `--help` reporting success.
        for argv in (["--help"], ["-h", "--bench"], ["-h", "--halp"]):
            rc, built = run(argv)
            c.case("%-26s prints help and builds nothing" % (" ".join(argv)),
                   rc == 0 and not built, "exit %d, built %s" % (rc, built))

    finally:
        shutil.rmtree(tmp, ignore_errors=True)
        shutil.rmtree(tmp + "-pubonly", ignore_errors=True)

    print("\n%d controls, %d failed" % (c.n, len(c.fails)))
    for f in c.fails:
        print("  FAIL: %s" % f)
    return 1 if c.fails else 0


def main(argv=None):
    ap = argparse.ArgumentParser(
        description=__doc__.split("\n\n")[0],
        formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--check", action="store_true",
                   help="verify freshness through open_ro, then reconcile every row "
                        "against the JSONL. Useful; not the mechanism.")
    g.add_argument("--inject", action="store_true",
                   help="the controls, in both directions")
    g.add_argument("--bench", action="store_true",
                   help="build time, database size, and three queries against a full scan")
    ap.add_argument("--db", default=None,
                    help="database path (default corpus/local/index.db)")
    ap.add_argument("--verbose", action="store_true")
    a = ap.parse_args(argv)
    if a.check:
        return cmd_check(a)
    if a.inject:
        return cmd_inject(a)
    if a.bench:
        return cmd_bench(a)
    return cmd_build(a)


if __name__ == "__main__":
    sys.exit(main())
