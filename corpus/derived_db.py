#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A derived SQLite read index over the two halves of the corpus index.

The JSONL stays the source of truth. This is a cache, built one way, gitignored, and
never authoritative about anything. Nothing writes back through it, and the build is the
only thing that writes it at all.

WHY
----
Every tool in `corpus/` re-parses both halves on every invocation - 18.3 MB published and
43.1 MB local, 92,800 rows, about 0.77 s of `json.loads` before the tool has done any of its
own work - and it does that dozens of times in a round. A tool that wants the rows in one
family, or the rows carrying one tag, or the rows under one path prefix, has no way to ask
for them: it scans everything and filters in Python.

THE GUARANTEE IS REFUSAL AT READ TIME, NOT A `--check` SOMEBODY REMEMBERS TO RUN
--------------------------------------------------------------------------------
A derived artefact that can be stale is a second source of truth waiting to happen, and
this repository has paid for that shape twice already:

  * `index-summary.json` could sit stale until a human ran `make-summary.py --check`, and
    it did, twice. The second time a round was reported green while it was failing.
  * `make-summary.SHIPPED` is a hand-maintained set carrying the comment *"nothing catches
    a stale set"*. Nothing caught it. 58 samples were counted as reproducible from a pinned
    source when they exist nowhere but inside a shard.

Both are the same defect: the detector was separate from the use, so the use could happen
without the detector. So the check here is not separate from the use. `open_ro()` verifies
freshness as part of opening the file and raises if it cannot - a stale read is not
*detectable*, it is *unperformable*. `derive-index-db.py --check` exists too because it is
useful to ask the question directly and to see the detail, but it is not the mechanism, and
no consumer is asked to remember it.

WHAT FRESHNESS MEANS HERE, WRITTEN DOWN RATHER THAN ASSUMED
------------------------------------------------------------
The `source` table records, for every JSONL the database was built from: its repo-relative
path, the **sha256 of its bytes**, its row count, and a cheap fingerprint (size, mtime,
inode). The `meta` table records the **schema version** and the **build time**. On open:

  1. the schema version must be one this module recognises, exactly;
  2. the set of sources recorded must equal the set present on this machine now - a half
     that appeared or disappeared since the build is a mismatch, not a detail;
  3. every recorded sha256 must equal the file's sha256 recomputed **now**;
  4. the row count stored per source must equal the rows the database actually holds for
     it, which catches a database truncated or half-built rather than a moved source.

Anything else raises. Hashing 61.4 MB costs about 0.055 s, roughly 7% of the JSONL parse it
replaces, and is paid on every open. That is the price of the guarantee and it is cheap.

**The fingerprint may only ever say "definitely stale".** `definitely_stale()` returns True
when size, mtime or inode disagree with the record, and otherwise returns False meaning
*not proven stale* - never *fresh*. It is never consulted by `open_ro()`, which always
hashes. The reason is exact: both halves are written by `indexio.write_jsonl_atomic`, which
`os.replace()`s a sibling temp file into place, so a fast path that can wrongly answer
"fresh" is the whole failure mode restated with a stopwatch attached.

WHAT THE GUARANTEE IS NOT
--------------------------
Freshness is not correctness. A passing open proves the database was built from exactly
these bytes; it does not prove the builder derived them faithfully. That is a different
question and it has a different check: `derive-index-db.py --check` re-reads both halves and
reconciles every row, every extracted column, every tag and every path against the database.

Nor is it proof against a forger. Anyone who can write the database file can rewrite the
`source` table to match a moved index. The controls in `--inject` cover accident and drift -
an index that moved, a mtime restored, a file replaced, a schema from another version - not
somebody deliberately editing the record. Consumers open with `mode=ro` precisely so that
"anyone" excludes them: the moment a consumer can write this file it becomes a second source
of truth, which is the thing this file must not be.

THE WHOLE ROW IS KEPT AS JSON, AND THAT IS DELIBERATE
------------------------------------------------------
`row.json` holds the source line verbatim. The extracted columns are an index onto it, not a
replacement for it. The census over both halves reports 326 dotted fields carried by rows and
53 of them orphans - written by no tracked tool (`field-provenance.py`, run 2026-09-07;
CORPUS_PLAN §11 records 316 and 54 from 2026-09-06, and the difference is the two rounds
merged since). It has been wrong about its own population four separate times by enumerating
fields through something that could not see all of them, and its standing caution is that a
field every row has lost is invisible to a census enumerated from the rows. A normalised
schema that dropped unmodelled fields would make a field invisible to the next census the
moment it stopped being extracted, and would do it silently. Keeping the row means the
database can lose a *column* and never lose a *field*.

FINDING ROWS, NOT COUNTING THEM
---------------------------------
This module exposes finders and no counters, on purpose. Every count a round quotes comes
from the JSONL or from `index-summary.json`. A denominator enumerated by a derived artefact
is CORPUS_PLAN §11's property with an extra layer of indirection, and there are eleven
recorded instances of it in this corpus already. If a figure is ever taken from here it has
to be reconciled against the JSONL in the same run - which is what `--check` does, and what
`--bench` does to every query it times.

WHY THIS IS NOT WIRED INTO `pre-push-check.py`
------------------------------------------------
That gate guards publication, and this database never ships: it is gitignored, local, and
**it contains customer identifiers** - the local half's `origin.path`, `account_hash` and
`site` values are in it by construction. Wiring a local-cache freshness check into the leak
gate would dilute what `SAFE TO PUSH` means, and the leak gate's entire value is that it says
exactly one thing. The reader is the enforcement point. See `SOURCES.md`.
"""
import contextlib, hashlib, json, os, sqlite3, sys, tempfile, time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)
from indexio import index_lock, LockBusy                                # noqa: E402

__all__ = ["SCHEMA_VERSION", "SOURCES", "DB_REL", "build", "open_ro",
           "present_sources", "definitely_stale", "describe",
           "find_by_cluster", "find_by_tag", "find_by_path_prefix",
           "DerivedDbError", "DatabaseMissing", "SchemaUnrecognised", "DatabaseStale"]

# Bump on ANY change to what the builder extracts or how it stores it. The reader refuses a
# version it does not recognise rather than reading columns that may mean something else -
# an unrecognised version is not a lesser answer, it is no answer.
SCHEMA_VERSION = 1

# Repo-relative, and in lock order: the builder always takes the published half's lock
# first, so two builders cannot deadlock against each other.
SOURCES = ("corpus/index.jsonl", "corpus/local/index-local.jsonl")
HALF = {"corpus/index.jsonl": "published", "corpus/local/index-local.jsonl": "local"}
REQUIRED = "corpus/index.jsonl"

# Under corpus/local/ because it carries local-half rows, which carry customer identifiers.
DB_REL = "corpus/local/index.db"

# The columns extracted for querying. Every one is also still in `row.json`.
CLUSTER_COLUMNS = ("bucket", "family", "staging_dir")
TAG_FIELDS = ("sensitivity", "technique", "discovered_by", "publish_blockers",
              "collected_from")

SCHEMA_SQL = """
CREATE TABLE meta (
    key    TEXT PRIMARY KEY,
    value  TEXT NOT NULL
);
CREATE TABLE source (
    path      TEXT PRIMARY KEY,   -- repo-relative
    half      TEXT NOT NULL,      -- 'published' | 'local'
    sha256    TEXT NOT NULL,      -- of the bytes the build read, and the freshness contract
    rows      INTEGER NOT NULL,
    bytes     INTEGER NOT NULL,
    mtime_ns  INTEGER NOT NULL,   -- fingerprint: may only ever say "definitely stale"
    inode     INTEGER NOT NULL
);
CREATE TABLE row (
    id            INTEGER PRIMARY KEY,
    half          TEXT NOT NULL,
    line_no       INTEGER NOT NULL,   -- 1-based, in the source file: traceable back
    sha256        TEXT,
    size          INTEGER,
    bucket        TEXT,
    family        TEXT,
    staging_dir   TEXT,
    verdict       TEXT,
    publishable   INTEGER,            -- 1 / 0 / NULL, never a string
    reason        TEXT,
    account_hash  TEXT,
    origin_path   TEXT,
    json          TEXT NOT NULL       -- the source line, verbatim
);
CREATE TABLE row_tag (
    row_id  INTEGER NOT NULL,
    kind    TEXT NOT NULL,
    value   TEXT NOT NULL
);
CREATE TABLE row_path (
    row_id  INTEGER NOT NULL,
    field   TEXT NOT NULL,
    path    TEXT NOT NULL
);
"""

INDEX_SQL = """
CREATE INDEX row_sha256      ON row(sha256);
CREATE INDEX row_half        ON row(half);
CREATE INDEX row_bucket      ON row(bucket);
CREATE INDEX row_family      ON row(family);
CREATE INDEX row_staging_dir ON row(staging_dir);
CREATE INDEX row_verdict     ON row(verdict);
CREATE INDEX row_publishable ON row(publishable);
CREATE INDEX row_reason      ON row(reason);
CREATE INDEX row_origin_path ON row(origin_path);
CREATE INDEX row_tag_kv      ON row_tag(kind, value);
CREATE INDEX row_tag_row     ON row_tag(row_id);
CREATE INDEX row_path_path   ON row_path(path);
CREATE INDEX row_path_row    ON row_path(row_id);
"""
# `row.sha256` is indexed and NOT unique. It happens to be unique across both halves today
# (44,544 + 48,256 distinct, zero overlap, measured 2026-09-07), but a UNIQUE constraint
# would make this cache an opinionated validator: a future duplicate would crash the build
# instead of being reported by the tool whose job that is.


class DerivedDbError(RuntimeError):
    """Base: the derived database cannot be used as it stands."""


class DatabaseMissing(DerivedDbError):
    """There is no database at that path - build it."""


class SchemaUnrecognised(DerivedDbError):
    """Not a derived index, or one written by a different schema version."""


class DatabaseStale(DerivedDbError):
    """A source moved since the build, or the database does not hold what it claims."""


# ---------------------------------------------------------------- sources and fingerprints

def present_sources(repo=REPO):
    """The subset of SOURCES that exists on this machine, in lock order.

    A public clone has `index.jsonl` and no `local/`, and a database built there is
    legitimately a published-only database. What is NOT legitimate is reading such a
    database on a machine where the local half exists: it would answer questions about half
    the corpus while looking like it answered about all of it. `open_ro` compares this set
    against the recorded one for exactly that reason.
    """
    out = tuple(rel for rel in SOURCES if os.path.exists(os.path.join(repo, rel)))
    if REQUIRED not in out:
        raise DerivedDbError("%s is missing; there is no corpus to derive from"
                             % os.path.join(repo, REQUIRED))
    return out


def _hash_file(abs_path):
    """(sha256hex, bytes) streamed, without holding the file in memory."""
    h = hashlib.sha256()
    n = 0
    with open(abs_path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
            n += len(chunk)
    return h.hexdigest(), n


def _read_and_hash(abs_path):
    """(sha256hex, data) from ONE read.

    One read on purpose: hashing the file and then parsing it separately leaves a window in
    which the bytes recorded and the bytes derived are different files.
    """
    with open(abs_path, "rb") as fh:
        data = fh.read()
    return hashlib.sha256(data).hexdigest(), data


def definitely_stale(db_path=None, repo=REPO):
    """(True, reasons) if staleness can be PROVEN cheaply; (False, []) otherwise.

    False means *not proven stale*. It never means fresh, it is never sufficient to open on,
    and `open_ro` does not call this function at all. Both halves are written by
    `indexio.write_jsonl_atomic`, whose `os.replace()` can hand back any (size, mtime, inode)
    triple it likes; a fast path that can wrongly answer "fresh" would reintroduce the exact
    failure this module exists to remove. Use it to decide whether a rebuild is *needed*,
    never to decide whether a read is *safe*.
    """
    db_path = db_path or os.path.join(repo, DB_REL)
    if not os.path.exists(db_path):
        return True, ["no database at %s" % db_path]
    try:
        conn = sqlite3.connect(_ro_uri(db_path), uri=True)
        conn.row_factory = sqlite3.Row
        stored = {r["path"]: r for r in conn.execute("SELECT * FROM source")}
        conn.close()
    except sqlite3.DatabaseError as exc:
        return True, ["unreadable as a derived index: %s" % exc]

    reasons = []
    try:
        present = set(present_sources(repo))
    except DerivedDbError as exc:
        return True, [str(exc)]
    for rel in sorted(present - set(stored)):
        reasons.append("%s exists now and is not in the database" % rel)
    for rel in sorted(set(stored) - present):
        reasons.append("%s is recorded and no longer exists" % rel)
    for rel in sorted(present & set(stored)):
        st = os.stat(os.path.join(repo, rel))
        rec = stored[rel]
        if st.st_size != rec["bytes"]:
            reasons.append("%s size %d, recorded %d" % (rel, st.st_size, rec["bytes"]))
        elif st.st_ino != rec["inode"] or st.st_mtime_ns != rec["mtime_ns"]:
            reasons.append("%s was replaced since the build (inode/mtime moved)" % rel)
    return bool(reasons), reasons


# ------------------------------------------------------------------------------- extraction

def _extract(row, half, line_no, raw):
    """The row's columns. Everything here is ALSO still in `raw`."""
    origin = row.get("origin")
    origin_path = origin.get("path") if isinstance(origin, dict) else None
    pub = row.get("publishable")
    return (half, line_no,
            _text(row.get("sha256")), _int(row.get("size")),
            _text(row.get("bucket")), _text(row.get("family")),
            _text(row.get("staging_dir")), _text(row.get("verdict")),
            (1 if pub is True else 0 if pub is False else None),
            _text(row.get("reason")), _text(row.get("account_hash")),
            _text(origin_path), raw)


def _text(v):
    return v if isinstance(v, str) else None


def _int(v):
    return v if isinstance(v, int) and not isinstance(v, bool) else None


def _tags(row):
    """(kind, value) pairs for the multi-valued fields the app searches on."""
    for field in TAG_FIELDS:
        v = row.get(field)
        if isinstance(v, list):
            for x in v:
                if isinstance(x, str):
                    yield field, x
    expect = row.get("expect")
    if isinstance(expect, dict) and isinstance(expect.get("must_detect"), list):
        for x in expect["must_detect"]:
            if isinstance(x, str):
                yield "must_detect", x
    placements = row.get("placements")
    if isinstance(placements, dict):
        for k in placements:
            if isinstance(k, str):
                yield "placement", k


def _paths(row):
    """(field, path) pairs. `origin.path` is the only path-valued field in either half.

    `collected_from` looks path-shaped and is not: all 52,219 of its entries are operation
    labels and not one contains a `/` (measured 2026-09-07 over both halves). It is indexed
    as a tag.
    """
    origin = row.get("origin")
    if isinstance(origin, dict) and isinstance(origin.get("path"), str):
        yield "origin.path", origin["path"]


# ----------------------------------------------------------------------------------- build

def build(db_path=None, repo=REPO, sources=None, log=None, lock_timeout=120.0):
    """Rebuild the database from the JSONL halves. Returns a stats dict.

    Two structural rules, both of them load-bearing:

    **The read happens under `indexio.index_lock`,** for the same reason `shard-gate --fix`
    does: deriving from rows another writer is mid-merge on produces a database that matches
    nothing, and a half-merged index is internally consistent so nothing downstream can tell.
    Both halves are locked, published first, before either is read.

    **The database is assembled in a sibling temp file and `os.replace()`d into place,** so a
    reader either sees the whole old database or the whole new one. There is no moment at
    which the file on disk is a partial build - which is what makes "opened while the builder
    is running" a defined behaviour rather than a race.

    The lock is released before the SQLite build, and that is deliberate rather than lazy.
    What is recorded is the sha256 of the bytes actually read, so an index written during the
    build makes the result **stale**, not **wrong** - and the reader refuses a stale database.
    Holding the lock for the whole build would block writers for seconds to convert a refusal
    into a wait, which is a worse trade.
    """
    repo = os.path.abspath(repo)
    db_path = db_path or os.path.join(repo, DB_REL)
    sources = tuple(sources) if sources else present_sources(repo)
    ordered = [rel for rel in SOURCES if rel in sources]
    say = log or (lambda *a: None)

    started = time.time()
    snapshot = []
    t0 = time.perf_counter()
    with contextlib.ExitStack() as stack:
        for rel in ordered:                       # published half first: fixed lock order
            stack.enter_context(index_lock(os.path.join(repo, rel),
                                           timeout=lock_timeout))
        for rel in ordered:
            abs_path = os.path.join(repo, rel)
            sha, data = _read_and_hash(abs_path)
            st = os.stat(abs_path)
            lines = [(i + 1, ln.decode("utf-8"))
                     for i, ln in enumerate(data.split(b"\n")) if ln.strip()]
            snapshot.append({"rel": rel, "half": HALF[rel], "sha256": sha,
                             "bytes": len(data), "mtime_ns": st.st_mtime_ns,
                             "inode": st.st_ino, "lines": lines})
            say("read %s: %d rows, sha256 %s" % (rel, len(lines), sha[:12]))
    read_s = time.perf_counter() - t0

    directory = os.path.dirname(os.path.abspath(db_path)) or "."
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=directory,
                               prefix=os.path.basename(db_path) + ".", suffix=".tmp")
    os.close(fd)
    stats = {"read_s": read_s, "sources": {}, "rows": 0, "tags": 0, "paths": 0}
    try:
        conn = sqlite3.connect(tmp)
        conn.isolation_level = None
        # The temp file is discarded on any failure, so it needs no crash safety of its own;
        # the atomic replace provides all of it. The FINAL database is left in the default
        # DELETE journal mode - never WAL - because a WAL database cannot be opened
        # `mode=ro` without creating a `-shm` beside it, and a reader that has to write
        # something to read is not read-only.
        conn.execute("PRAGMA journal_mode=OFF")
        conn.execute("PRAGMA synchronous=OFF")
        conn.execute("BEGIN")
        conn.executescript(SCHEMA_SQL)
        conn.execute("BEGIN")

        next_id = 1
        for src in snapshot:
            half, n_tag, n_path = src["half"], 0, 0
            rows_data, tags_data, paths_data = [], [], []
            for line_no, raw in src["lines"]:
                row = json.loads(raw)
                rows_data.append((next_id,) + _extract(row, half, line_no, raw))
                for kind, value in _tags(row):
                    tags_data.append((next_id, kind, value))
                    n_tag += 1
                for field, path in _paths(row):
                    paths_data.append((next_id, field, path))
                    n_path += 1
                next_id += 1
            conn.executemany(
                "INSERT INTO row (id, half, line_no, sha256, size, bucket, family, "
                "staging_dir, verdict, publishable, reason, account_hash, origin_path, "
                "json) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)", rows_data)
            conn.executemany("INSERT INTO row_tag (row_id, kind, value) VALUES (?,?,?)",
                             tags_data)
            conn.executemany("INSERT INTO row_path (row_id, field, path) VALUES (?,?,?)",
                             paths_data)
            conn.execute(
                "INSERT INTO source (path, half, sha256, rows, bytes, mtime_ns, inode) "
                "VALUES (?,?,?,?,?,?,?)",
                (src["rel"], half, src["sha256"], len(src["lines"]), src["bytes"],
                 src["mtime_ns"], src["inode"]))
            stats["sources"][src["rel"]] = {"rows": len(src["lines"]),
                                            "sha256": src["sha256"],
                                            "tags": n_tag, "paths": n_path}
            stats["rows"] += len(src["lines"])
            stats["tags"] += n_tag
            stats["paths"] += n_path
            say("indexed %s: %d rows, %d tags, %d paths" % (src["rel"], len(src["lines"]),
                                                            n_tag, n_path))

        conn.executemany("INSERT INTO meta (key, value) VALUES (?,?)", [
            ("schema_version", str(SCHEMA_VERSION)),
            ("built_at", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(started))),
            ("built_by", "corpus/derived_db.py build()"),
            ("source_count", str(len(snapshot))),
        ])
        conn.execute("COMMIT")
        conn.executescript(INDEX_SQL)
        conn.execute("ANALYZE")
        conn.close()

        os.chmod(tmp, 0o644)
        os.replace(tmp, db_path)
        tmp = None
    finally:
        if tmp is not None:
            for suffix in ("", "-journal", "-wal", "-shm"):
                try:
                    os.unlink(tmp + suffix)
                except OSError:
                    pass

    dirfd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(dirfd)
    except OSError:
        pass                       # some filesystems refuse to fsync a directory
    finally:
        os.close(dirfd)

    stats["build_s"] = time.perf_counter() - t0
    stats["db_bytes"] = os.path.getsize(db_path)
    stats["db_path"] = db_path
    return stats


# ------------------------------------------------------------------------------------ read

def _ro_uri(db_path):
    """A `file:` URI with `mode=ro`, escaping handled by pathlib rather than by hand."""
    import pathlib
    return pathlib.Path(os.path.abspath(db_path)).as_uri() + "?mode=ro"


def verify(conn, repo=REPO, expected=None, db_path="<db>"):
    """Raise unless the database is fresh. Returns the per-source detail on success.

    Complaints are collected and reported together rather than raised on the first one: when
    both halves have moved, "index.jsonl moved" alone is a true statement that sends the
    reader to fix half the problem.
    """
    try:
        got = conn.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchall()
    except sqlite3.DatabaseError as exc:
        raise SchemaUnrecognised("%s is not a readable derived index: %s" % (db_path, exc))
    if not got:
        raise SchemaUnrecognised("%s records no schema_version" % db_path)
    try:
        version = int(got[0][0])
    except (TypeError, ValueError):
        raise SchemaUnrecognised("%s records schema_version %r, which is not a version"
                                 % (db_path, got[0][0]))
    if version != SCHEMA_VERSION:
        raise SchemaUnrecognised(
            "%s was built by schema version %d; this module reads version %d only. "
            "Rebuild it: corpus/derive-index-db.py" % (db_path, version, SCHEMA_VERSION))

    expected = tuple(expected) if expected else present_sources(repo)
    try:
        stored = {r["path"]: r for r in conn.execute("SELECT * FROM source")}
        conn.execute("SELECT COUNT(*) FROM row").fetchone()
    except sqlite3.DatabaseError as exc:
        # A file carrying a plausible `meta` and not the rest is not a lesser database, it
        # is a different one. Without this it escaped as a raw sqlite3.OperationalError,
        # which no caller of open_ro would think to catch.
        raise SchemaUnrecognised("%s records schema version %d and does not have the "
                                 "tables that version means: %s" % (db_path, version, exc))
    complaints, detail = [], {}

    for rel in sorted(set(expected) - set(stored)):
        complaints.append("%s exists on this machine and the database was not built from "
                          "it" % rel)
    for rel in sorted(set(stored) - set(expected)):
        complaints.append("%s was built in and is not present now" % rel)

    for rel in sorted(set(expected) & set(stored)):
        rec = stored[rel]
        abs_path = os.path.join(repo, rel)
        try:
            sha, nbytes = _hash_file(abs_path)
        except OSError as exc:
            complaints.append("%s cannot be read to verify it: %s" % (rel, exc))
            continue
        held = conn.execute("SELECT COUNT(*) FROM row WHERE half = ?",
                            (rec["half"],)).fetchone()[0]
        detail[rel] = {"stored_sha256": rec["sha256"], "actual_sha256": sha,
                       "stored_rows": rec["rows"], "held_rows": held,
                       "stored_bytes": rec["bytes"], "actual_bytes": nbytes}
        if sha != rec["sha256"]:
            complaints.append(
                "%s MOVED since the build: sha256 %s now, %s recorded"
                % (rel, sha[:16], rec["sha256"][:16]))
        if held != rec["rows"]:
            complaints.append(
                "%s: the database holds %d rows for the %s half and records %d - the "
                "build did not finish, or the file was edited" % (rel, held, rec["half"],
                                                                  rec["rows"]))

    if complaints:
        raise DatabaseStale("%s is stale:\n  - %s\nRebuild it: corpus/derive-index-db.py"
                            % (db_path, "\n  - ".join(complaints)))
    return detail


def open_ro(db_path=None, repo=REPO, expected=None):
    """Open the derived database read-only, verified fresh, or raise.

    There is no flag to skip the verification and there must never be one. `mode=ro` is not
    a courtesy either: the builder is the only writer, and the moment a consumer can write
    this file it stops being derived and starts being a second source of truth.

    Always hashes. It does not consult `definitely_stale()` - see that function.
    """
    repo = os.path.abspath(repo)
    db_path = db_path or os.path.join(repo, DB_REL)
    if not os.path.exists(db_path):
        raise DatabaseMissing("no derived index at %s - build it: "
                              "corpus/derive-index-db.py" % db_path)
    conn = sqlite3.connect(_ro_uri(db_path), uri=True)
    conn.row_factory = sqlite3.Row
    try:
        verify(conn, repo=repo, expected=expected, db_path=db_path)
    except Exception:
        conn.close()
        raise
    return conn


def describe(conn):
    """The provenance record, for a tool that wants to print what it is reading."""
    meta = {r["key"]: r["value"] for r in conn.execute("SELECT key, value FROM meta")}
    sources = [dict(r) for r in conn.execute("SELECT * FROM source ORDER BY path")]
    return {"meta": meta, "sources": sources}


# --------------------------------------------------------------------------------- finders
# Finders, not counters. See the module docstring: every count a round quotes comes from the
# JSONL or from index-summary.json, and a figure taken from here is reconciled in the same
# run or it is not a figure.

def _rows(conn, sql, args):
    return [json.loads(r["json"]) for r in conn.execute(sql, args)]


def find_by_cluster(conn, kind, value, half=None):
    """Rows in one cluster. `kind` is one of CLUSTER_COLUMNS.

    "Cluster" is not a field in either half; it is the three columns this corpus actually
    groups by - `bucket` (6 values), `family` (46) and `staging_dir` (75 rows). Naming them
    here rather than accepting an arbitrary column keeps the query surface something the
    schema version covers.
    """
    if kind not in CLUSTER_COLUMNS:
        raise ValueError("cluster kind %r is not one of %s" % (kind, list(CLUSTER_COLUMNS)))
    sql = "SELECT json FROM row WHERE %s = ?" % kind
    args = [value]
    if half is not None:
        sql += " AND half = ?"
        args.append(half)
    return _rows(conn, sql + " ORDER BY id", args)


def find_by_tag(conn, kind, value, half=None):
    """Rows carrying one value of one list-valued field (`sensitivity`, `technique`, ...)."""
    sql = ("SELECT r.json FROM row_tag t JOIN row r ON r.id = t.row_id "
           "WHERE t.kind = ? AND t.value = ?")
    args = [kind, value]
    if half is not None:
        sql += " AND r.half = ?"
        args.append(half)
    return _rows(conn, sql + " ORDER BY r.id", args)


def _prefix_upper(prefix):
    """The exclusive upper bound for a prefix range scan, or None for the empty prefix.

    A range scan rather than `LIKE 'p%'` because LIKE only uses an index under
    `case_sensitive_like`, and rather than `GLOB 'p*'` because a path containing `*`, `?` or
    a bracket would have to be escaped and GLOB's bracket-escaping cannot express a literal
    `]` cleanly. SQLite compares TEXT by UTF-8 bytes and UTF-8 preserves code point order,
    so incrementing the last code point is the correct bound.
    """
    if not prefix:
        return None
    last = ord(prefix[-1]) + 1
    if 0xD800 <= last <= 0xDFFF:        # surrogates are not encodable; skip the block
        last = 0xE000
    if last > 0x10FFFF:
        return None
    return prefix[:-1] + chr(last)


def find_by_path_prefix(conn, prefix, half=None):
    """Rows whose `origin.path` starts with `prefix`.

    `origin.path` is a local-half field: 48,256 rows carry it and no published row does, by
    the gate's own rule that a published row has no `origin`. A prefix search here is
    therefore a search of the local half whatever `half` says, and that is a property of the
    corpus rather than of this query.
    """
    upper = _prefix_upper(prefix)
    sql = ("SELECT DISTINCT r.id AS id, r.json AS json FROM row_path p "
           "JOIN row r ON r.id = p.row_id WHERE p.path >= ?")
    args = [prefix]
    if upper is not None:
        sql += " AND p.path < ?"
        args.append(upper)
    if half is not None:
        sql += " AND r.half = ?"
        args.append(half)
    return _rows(conn, sql + " ORDER BY r.id", args)


if __name__ == "__main__":
    sys.exit("derived_db.py is a library. Build and check with corpus/derive-index-db.py, "
             "which carries the --check and --inject modes.")
