#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Turn the unreviewed quarantine bucket into a queue an operator can answer.

WHY THE UNIT IS NOT THE ROW, AND NOT THE DIRECTORY EITHER
---------------------------------------------------------
23,612 rows in `quarantine/evidence` are unreviewed. Reviewing them one at a time is
470 rounds of fifty. Round 9 established the better unit - malware arrives in
directories, so one placement judgement answers every row in one - and that is what
`staging-directory-review` records.

Applied here, by directory, that is still 2,222 decisions, 165 of them to reach 80% of
the rows. But a quarantine path is not a directory an attacker chose. It is a directory
an incident responder *created*, and every file underneath it was moved there by one
command. So the decision the operator is actually being asked for sits one level higher
than the directory: it is about the containment operation. 2,222 directories roll up
into 177 operations, and three of those hold 85% of the rows.

An operation is still not the unit, because an operation that moved a whole webroot moved
upstream plugin code, customer photographs and the attacker's dropper in the same command.
So the unit is the **lane**: an operation crossed with what the file actually is, read
from the bytes. Nine lanes cover 80% of the rows and nineteen cover 89%.

THE SAFETY VALVE, AND THE THING IT CANNOT DO
--------------------------------------------
Any row the collecting scan already flagged is pulled out of its bulk lane into a
`FLAGGED-BY-SCAN` lane for its operation, and is never closed by a bulk judgement. What
is left in a bulk lane is material no rule fired on.

That is worth stating in the form CORPUS_PLAN section 11 asks for, because it is the same
shape: a lane whose membership is "the scanner said nothing" cannot, on its own, tell you
the scanner was right. It is a denominator enumerated by the process being measured. So
every bulk lane carries a **second, scanner-independent attestation** and the queue prints
it beside the count:

  content class   read from magic bytes and structure, never from the extension. A lane of
                  2,637 JPEGs is images because the bytes are JPEG, not because nothing
                  fired on them;
  upstream path   for a lane under a plugin or theme slug, whether the file's path inside
                  that slug exists in a pinned release of the same slug. Different version,
                  different bytes, so `resolve-benign.py` cannot close it by hash - but the
                  path is attested by upstream rather than by us.

A lane with neither attestation is reported as having neither. That is the honest output
and it is the one an operator should look at first.

WHAT IT WILL NOT DO
-------------------
It sets no verdict and writes no index. Nothing leaves `unreviewed` without
`review.human_confirmed`, which no tool can set, so the deliverable is the queue and the
evidence, not an answer.

USAGE
  corpus/quarantine-queue.py                     the queue, to stdout
  corpus/quarantine-queue.py --markdown FILE     also write it as the tracked queue doc
  corpus/quarantine-queue.py --lanes N           how many lanes to print (default 25)
  corpus/quarantine-queue.py --inject            the positive control
"""
import argparse, collections, json, os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
from indexio import read_jsonl                                        # noqa: E402

LOC = os.path.join(HERE, "local", "index-local.jsonl")
COLLECTION = os.path.join(ROOT, "trail-data", "incoming", "2026-09-03")
BLOBMAP = os.path.join(COLLECTION, "derived", "blobmap-all.jsonl")
PINNED = os.path.join(ROOT, "trail-data", "CMS-ext")
BUCKET = "quarantine/evidence"

# Magic first, extension never. A payload named .jpg is a payload; the corpus already
# ships seven polyglots that exist because the two disagree.
ARCHIVE_MAGIC = ((b"PK\x03\x04", "zip"), (b"\x1f\x8b", "gzip"), (b"\xfd7zXZ", "xz"),
                 (b"BZh", "bzip2"), (b"Rar!", "rar"), (b"7z\xbc\xaf", "7z"))
IMAGE_MAGIC = ((b"\xff\xd8\xff", "jpeg"), (b"\x89PNG\r\n", "png"), (b"GIF8", "gif"),
               (b"\x00\x00\x01\x00", "ico"), (b"BM", "bmp"), (b"RIFF", "riff"))
FONT_MAGIC = (b"wOFF", b"wOF2", b"OTTO")
EXTENSIONS = ((".js", "js-source"), (".css", "stylesheet"), (".json", "json"),
              (".po", "gettext-po"), (".svg", "svg"), (".html", "html"), (".htm", "html"),
              (".tpl", "template"), (".tsv", "tabular"), (".txt", "plain-text"),
              (".md", "plain-text"), (".xml", "xml"), (".sql", "sql-dump"), (".log", "log"))

# §2.3: members are the corpus data and the container never is. That is a policy answer,
# not a per-operation judgement, so containers form one lane across every operation.
ARCHIVE_LANE = ("*", "ARCHIVE-CONTAINER", "")
FLAGGED = "FLAGGED-BY-SCAN"


def classify(data, path):
    """What the file is, from the bytes. `path` decides only where the bytes are silent."""
    if data is None:
        return "unresolved"
    for magic, _ in ARCHIVE_MAGIC:
        if data.startswith(magic):
            return "archive-container"
    if len(data) >= 265 and data[257:262] == b"ustar":
        return "archive-container"
    for magic, _ in IMAGE_MAGIC:
        if data.startswith(magic):
            return "image"
    if data.startswith(FONT_MAGIC):
        return "font"
    if data.startswith(b"%PDF"):
        return "pdf"
    if data.startswith((b"\xde\x12\x04\x95", b"\x95\x04\x12\xde")):
        return "gettext-mo"
    head = data[:8192].lower()
    if b"[desc]" in head and b"[title]" in head:
        return "doorway-text-corpus"
    if b"<?php" in head or head.startswith(b"<?"):
        return "php-source"
    if re.match(rb"\s*\[[a-z0-9_.-]{2,32}\]\s*\n\s*listen\s*=", head):
        return "fpm-pool-config"
    if b"goaccess" in head:
        return "analytics-report"
    low = path.lower()
    for ext, name in EXTENSIONS:
        if low.endswith(ext):
            return name
    if low.endswith(".htaccess") or "/.htaccess" in low:
        return "htaccess"
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        return "binary-other"
    return "text-other"


def operation(path):
    """The containment operation: /root/INCIDENT/<operation>. One responder command."""
    parts = path.split("/")
    return "/".join(parts[:4]) if len(parts) > 3 else path


def role(path):
    """Where in a webroot the file sat, or which host-level tree it came from."""
    m = re.search(r"/(wp-content|wp-includes|wp-admin)"
                  r"(?:_{0,2}[0-9a-f]{4,8})?(?:/(plugins|themes|uploads|languages|cache"
                  r"|upgrade|mu-plugins))?", path)
    if m:
        return m.group(1) + ("/" + m.group(2) if m.group(2) else "")
    for token in ("cwp_stats", "open_basedir", "per-account-tmp",
                  "/logs/", "/mail/", "/etc/", "/tmp/", "/var/"):
        if token in path:
            return token.strip("/")
    return "other"


def slug_and_rel(path):
    """(<plugin or theme slug>, <path inside it>) for a webroot component file."""
    m = re.search(r"(?:plugins|themes)[/_]([A-Za-z0-9._-]+)[/_](.+)$", path)
    return (m.group(1), m.group(2)) if m else (None, None)


def blobmap():
    """sha256 -> collection-relative paths. The bytes are out of repo; this finds them."""
    out = {}
    with open(BLOBMAP, encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                r = json.loads(line)
                out[r["sha256"]] = r["paths"]
    return out


def upstream_paths():
    """slug -> every relative path a pinned release of that slug contains."""
    out = collections.defaultdict(set)
    for kind in ("wp-plugin", "wp-theme"):
        d = os.path.join(PINNED, kind)
        if not os.path.isdir(d):
            continue
        for entry in sorted(os.listdir(d)):
            root = os.path.join(d, entry)
            if not os.path.isdir(root):
                continue
            for slug in sorted(os.listdir(root)):
                sr = os.path.join(root, slug)
                if not os.path.isdir(sr):
                    continue
                for dirpath, _, filenames in os.walk(sr):
                    rel = os.path.relpath(dirpath, sr)
                    for fn in filenames:
                        out[slug].add(os.path.normpath(os.path.join(rel, fn)))
    return out


def lane_of(row, content):
    """Which lane a row belongs to. Flagged and archive both override the bulk lane."""
    if (row.get("observed_detection") or {}).get("rules"):
        return (operation(row["origin"]["path"]), FLAGGED, "")
    if content == "archive-container":
        return ARCHIVE_LANE
    p = row["origin"]["path"]
    return (operation(p), role(p), content)


def build(rows, read, upstream):
    """Lanes, each carrying the evidence the queue prints. Writes nothing."""
    lanes = {}
    for r in rows:
        p = r["origin"]["path"]
        data = read(r["sha256"])
        content = classify(data, p)
        key = lane_of(r, content)
        e = lanes.setdefault(key, dict(
            n=0, bytes=0, dirs=set(), accounts=set(), mtime_minutes=set(),
            rules=collections.Counter(), sensitivity=collections.Counter(),
            content=collections.Counter(), slugs=collections.Counter(),
            slug_pinned=0, path_attested=0, unresolved=0))
        e["n"] += 1
        e["bytes"] += r.get("size", 0)
        e["dirs"].add(p.rsplit("/", 1)[0])
        e["accounts"].add(r["origin"].get("account_hash") or r.get("account_hash") or "-")
        if r["origin"].get("mtime"):
            e["mtime_minutes"].add(r["origin"]["mtime"] // 60)
        e["content"][content] += 1
        if content == "unresolved":
            e["unresolved"] += 1
        for t in (r.get("sensitivity") or []):
            e["sensitivity"][t] += 1
        for c in (r.get("observed_detection") or {}).get("rules", []):
            e["rules"][c] += 1
        slug, rel = slug_and_rel(p)
        if slug:
            e["slugs"][slug] += 1
            if slug in upstream:
                e["slug_pinned"] += 1
                if rel.replace("_", "/") in upstream[slug] or rel in upstream[slug]:
                    e["path_attested"] += 1
    return lanes


def attestation(e):
    """The scanner-independent evidence for a bulk lane, or an explicit absence of one."""
    out = []
    top, n = e["content"].most_common(1)[0]
    if n == e["n"] and top not in ("text-other", "binary-other", "unresolved"):
        out.append("every file is %s by magic/structure (%d of %d)" % (top, n, e["n"]))
    elif n / float(e["n"]) >= 0.9:
        out.append("%d of %d are %s by magic/structure" % (n, e["n"], top))
    if e["path_attested"]:
        out.append("%d of %d sit at a path a pinned release of the same slug also has"
                   % (e["path_attested"], e["n"]))
    if not out:
        out.append("NO scanner-independent attestation: content class is mixed or generic")
    return out


def render(lanes, limit):
    order = sorted(lanes.items(), key=lambda kv: (-kv[1]["n"], kv[0]))
    total = sum(e["n"] for _, e in order)
    lines = []
    w = lines.append
    w("unreviewed rows in %s : %d" % (BUCKET, total))
    w("distinct directories                  : %d"
      % len(set(d for _, e in order for d in e["dirs"])))
    w("distinct containment operations       : %d"
      % len(set(k[0] for k, _ in order if k[0] != "*")))
    w("review lanes                          : %d" % len(order))
    cum, n80 = 0, 0
    for _, e in order:
        cum += e["n"]
        n80 += 1
        if cum >= 0.8 * total:
            break
    w("lanes covering 80%% of the rows        : %d" % n80)
    w("")
    cum = 0
    for i, (key, e) in enumerate(order[:limit], 1):
        cum += e["n"]
        op, rl, ct = key
        w("-" * 78)
        w("Q%-3d %6d rows  %5.1f%% cumulative   %d dir(s), %d account(s), %.1f MB"
          % (i, e["n"], 100.0 * cum / total, len(e["dirs"]), len(e["accounts"]),
             e["bytes"] / 1048576.0))
        w("     operation : %s" % ("(every operation)" if op == "*" else op))
        w("     lane      : %s%s" % (rl, " / " + ct if ct else ""))
        if rl == FLAGGED:
            w("     the scan already flagged every row here; these are NOT closable in bulk")
            w("     rules     : %s" % ", ".join("%s x%d" % (c, n)
                                                for c, n in e["rules"].most_common(8)))
        else:
            for a in attestation(e):
                w("     evidence  : %s" % a)
        w("     mtimes    : %d distinct minute(s) across %d file(s)"
          % (len(e["mtime_minutes"]), e["n"]))
        tags = ", ".join("%s x%d" % (t, n) for t, n in e["sensitivity"].most_common(5))
        w("     tags      : %s" % (tags or "-"))
        if e["slugs"]:
            w("     slugs     : %d distinct, %d row(s) under a slug with a pinned release"
              % (len(e["slugs"]), e["slug_pinned"]))
    return "\n".join(lines)


def inject():
    """Positive control: prove the router can say the other thing, in both directions.

    Two of these cases are the ones that matter and neither had ever fired. A file whose
    magic contradicts its extension must follow the magic - the corpus ships seven
    polyglots because that disagreement is the whole technique, and a router that trusted
    `.jpg` would file a dropper into a lane of photographs and close it in bulk. And a
    flagged row must leave its bulk lane no matter how ordinary its content looks, because
    the bulk lane is exactly where a closed judgement would swallow it.

    The negative half is as load-bearing: an ordinary JPEG must NOT be routed anywhere
    special. A router that specialises everything proves nothing about 23,612 rows.
    """
    fails = []

    def case(label, data, path, row, want_content, want_lane):
        content = classify(data, path)
        r = dict(row, origin=dict(row.get("origin", {}), path=path))
        lane = lane_of(r, content)
        got = "%s|%s" % (content, lane[1])
        ok = content == want_content and lane[1] == want_lane
        print("  %-58s %-34s %s" % (label, got, "ok" if ok else
                                    "WRONG (wanted %s|%s)" % (want_content, want_lane)))
        if not ok:
            fails.append(label)

    P = "/root/INCIDENT/op-20260101-000000/moved/acct01/wp-content/uploads/2021/01/%s"
    plain = {"origin": {}, "sensitivity": ["unreviewed"]}
    flagged = {"origin": {}, "sensitivity": ["unreviewed"],
               "observed_detection": {"rules": ["OBF024"]}}

    print("=== magic beats extension, in both directions ===")
    case("PHP payload named .jpg", b"<?php eval($_POST[1]);", P % "a.jpg",
         plain, "php-source", "wp-content/uploads")
    case("real JPEG named .php", b"\xff\xd8\xff\xe0\x00\x10JFIF", P % "b.php",
         plain, "image", "wp-content/uploads")
    case("zip named .png", b"PK\x03\x04\x14\x00", P % "c.png",
         plain, "archive-container", "ARCHIVE-CONTAINER")
    case("tar with no extension at all", b"\0" * 257 + b"ustar" + b"\0" * 20,
         P % "d", plain, "archive-container", "ARCHIVE-CONTAINER")

    print("=== a flagged row leaves its bulk lane whatever it looks like ===")
    case("flagged JPEG", b"\xff\xd8\xff\xe0\x00\x10JFIF", P % "e.jpg",
         flagged, "image", FLAGGED)
    case("flagged archive stays flagged, not filed as a container",
         b"PK\x03\x04\x14\x00", P % "f.zip", flagged, "archive-container", FLAGGED)

    print("=== the negative half: ordinary files must NOT be specialised ===")
    case("ordinary JPEG", b"\xff\xd8\xff\xe0\x00\x10JFIF", P % "g.jpg",
         plain, "image", "wp-content/uploads")
    case("ordinary stylesheet", b"body{margin:0}", P % "h.css",
         plain, "stylesheet", "wp-content/uploads")
    case("prose that merely mentions an archive", b"see the zip file PK for details",
         P % "i.txt", plain, "plain-text", "wp-content/uploads")

    print("=== structures this round turned on ===")
    case("doorway text corpus, extensionless",
         b"[DESC]x[/DESC]\n[KEYWORDS][/KEYWORDS]\n[TITLE]y[/TITLE]\n[TEXT]<p>z</p>[/TEXT]",
         "/root/INCIDENT/op-20260101-000000/moved/acct01-imported/some-slug",
         plain, "doorway-text-corpus", "other")
    case("php-fpm pool config", b"[acct01]\nlisten = /run/x.sock\nuser = \"acct01\"\n",
         "/root/INCIDENT/op-20260101-000000/open_basedir/php74-acct01.conf.bak",
         plain, "fpm-pool-config", "open_basedir")

    print("=== ordering and membership ===")
    lanes = {("op", "a", "x"): {"n": 5}, ("op", "b", "y"): {"n": 50}}
    first = sorted(lanes.items(), key=lambda kv: (-kv[1]["n"], kv[0]))[0][0][1]
    ok = first == "b"
    print("  %-58s %-34s %s" % ("queue is ordered by rows closed, descending",
                                "first=%s" % first, "ok" if ok else "WRONG"))
    if not ok:
        fails.append("ordering")

    print()
    if fails:
        print("INJECT FAILED: %d case(s): %s" % (len(fails), ", ".join(fails)))
        return 1
    print("inject: all cases routed correctly, positive and negative")
    return 0


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("--lanes", type=int, default=25)
    ap.add_argument("--markdown")
    ap.add_argument("--inject", action="store_true")
    args = ap.parse_args(argv)
    if args.inject:
        return inject()

    if not os.path.isfile(BLOBMAP):
        # Same rule fetch-benign.sh applies to zstd: name the missing thing and stop.
        # A content lane computed without the bytes would be a lane keyed on extensions,
        # which is the one thing this router exists not to do.
        print("missing: %s" % BLOBMAP, file=sys.stderr)
        print("the bytes live outside the repository; this tool needs the collection "
              "tree to classify content and will not fall back to extensions",
              file=sys.stderr)
        return 2

    rows = [r for r in read_jsonl(LOC)
            if r.get("bucket") == BUCKET and r.get("verdict") == "unreviewed"]
    bm = blobmap()

    def read(sha):
        for p in bm.get(sha, ()):
            fp = os.path.join(COLLECTION, p)
            if os.path.isfile(fp):
                with open(fp, "rb") as fh:
                    return fh.read(1 << 16)
        return None

    lanes = build(rows, read, upstream_paths())
    text = render(lanes, args.lanes)
    print(text)
    if args.markdown:
        with open(args.markdown, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
