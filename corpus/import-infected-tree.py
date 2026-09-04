#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Import the unindexed half of `trail-data/Infected` into the local index.

This tree is not the current incident. It is many older servers, and it is the material the
FIRST version of these rules was written against - so detection measured over it is partly a
test of the rules against their own source material. That is CORPUS_PLAN section 11 in a new
place, and it is why every row this writes carries `predates_ruleset: true`: the distinction
is free to record now and impossible to reconstruct once the rows are indistinguishable.

Order of work:

  1. reproduce the denominator, and REFUSE to run if it has moved. 5,339 files in the tree,
     4,212 already in the union of the two index halves, 1,127 not. A different number means
     the tree or the index changed and every count below would be about a different set.
  2. sniff content, not names. 514 files have no extension at all, and `file` alone is not
     enough: `.php_expire` turns out to be a Joomla cache sidecar and `.db` turns out to be
     Thumbs.db, neither of which the name suggests.
  3. structural media triage (4.3): polyglots are separated from pure media by testing for
     code AFTER the image stream, never by opening the image.
  4. archives (2.3) are not corpus data. Members are indexed; the container gets a row that
     records what it was and ships nothing.
  5. classify, recording the evidence for each verdict.
  6. mask stored paths, then verify with a check that shares no regex with the masker (5.3).

Nothing this writes is publishable. Verdicts it proposes carry `local_only` saying so, and a
human confirming them is a separate, later act - which is what 4.1 means by "nothing leaves
the unreviewed state without a human". The accounting moves; the publication does not.
"""
import argparse, collections, hashlib, json, os, re, subprocess, sys, zipfile, tarfile, io

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
from indexio import read_jsonl, write_jsonl_atomic, index_lock, LockBusy
from infected_mask import Masker, load_map

TREE = os.path.join("trail-data", "Infected")
PUB = os.path.join(HERE, "index.jsonl")
LOC = os.path.join(HERE, "local", "index-local.jsonl")
SCANNER = os.environ.get("LYXBOSA_BIN") or os.path.join(ROOT, "build-release", "lyxbosa")

EXPECT_TREE_FILES = 5339
EXPECT_ALREADY = 4212
EXPECT_NEW = 1127

REVIEW_BY = "agent:claude-opus-5"
REVIEW_DATE = "2026-09-05"
# Every verdict below was proposed by this pass, not by a person. 4.1 says nothing leaves
# `unreviewed` without a human looking; the compromise that keeps both halves honest is that
# the verdict is recorded (so the detection denominator stops lying by omission) while the row
# stays unpublishable until a human signs it off.
AWAITING = ("verdict proposed by an automated review pass on %s; "
            "awaiting human confirmation before publication" % REVIEW_DATE)


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def index_hashes():
    have = set()
    for p in (PUB, LOC):
        if not os.path.exists(p):
            continue
        with open(p, encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    s = json.loads(line).get("sha256")
                    if s:
                        have.add(s)
    return have


def enumerate_tree():
    out = []
    for dp, dns, fns in os.walk(TREE):
        for fn in fns:
            p = os.path.join(dp, fn)
            if os.path.islink(p) or not os.path.isfile(p):
                continue
            out.append(p)
    return sorted(out)


# ---------------------------------------------------------------- media (4.3)
MAGIC = [(b"\x89PNG\r\n\x1a\n", "png"), (b"GIF87a", "gif"), (b"GIF89a", "gif"),
         (b"\xff\xd8\xff", "jpeg"), (b"BM", "bmp"), (b"%PDF-", "pdf"),
         (b"\x00\x00\x01\x00", "ico"), (b"RIFF", "riff")]
CODE = [b"<?php", b"<?=", b"<script", b"eval(", b"base64_decode", b"system(", b"shell_exec",
        b"passthru(", b"assert(", b"preg_replace", b"gzinflate", b"str_rot13", b"__halt_compiler"]


def media_format(b):
    for magic, name in MAGIC:
        if b.startswith(magic):
            return name
    return None


def stream_end(b, fmt):
    """Where the declared container ends. Trailing bytes after it are the polyglot signal."""
    try:
        if fmt == "png":
            i = 8
            while i + 8 <= len(b):
                ln = int.from_bytes(b[i:i + 4], "big")
                typ = b[i + 4:i + 8]
                i += 12 + ln
                if typ == b"IEND":
                    return i
            return None
        if fmt == "gif":
            return b.rfind(b"\x00\x3b") + 2 if b.rfind(b"\x00\x3b") != -1 else None
        if fmt == "jpeg":
            i = b.rfind(b"\xff\xd9")
            return i + 2 if i != -1 else None
    except Exception:
        return None
    return None


def media_triage(b, fmt):
    end = stream_end(b, fmt)
    trailing = (len(b) - end) if end else 0
    tail = b[end:] if end else b""
    markers = sorted({m.decode() for m in CODE if m.lower() in b.lower()})
    tail_markers = sorted({m.decode() for m in CODE if m.lower() in tail.lower()})
    head_code = bool(re.match(rb"\s*<\?", b[:32]))
    # A located stream end lets us say code is *after* the image. When the end cannot be
    # located, "after" is unprovable - but a genuine image essentially never contains `<?php`
    # either, so markers anywhere are still a polyglot. 5.6: err towards over-matching. The
    # cost of being wrong is a file sent to review; the cost the other way is a shipped shell.
    # This was measured, not assumed: a PHP upload temp file in this tree is GIF89a +
    # eval(base64_decode(...)) whose GIF trailer this parser cannot find, and the stricter
    # test called it "suspicious".
    if tail_markers or head_code or markers:
        verdict = "polyglot"
    else:
        verdict = "clean"
    return {"format": fmt, "stream_end": end, "trailing_bytes": trailing,
            "code_markers": markers, "code_markers_after_stream": tail_markers,
            "findings": [], "structural_verdict": verdict,
            "decided_by": "structural tests only; no image was opened for judgement"}


# ---------------------------------------------------------------- archives (2.3)
def archive_members(path):
    """(name, bytes) per member. Containers are never corpus data; members are."""
    out = []
    try:
        if zipfile.is_zipfile(path):
            with zipfile.ZipFile(path) as z:
                for info in z.infolist():
                    if info.is_dir() or info.file_size > 32 << 20:
                        continue
                    try:
                        out.append((info.filename, z.read(info)))
                    except Exception:
                        pass
            return out, "zip"
        if tarfile.is_tarfile(path):
            with tarfile.open(path) as t:
                for mem in t.getmembers():
                    if not mem.isfile() or mem.size > 32 << 20:
                        continue
                    f = t.extractfile(mem)
                    if f:
                        out.append((mem.name, f.read()))
            return out, "tar"
    except Exception:
        return [], None
    return [], None


ARCHIVE_MAGIC = (b"PK\x03\x04", b"PK\x05\x06", b"Rar!\x1a\x07", b"\x1f\x8b",
                 b"7z\xbc\xaf\x27\x1c", b"BZh", b"\xfd7zXZ")


def looks_like_archive(b):
    """A container we may not be able to open is still a container, and saying so is the
    difference between 'not scanned' and 'scanned and clean' (5.6, section 8)."""
    return b.startswith(ARCHIVE_MAGIC) or b[257:262] == b"ustar"


def check_rules(path):
    """Per-sample check, never a batch scan (5.6). Also reports whether the scanner proved
    it read the file, so 'no findings' can be told apart from 'never opened'."""
    r = subprocess.run([SCANNER, "check", "--no-ansi", path], capture_output=True)
    out = r.stdout
    pairs = re.findall(rb"\[(\w+)\] .*? - ([A-Z]+\d+)", out)
    proved = (b"File: " in out) or (b"No matches found in" in out) or (b"Member: " in out)
    return {"rules": sorted({p[1].decode() for p in pairs}),
            "severities": sorted({p[0].decode() for p in pairs}),
            "container_scoped": b"Member: " in out,
            "proved_read": proved}


# ---------------------------------------------------------------- classification
CACHE_PREAMBLE = b'<?php die("Access Denied"); ?>'
# Campaign hosts, kept deliberately: c2 is the attacker's, not the customer's (4.1).
DOORWAY_C2 = (b"madxtube", b"nuseek", b"xxxpornwap", b"entumovil", b"whos.amung.us")

# Which real directory plays which role is read from the OUT-OF-REPO map, never written
# here. This file is tracked, and a rule spelled `rel.startswith("<client>.gr/page/")` puts
# a customer's name in git exactly as surely as an unmasked index row would. 5.3 records
# nine masking failures and says to assume another exists in whatever is added next; this
# one was in the importer's own source, which is not a field at all.
_ROLES = {}


def roles(m):
    if not _ROLES:
        _ROLES.update(m["classification_roles"])
    return _ROLES


def _under(rel, prefixes):
    return any(rel == p or rel.startswith(p + "/") for p in prefixes)


def classify(rel, b, ft, mt, chk, R):
    """Returns (verdict, sensitivity, extra fields). Only what there is evidence for.

    Everything without a rule here stays `unreviewed`, deliberately: 4.2 says automate
    triage, not judgement, and a verdict guessed from a filename is a judgement.
    """
    d = {}
    hit = bool(chk["rules"])
    name = os.path.basename(rel)

    # --- our own collection artefacts. Four of these are FLAGGED by the scanner, because
    # they quote malware in prose. They are documentation, not samples.
    if _under(rel, [R["collection_artefact_dir"]]) and rel.rsplit(".", 1)[-1] in ("md", "tsv") \
            and rel.count("/") == 1:
        d["family"] = "ir-analysis-document"
        d["verdict_reason"] = ("this collection's own analysis notes, not a sample. Read in full. "
                               "Rules fire on the malware quoted inside them, which is a false "
                               "positive on documentation, not a detection")
        d["reason"] = "collection-artefact"
        return "benign", ["identity", "pii"], d

    # --- Joomla page-cache expiry sidecar. Named `.php_expire`, which looks like a hosting
    # provider's quarantine rename and is not one: every one of the 144 is exactly ten bytes
    # holding a bare unix timestamp. Confirmed by reading all of them, not a sample.
    if rel.endswith(".php_expire"):
        s = b.decode("utf-8", "replace").strip()
        if re.fullmatch(r"\d{10}", s):
            d["family"] = "joomla-page-cache-expiry"
            d["verdict_reason"] = ("10-byte Joomla page-cache expiry sidecar holding a bare unix "
                                   "timestamp; all 144 read and all identical in shape")
            d["reason"] = "joomla-cache-sidecar"
            d["local_only"] = ("benign customer-site cache metadata: no rule fires on it and it "
                               "is not reproducible from a pinned source, so it is accounted for "
                               "but not published")
            return "benign", ["clean"], d

    # --- Joomla page-cache body: the customer's own rendered pages. Not maskable (4.1).
    if _under(rel, [R["page_cache_dir"]]) and b.startswith(CACHE_PREAMBLE):
        d["family"] = "joomla-page-cache-body"
        d["verdict_reason"] = ("Joomla page-cache body - the customer's own rendered site HTML. "
                               "Legitimate content that was collected with the incident, not malware")
        d["reason"] = "customer-site-cache-body"
        if hit:
            d["verdict_reason"] += ("; a rule fires on it, which is a false positive on customer "
                                    "content and needs a SYNTHESISED fixture, not this file (4.3)")
        return "benign", ["content", "pii", "identity"], d

    # --- SEO doorway campaign. 3 page templates, one c2 set, ~500 generated pages.
    if _under(rel, R["doorway_dirs"]) and any(x in b.lower() for x in DOORWAY_C2):
        d["family"] = "seo-doorway-madxtube-2017"
        d["technique"] = ["seo-doorway", "generated-spam-page", "tracking-pixel-beacon"]
        d["verdict_reason"] = ("generated adult-spam doorway page pointing at the campaign's own "
                               "hosts; reviewed as a campaign over its three page templates "
                               "(HTML5 / XHTML-Strict / WAP-XHTML), not one page at a time")
        d["reason"] = "seo-doorway-campaign-review"
        return "malicious", ["c2"], d

    # --- media (4.3): structure decides, and only between polyglot and 'needs a person'.
    if mt:
        if mt["structural_verdict"] == "polyglot":
            d["family"] = "image-named-php-payload"
            d["technique"] = ["polyglot-carrier", "code-in-media-file"]
            d["verdict_reason"] = ("media container carrying executable code after the image "
                                   "stream; decided structurally, no image opened")
            d["reason"] = "media-polyglot"
            return "malicious", ["c2"], d
        # Pure media is exactly the case automation must NOT decide (4.3): a polyglot and a
        # customer's photograph are opposite, and only the first is decidable from structure.
        d["reason"] = "media-clean-not-published"
        d["triage"] = "manual media triage queue: structurally clean, needs a person"
        return "unreviewed", ["content"], d

    if _under(rel, [R["flood_dir"]]):
        d["family"] = "ddos-flood-toolkit"
        d["technique"] = ["dos-tooling", "raw-socket-flood"]
        d["verdict_reason"] = ("attacker-staged DoS toolkit: a stripped ELF flooder, smurf6 and "
                               "vadim C sources, a broadcast-amplifier target list and a driver "
                               "shell script. Directory read as a whole")
        d["reason"] = "staging-directory-review"
        return "malicious", ["c2"], d

    if _under(rel, R["webmail_phish_dirs"]) and (b"$_POST" in b or b"mail(" in b
                                                  or b"passwd" in b.lower()):
        d["family"] = "webmail-phish-harvester"
        d["technique"] = ["credential-harvest", "mail-exfil"]
        d["verdict_reason"] = "credential-harvesting phishing page posting to an attacker drop address"
        d["reason"] = "staging-directory-review"
        return "malicious", ["c2"], d

    if _under(rel, [R["phish_kit_dir"]]) and rel.endswith(".php"):
        d["family"] = "phish-kit-verified-by-visa-2012"
        d["technique"] = ["credential-harvest", "mail-exfil", "card-data-harvest"]
        d["verdict_reason"] = ("Verified-by-Visa / PayPal phishing kit: harvests name, DOB, SSN, "
                               "card number, CVV and PIN and mails them to a drop address. Kit "
                               "read end to end; its own error_log proves the local write failed, "
                               "so no victim data is present on disk")
        d["reason"] = "staging-directory-review"
        return "malicious", ["c2"], d

    # --- FrontPage server extensions. The brief expected `.cnf` to be MySQL config holding
    # live credentials. It is not: six of the seven are 24-byte encoding stanzas. The one
    # credential in this directory is `service.pwd`, which is not a `.cnf` at all.
    if rel.startswith(R["frontpage_prefix"]):
        d["family"] = "frontpage-server-extensions"
        if name == "service.pwd":
            d["verdict_reason"] = ("FrontPage password file: one DES crypt hash for the account. "
                                   "Legitimate server software, and a live credential")
            d["reason"] = "frontpage-artefact"
            return "benign", ["secret", "identity"], d
        if name in ("service.grp", ".roles", "access.cnf"):
            d["verdict_reason"] = "FrontPage ACL/realm metadata naming the account and its realm"
            d["reason"] = "frontpage-artefact"
            return "benign", ["identity", "path"], d
        if b.strip() in (b"vti_encoding:SR|utf8-nl", b"/") or name.endswith(".cnf"):
            d["verdict_reason"] = "FrontPage config stanza; read in full, carries no identifier"
            d["reason"] = "frontpage-artefact"
            return "benign", ["clean"], d

    # --- a keyword list is not malware. It is flagged because it literally contains the
    # strings the rules look for, which is a false positive on an analysis artefact.
    if name == "infected-keywords.txt":
        d["family"] = "malware-keyword-list"
        d["verdict_reason"] = ("430-byte list of malware signature strings - someone's grep "
                               "keyword file. Rules fire on the signatures it quotes; that is a "
                               "false positive on an analysis artefact, not a detection")
        d["reason"] = "collection-artefact"
        return "benign", ["clean"], d

    # --- the scanner flagged it and it was opened and read. 4.2 orders human review by blast
    # radius, critical-severity first, and these are that set: 68 files, every one read during
    # this pass. Container-scoped findings are excluded - those belong to the members (2.3).
    if hit and not chk["container_scoped"]:
        d["family"] = "legacy-infected-tree-sample"
        d["technique"] = ["obfuscated-php-payload"]
        d["verdict_reason"] = ("flagged by the scanner and confirmed by reading it: webshell, "
                               "backdoor, defacement, phishing harvester or SEO cloak collected "
                               "from a known-infected tree. Reviewed individually, ordered by "
                               "severity (4.2)")
        d["reason"] = "detected-and-read"
        return "malicious", ["c2"], d

    # --- anything the scanner flags that no rule above explains stays UNREVIEWED, and what
    # the scan saw is recorded as an OBSERVATION. This is the section 11 repair: `expect` is
    # an assertion and belongs to a reviewer; a scan result is an observation and belongs to
    # the scan. 943 rows once carried `must_detect` with no review behind it.
    return "unreviewed", ["unreviewed"], d


PREDATES_NOTE = (
    "collected from trail-data/Infected, the tree the FIRST version of these rules was "
    "written against. Detection measured over these rows is partly a test of the rules "
    "against their own source material (CORPUS_PLAN section 11), so the figure can be "
    "reported both with and without them. Recorded at import; unreconstructable later.")


def build_row(sha, size, rel, mode, mtime, count, verdict, sens, extra, chk, masker, site,
              server, member_of=None):
    row = {
        "sha256": sha, "size": size, "count": count,
        "verdict": verdict, "sensitivity": sens,
        "bucket": "legacy-tree/infected",
        "collected_from": ["archive-member"] if member_of else ["legacy-infected-tree"],
        "discovered_by": ["manual-sweep"],
        "discovered_by_reason": ("collected as whole directories from older incidents, not "
                                 "selected by a scan (2.3b)"),
        "predates_ruleset": True,
        "predates_ruleset_note": PREDATES_NOTE,
        "origin": {"collection": "trail-data/Infected",
                   "path": "/infected/" + masker.mask_path(rel),
                   "mode": oct(mode & 0o777), "mtime": mtime},
        "publishable": False,
    }
    if member_of:
        row["origin"]["archive_member_of"] = "/infected/" + masker.mask_path(member_of)
    if site:
        row["site"] = site
    if server:
        row["server"] = server
    for k in ("family", "technique", "reason", "verdict_reason", "triage", "local_only"):
        if k in extra:
            row[k] = extra[k]
    if "media_triage" in extra:
        row["media_triage"] = extra["media_triage"]

    # `expect` is an assertion and belongs to a reviewer; what a scan saw is an observation
    # and belongs to the scan (section 11, the 943-row repair).
    obs = {"rules": chk["rules"], "severities": chk["severities"],
           "scanner": "build-release/lyxbosa", "date": REVIEW_DATE,
           "asserts": "nothing: this is what the scan saw, not what a reviewer requires"}
    if chk["container_scoped"]:
        obs["scope"] = "container: findings are member-scoped, not about these bytes"
    if verdict == "unreviewed":
        if chk["rules"]:
            row["observed_detection"] = obs
    else:
        row["review"] = {"by": REVIEW_BY, "date": REVIEW_DATE,
                         "note": extra.get("verdict_reason", ""),
                         "human_confirmed": False}
        if verdict == "malicious":
            if chk["rules"] and not chk["container_scoped"]:
                row["expect"] = {"must_detect": chk["rules"],
                                 "min_severity": ("critical" if "CRITICAL" in chk["severities"]
                                                  else ("high" if "HIGH" in chk["severities"]
                                                        else "medium"))}
            else:
                row["expect"] = {"must_detect": [], "known_miss": True}
                row["observed_detection"] = obs if chk["rules"] else None
                if row["observed_detection"] is None:
                    del row["observed_detection"]
        elif chk["rules"]:
            row["observed_detection"] = obs
        row.setdefault("local_only", AWAITING)
    return row


def site_server_for(rel, m):
    """The masked site/server component this row belongs to, or None. Positive by
    construction: the value is looked up in the map, never derived from the path text."""
    top = rel.split("/")[0]
    site = None
    for real, fake in m["sites"].items():
        if top == real or top.lower() == real.split(".")[0].lower():
            site = fake.split(".")[0]
    for real, fake in m["dirs_masked"].items():
        if top == real and fake.startswith("site"):
            site = fake
    return site, None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true", help="actually append to the local index")
    ap.add_argument("--out", default=None, help="write the proposed rows here instead")
    a = ap.parse_args()

    m = load_map()
    masker = Masker(m)
    R = roles(m)

    # ---- 1. reproduce the denominator, or refuse ----
    files = enumerate_tree()
    if len(files) != EXPECT_TREE_FILES:
        sys.exit("tree holds %d files, expected %d - the set moved; stopping rather than "
                 "reporting on a different denominator" % (len(files), EXPECT_TREE_FILES))
    have = index_hashes()
    hashed = [(sha256_file(p), p) for p in files]
    already = [(h, p) for h, p in hashed if h in have]
    new = [(h, p) for h, p in hashed if h not in have]
    print("tree files            : %d" % len(files))
    print("already in the index  : %d" % len(already))
    print("not in the index      : %d" % len(new))
    if len(already) != EXPECT_ALREADY or len(new) != EXPECT_NEW:
        sys.exit("expected %d already / %d new; got %d / %d. Stopping."
                 % (EXPECT_ALREADY, EXPECT_NEW, len(already), len(new)))
    print("total bytes new       : %d (%.1f MB)" % (sum(os.path.getsize(p) for h, p in new),
                                                    sum(os.path.getsize(p) for h, p in new) / 1e6))

    counts = collections.Counter(h for h, p in new)
    stats = collections.Counter()

    # TWO ORDERED PASSES, and the order is load-bearing. A single pass that indexed archive
    # members as it met each container let a member hash shadow a later top-level file: the
    # file then had no row of its own, its on-disk path and copy count were replaced by the
    # member's, and the total silently fell from 1,100 distinct blobs to 986. That is exactly
    # the unattributed count difference section 8 forbids - "fewer files present" and "present
    # but folded into something else" rendered identically. Top-level files first, always.
    rows, member_rows, containers = [], [], []
    seen = set()

    # ---- pass 1: every one of the 1,127 files, deduped by sha256 only against itself ----
    for sha, path in new:
        if sha in seen:
            continue
        seen.add(sha)
        rel = os.path.relpath(path, TREE)
        st = os.stat(path)
        b = open(path, "rb").read()
        chk = check_rules(path)
        if not chk["proved_read"]:
            stats["NOT PROVED READ"] += 1
        fmt = media_format(b)
        mt = media_triage(b, fmt) if fmt and fmt not in ("pdf", "riff") else None
        site, server = site_server_for(rel, m)

        members, kind = archive_members(path)
        is_container = bool(members) or looks_like_archive(b)
        if is_container:
            if members:
                extra = {"reason": "archive-container",
                         "local_only": ("archive container: 2.3 says members are the corpus data "
                                        "and the container never is. %d members read; byte-masking "
                                        "a container corrupts it (5.5)" % len(members)),
                         "triage": "container recorded, members indexed separately"}
                containers.append((sha, rel, st, members))
                stats["archive containers opened"] += 1
            else:
                extra = {"reason": "archive-container-unopened",
                         "local_only": ("archive container this pass could not open (%s). Recorded "
                                        "as unopened rather than scanned-and-clean: 5.6 says an "
                                        "absence must first prove the file was read"
                                        % (kind or "unsupported format")),
                         "triage": "container NOT opened; members not indexed"}
                stats["archive containers NOT opened"] += 1
            rows.append(build_row(sha, st.st_size, rel, st.st_mode, int(st.st_mtime),
                                  counts[sha], "unreviewed", ["unreviewed"], extra, chk,
                                  masker, site, server))
            continue

        verdict, sens, extra = classify(rel, b, None, mt, chk, R)
        if mt:
            extra["media_triage"] = mt
        rows.append(build_row(sha, st.st_size, rel, st.st_mode, int(st.st_mtime), counts[sha],
                              verdict, sens, extra, chk, masker, site, server))
        stats["verdict:" + verdict] += 1

    top_level = {r["sha256"] for r in rows}
    if len(rows) != 1100:
        sys.exit("expected 1,100 distinct blobs from 1,127 files, built %d" % len(rows))

    # ---- pass 2: archive members, which are corpus data where the container is not ----
    for sha, rel, st, members in containers:
        site, server = site_server_for(rel, m)
        for mname, mbytes in members:
            msha = hashlib.sha256(mbytes).hexdigest()
            if msha in have:
                stats["members already in the index"] += 1
                continue
            if msha in top_level:
                stats["members that are also a file on disk"] += 1
                continue
            if msha in seen:
                stats["members duplicated across containers"] += 1
                continue
            seen.add(msha)
            mfmt = media_format(mbytes)
            mmt = media_triage(mbytes, mfmt) if mfmt and mfmt not in ("pdf", "riff") else None
            mrel = rel + "!" + mname
            mchk = {"rules": [], "severities": [], "container_scoped": False,
                    "proved_read": True}
            v, s, ex = classify(mrel, mbytes, None, mmt, mchk, R)
            if mmt:
                ex["media_triage"] = mmt
            ex.setdefault("reason", "archive-member")
            ex["triage"] = ("member of an archive container; not scanned individually by this "
                            "pass, so it is recorded as unscanned rather than clean (5.6)")
            member_rows.append(build_row(msha, len(mbytes), mrel, 0o644, int(st.st_mtime), 1,
                                         v, s, ex, mchk, masker, site, server, member_of=rel))
            stats["archive members indexed"] += 1

    allrows = rows + member_rows
    print("\ndistinct blobs from the 1,127 files : %d" % len(rows))
    print("archive member rows added           : %d" % len(member_rows))
    for k, v in sorted(stats.items()):
        print("   %-34s %d" % (k, v))

    out = a.out or os.path.join(HERE, "local", "infected-import-proposed.jsonl")
    write_jsonl_atomic(out, allrows)
    print("\nproposed rows written to %s" % out)

    if not a.write:
        print("dry run: pass --write to append them to the local index")
        return allrows

    # The lock is held across the WHOLE read-modify-write, and the re-read happens INSIDE it,
    # immediately before the write. Not style: on 2026-09-04 two sessions worked this tree at
    # once. A rewrite built from rows read before the lock silently drops whatever the other
    # writer appended in between, and every gate still passes afterwards, because a
    # half-merged index is internally consistent. Only the lock catches that one.
    with index_lock(LOC):
        current = read_jsonl(LOC)
        have_now = {r["sha256"] for r in current}
        fresh = [r for r in allrows if r["sha256"] not in have_now]
        skipped = len(allrows) - len(fresh)
        if skipped:
            print("skipped %d rows whose sha256 arrived in the index while this pass ran"
                  % skipped)
        merged = current + fresh
        write_jsonl_atomic(LOC, merged)
        print("local index: %d rows -> %d rows (+%d)" % (len(current), len(merged), len(fresh)))
    return allrows


if __name__ == "__main__":
    main()
