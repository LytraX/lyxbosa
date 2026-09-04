#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Every writer of a corpus index goes through here.

Two failure modes, both live on 2026-09-04 when two sessions worked this tree at
once. Only the first one actually bit, and it cost a round.

**A reader saw a torn file.** `shard-gate.py --fix` opened a 62 MB index with
`"w"`, which truncates before the first row is written. A concurrent reader
measured 48,407 rows, then 14,148, then 79,467 - three moments of one write, not
three states of a corrupt file. It also saw fields that "appear nowhere in my
sources" and were gone seconds later: they were the other session's merge,
half-written. From outside there is no way to tell that from corruption, so the
round was correctly reported as possibly-torn and stopped. `make-summary --check`
passing in one instant and failing the next is the diagnostic tell.

**A writer could have lost the other's appends.** Nothing did, because only one
session was writing. Had both been, the last full-file rewrite would have
silently dropped the other's rows *with every gate still passing* - a
half-merged index is internally consistent, so no integrity check can catch it.
That is the more dangerous of the two and the one with no external symptom.

`write_jsonl_atomic` fixes the first: a reader sees the old complete file or the
new complete file, never a prefix. `index_lock` fixes the second.

An ad-hoc merge script is exactly as dangerous as this one was - if you write a
new index writer, import these rather than reaching for `open(path, "w")`.
"""
import json, os, sys, time, errno, fcntl, tempfile, contextlib

__all__ = ["write_jsonl_atomic", "read_jsonl", "index_lock", "LockBusy"]


class LockBusy(RuntimeError):
    """Another process holds the index lock."""


def read_jsonl(path):
    """Rows from a JSONL file, blank lines skipped."""
    with open(path, encoding="utf-8") as fh:
        return [json.loads(l) for l in fh if l.strip()]


def write_jsonl_atomic(path, rows, sort_keys=True):
    """Replace `path` with `rows` so that no reader ever observes a partial file.

    Writes a sibling temp file, fsyncs it, then `os.replace()`, which is atomic
    within a filesystem - the rename either has happened or has not. The temp
    file is a sibling rather than in /tmp precisely so the rename cannot cross a
    filesystem boundary and degrade to a copy.
    """
    path = os.path.abspath(path)
    directory = os.path.dirname(path) or "."
    mode = None
    try:
        mode = os.stat(path).st_mode & 0o777
    except FileNotFoundError:
        pass

    fd, tmp = tempfile.mkstemp(dir=directory,
                               prefix=os.path.basename(path) + ".",
                               suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            for r in rows:
                fh.write(json.dumps(r, sort_keys=sort_keys) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        # mkstemp is 0600; an index is world-readable and should stay that way.
        os.chmod(tmp, mode if mode is not None else 0o644)
        os.replace(tmp, path)
        tmp = None
    finally:
        if tmp is not None:
            try:
                os.unlink(tmp)
            except OSError:
                pass

    # Persist the rename, not just the bytes: without this a crash can leave the
    # directory entry pointing at the old inode.
    dirfd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(dirfd)
    except OSError:
        pass          # some filesystems refuse to fsync a directory
    finally:
        os.close(dirfd)


@contextlib.contextmanager
def index_lock(path, timeout=120.0, quiet=False):
    """Hold an exclusive lock covering `path` for the duration of the block.

    The lock is a sibling `.lock` file holding the owner's pid, so a wait can
    name what it is waiting for. Raises LockBusy after `timeout` rather than
    waiting forever - an agent that blocks silently is worse than one that says
    which pid to look at.
    """
    lock_path = os.path.abspath(path) + ".lock"
    deadline = time.time() + timeout
    announced = False
    fh = open(lock_path, "a+", encoding="utf-8")
    try:
        while True:
            try:
                fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError as exc:
                if exc.errno not in (errno.EACCES, errno.EAGAIN):
                    raise
                fh.seek(0)
                holder = fh.read().strip() or "unknown"
                if time.time() >= deadline:
                    raise LockBusy(
                        "%s is locked by %s; waited %.0fs. Another session is "
                        "writing the index - do not bypass this, its rows would "
                        "be lost silently." % (path, holder, timeout))
                if not announced and not quiet:
                    print("waiting for index lock on %s (held by %s)"
                          % (os.path.basename(path), holder), file=sys.stderr)
                    announced = True
                time.sleep(0.25)

        fh.seek(0)
        fh.truncate()
        fh.write("pid %d\n" % os.getpid())
        fh.flush()
        try:
            yield
        finally:
            fh.seek(0)
            fh.truncate()
            fh.flush()
            fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
    finally:
        fh.close()


def _selftest():
    """`python3 corpus/indexio.py --selftest`

    Reproduces the 2026-09-04 symptom against the old write, then shows it gone.
    The control half is what makes this worth keeping: a test that only proves
    the new path is clean cannot tell you the old path was the cause.
    """
    import shutil, tempfile, threading

    tmpdir = tempfile.mkdtemp(prefix="indexio-selftest.")
    try:
        path = os.path.join(tmpdir, "idx.jsonl")
        small = [{"sha256": "%064x" % i, "n": i} for i in range(2000)]
        big = [{"sha256": "%064x" % i, "n": i} for i in range(9000)]
        valid = {len(small), len(big)}

        def hammer(writer, target):
            writer(small)
            state = {"stop": False}
            seen, torn = set(), []

            def reader():
                while not state["stop"]:
                    try:
                        with open(target, encoding="utf-8") as fh:
                            txt = fh.read()
                    except FileNotFoundError:
                        torn.append("file absent")
                        continue
                    n = txt.count("\n")
                    seen.add(n)
                    if txt and not txt.endswith("\n"):
                        torn.append("partial final line at %d rows" % n)
                    elif n not in valid:
                        torn.append("intermediate row count %d" % n)

            t = threading.Thread(target=reader)
            t.start()
            for i in range(12):
                writer(big if i % 2 == 0 else small)
            state["stop"] = True
            t.join()
            return seen, torn

        def old_write(rows):
            with open(os.path.join(tmpdir, "old.jsonl"), "w", encoding="utf-8") as fh:
                for r in rows:
                    fh.write(json.dumps(r, sort_keys=True) + "\n")

        seen_old, torn_old = hammer(old_write, os.path.join(tmpdir, "old.jsonl"))
        seen_new, torn_new = hammer(lambda rows: write_jsonl_atomic(path, rows), path)

        print("control  open(path,'w'):  %2d distinct row counts %s, %d torn reads"
              % (len(seen_old), "(min %d, max %d)" % (min(seen_old), max(seen_old)),
                 len(torn_old)))
        print("fixed    write_jsonl_atomic: %d distinct row counts %s, %d torn reads"
              % (len(seen_new), sorted(seen_new), len(torn_new)))

        failures = []
        if torn_new or seen_new - valid:
            failures.append("write_jsonl_atomic exposed a partial file")
        if not torn_old:
            # Not a failure of the fix - a failure of the test to demonstrate
            # anything. Say so rather than reporting a hollow pass.
            print("note: the control did not tear on this run (timing); the "
                  "atomic assertion above still held")

        # Lock: a second holder must be refused, and the file must free after.
        lockable = os.path.join(tmpdir, "locked.jsonl")
        write_jsonl_atomic(lockable, small)
        with index_lock(lockable):
            try:
                with index_lock(lockable, timeout=0.5, quiet=True):
                    failures.append("index_lock admitted a second holder")
            except LockBusy:
                pass
        try:
            with index_lock(lockable, timeout=0.5, quiet=True):
                pass
        except LockBusy:
            failures.append("index_lock stayed held after its block exited")
        print("lock     mutual exclusion and release: %s"
              % ("FAIL" if failures else "ok"))

        for f in failures:
            print("FAIL:", f)
        return 1 if failures else 0
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        sys.exit(_selftest())
    sys.exit("usage: indexio.py --selftest   (this module is a library; see the docstring)")
