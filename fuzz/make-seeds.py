#!/usr/bin/env python3
"""Write the fuzz seed corpus. Synthetic, deterministic, and it reads nothing.

WHY IT READS NOTHING

A fuzzer copies its seeds into a working corpus, mutates them, and writes a new file for
every input it minimises. A seed drawn from `trail-data/`, `corpus/local/` or
`corpus/blobs/` would therefore multiply itself into a directory nobody is watching, on
its way to being nobody's idea of a deliberate copy. AGENTS.md is about what reaches the
remote; this is the same argument one step earlier, about what reaches a directory that
grows on its own.

`corpus/shards/` holds masked, published, redistributable rows and would have been
allowed. It is still not used here. A shard row is a masked *finding*, not a container,
and what these targets want is the shape of the parser input - a central directory, a tar
header block, a gzip member - which the shards do not carry. Synthetic inputs are also
reviewable: every byte below has a line of Python next to it saying what it is for, which
is not true of anything lifted from a real host.

WHAT THE SEEDS ARE FOR

libFuzzer finds a zip's magic quickly and its central directory almost never. The seeds
exist to put the fuzzer inside each parser, so the campaign spends its budget on the
branches that read attacker-controlled lengths, names and offsets rather than on
rediscovering "PK\\x03\\x04". Each one is aimed at a decision the readers make; the
comment on each says which.

Deterministic: every timestamp is pinned, so re-running this produces the same bytes and
`git status` stays quiet.

    python3 fuzz/make-seeds.py [--check]

--check writes nothing and exits non-zero if the committed seeds differ from what this
script would write - so a seed edited by hand, or a generator changed without
regenerating, is caught rather than discovered later.
"""

import argparse
import io
import os
import struct
import sys
import zipfile
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
SEEDS = os.path.join(HERE, "seeds")

# Pinned so the bytes are reproducible.
DOS_TIME = (2020, 1, 1, 0, 0, 0)

# Small, obvious, synthetic. Written here rather than lifted from anywhere: these strings
# exist to make the rule engine take its interesting branches on a member's bytes, not to
# be realistic samples of anything.
WEBSHELL = b"<?php @eval($_POST['c']); ?>\n"
ASSEMBLED = (b"<?php $a='ba';$b='se';$c='64';$d='_de';$e='code';"
             b"$f=$a.$b.$c.$d.$e; $g=$f('cGhwaW5mbygpOw=='); @$g(); ?>\n")
PLAIN = b"<?php\n// an ordinary file\necho 'hello';\n"


def zip_of(members, compression=zipfile.ZIP_DEFLATED):
    """A zip built by the standard library, with pinned timestamps."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression) as archive:
        for name, body in members:
            info = zipfile.ZipInfo(name, DOS_TIME)
            info.compress_type = compression
            info.external_attr = 0o644 << 16
            archive.writestr(info, body)
    return buffer.getvalue()


def gzip_of(payload, mtime=0):
    """A gzip member with a pinned mtime, built from raw deflate so nothing is guessed."""
    compressor = zlib.compressobj(9, zlib.DEFLATED, -zlib.MAX_WBITS)
    deflated = compressor.compress(payload) + compressor.flush()
    header = b"\x1f\x8b\x08\x00" + struct.pack("<I", mtime) + b"\x02\xff"
    trailer = struct.pack("<II", zlib.crc32(payload) & 0xFFFFFFFF, len(payload) & 0xFFFFFFFF)
    return header + deflated + trailer


def tar_header(name, size, typeflag=b"0", prefix=b"", magic=b"ustar\x0000"):
    """One 512-byte tar header block, checksum included.

    Hand-built rather than taken from tarfile, because several seeds below need a header
    that tarfile would refuse to write - that is the point of them.
    """
    block = bytearray(512)
    block[0:len(name)] = name[:100]
    block[100:108] = b"000644\x00 "
    block[108:116] = b"000000\x00 "
    block[116:124] = b"000000\x00 "
    block[124:136] = ("%011o\x00" % size).encode()
    block[136:148] = b"00000000000\x00"
    block[148:156] = b" " * 8          # checksum field reads as spaces while summing
    block[156:157] = typeflag
    block[257:265] = magic
    block[265:297] = b"root".ljust(32, b"\x00")
    block[297:329] = b"root".ljust(32, b"\x00")
    if prefix:
        block[345:345 + len(prefix)] = prefix[:155]
    checksum = sum(block) & 0o7777777
    block[148:156] = ("%06o\x00 " % checksum).encode()
    return bytes(block)


def tar_member(name, body, typeflag=b"0"):
    padded = body + b"\x00" * ((512 - len(body) % 512) % 512)
    return tar_header(name, len(body), typeflag) + padded


def tar_of(members):
    out = b"".join(tar_member(*m) for m in members)
    return out + b"\x00" * 1024


def lying_central_directory():
    """A zip whose central directory claims a member far larger than the file holds.

    The size in the index is what the pre-count believes and what the member-size guard
    tests, and it is attacker-controlled. This seed is the disagreement between what the
    index says and what the stream delivers.
    """
    body = b"x" * 16
    name = b"big.php"
    crc = zlib.crc32(body) & 0xFFFFFFFF
    claimed = 0xFFFFFF00                       # ~4 GB claimed, 16 bytes present

    local = (struct.pack("<IHHHHHIIIHH", 0x04034B50, 20, 0, 0, 0, 0,
                         crc, len(body), claimed, len(name), 0) + name + body)
    central = (struct.pack("<IHHHHHHIIIHHHHHII", 0x02014B50, 20, 20, 0, 0, 0, 0,
                           crc, len(body), claimed, len(name), 0, 0, 0, 0, 0, 0) + name)
    end = struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, 1, 1,
                      len(central), len(local), 0)
    return local + central + end


def archive_seeds():
    """Each entry: (filename, bytes, what decision in the readers it is aimed at)."""
    seeds = []

    seeds.append(("zip-webshell.zip", zip_of([("shell.php", WEBSHELL)]),
                  "the ordinary path: index, one deflated member, rules over its bytes"))

    seeds.append(("zip-assembled.zip", zip_of([("inc/loader.php", ASSEMBLED)]),
                  "a member whose bytes reach the PHP constant folder"))

    inner = zip_of([("shell.php", WEBSHELL)])
    seeds.append(("zip-nested.zip", zip_of([("payload.zip", inner)]),
                  "recursion: a container inside a container, at the depth limit of 2"))

    deeper = zip_of([("payload.zip", inner)])
    seeds.append(("zip-nested-3.zip", zip_of([("outer.zip", deeper)]),
                  "one level past maxDepth, so the depth skip is a reachable branch"))

    seeds.append(("zip-traversal.zip",
                  zip_of([("../../../../etc/passwd", b"root:x:0:0::/root:/bin/sh\n")]),
                  "a member name that escapes its own archive when normalised"))

    seeds.append(("zip-absolute-name.zip", zip_of([("/etc/shadow", b"x\n")]),
                  "an absolute member name"))

    seeds.append(("zip-site-backup.zip", zip_of([
        ("index.php", PLAIN),
        ("wp-config.php", b"<?php define('DB_PASSWORD','x'); ?>\n"),
        ("wp-content/themes/t/style.css", b"body{}\n"),
        ("wp-includes/version.php", b"<?php $wp_version='6.0'; ?>\n"),
        ("wp-admin/index.php", PLAIN),
    ]), "the index-only classification that makes the container itself the finding"))

    seeds.append(("zip-bomb.zip", zip_of([("zeros.bin", b"\x00" * (2 * 1024 * 1024))]),
                  "a compression ratio well past the guard, so the ratio branch is entered"))

    seeds.append(("zip-stored.zip", zip_of([("plain.php", PLAIN)], zipfile.ZIP_STORED),
                  "a stored member: no inflate at all"))

    seeds.append(("zip-lying-size.zip", lying_central_directory(),
                  "an index that claims ~4 GB for a 16-byte member"))

    seeds.append(("zip-empty.zip", zip_of([]),
                  "an archive with no members: the empty-index branch"))

    full = zip_of([("shell.php", WEBSHELL), ("a.php", PLAIN)])
    seeds.append(("zip-truncated.zip", full[:len(full) // 2],
                  "no end-of-central-directory: libzip refuses and the count must say so"))

    seeds.append(("zip-many-members.zip",
                  zip_of([("d%03d/f%03d.php" % (i // 16, i), PLAIN) for i in range(256)]),
                  "an index large enough for the per-member loop and the directory tallies"))

    seeds.append(("tar-webshell.tar", tar_of([(b"var/www/shell.php", WEBSHELL)]),
                  "the tar reader's ordinary path"))

    seeds.append(("tar-longname.tar",
                  tar_member(b"././@LongLink", (b"a/" * 80) + b"shell.php\x00", b"L") +
                  tar_member(b"long.php", WEBSHELL) + b"\x00" * 1024,
                  "a GNU long-name block, whose length is attacker-controlled"))

    pax = b"30 path=deeply/nested/shell.php\n"
    seeds.append(("tar-pax.tar",
                  tar_member(b"PaxHeader", pax, b"x") +
                  tar_member(b"shell.php", WEBSHELL) + b"\x00" * 1024,
                  "a PAX extended header, whose record lengths are attacker-controlled"))

    # 0o77777777777 is 8 GB in the eleven octal digits the field holds, and the header is
    # built through tar_header so the checksum COVERS that size. Spelling the field by hand
    # would leave the checksum describing a different header, and TarReader verifies the
    # checksum before it reads the size - so the seed would be turned away at the door and
    # would never reach the arithmetic it exists to exercise.
    seeds.append(("tar-huge-size.tar",
                  tar_header(b"huge.php", 0o77777777777, b"0") + b"\x00" * 1024,
                  "a valid header claiming 8 GB from a stream that holds nothing"))

    seeds.append(("tar-no-magic.tar",
                  tar_header(b"x.php", len(WEBSHELL), b"0", magic=b"\x00" * 8) +
                  WEBSHELL.ljust(512, b"\x00") + b"\x00" * 1024,
                  "a header with no ustar magic, which sniff() has to decide about"))

    seeds.append(("tar-symlink.tar",
                  tar_member(b"link.php", b"", b"2") + b"\x00" * 1024,
                  "a symlink entry, which has a target but no bytes"))

    tar_bytes = tar_of([(b"www/shell.php", WEBSHELL), (b"www/index.php", PLAIN)])
    seeds.append(("targz-webshell.tar.gz", gzip_of(tar_bytes),
                  "the gzip source feeding the tar reader, which is the .tar.gz path"))

    seeds.append(("gz-single.gz", gzip_of(WEBSHELL),
                  "a gzip that is not a tar: the single-member path"))

    seeds.append(("gz-truncated.gz", gzip_of(tar_bytes)[:40],
                  "a gzip stream that ends mid-deflate"))

    seeds.append(("gz-two-members.gz", gzip_of(PLAIN) + gzip_of(WEBSHELL),
                  "two concatenated gzip members, the second of which is easy to miss"))

    seeds.append(("gz-of-zip.gz", gzip_of(zip_of([("shell.php", WEBSHELL)])),
                  "a container inside a gzip, which is recursion through two readers"))

    return seeds


def content_seeds():
    seeds = []
    seeds.append(("php-eval-post.php", WEBSHELL, "the plainest webshell shape"))
    seeds.append(("php-assembled.php", ASSEMBLED, "fragments the constant folder resolves"))
    seeds.append(("php-assembled-long.php",
                  b"<?php $x=" + b".".join(b"'%c'" % (97 + i % 26) for i in range(400)) +
                  b"; @$x(); ?>\n",
                  "a 400-term concatenation, to price the folder's inner loop"))
    seeds.append(("php-variable-chain.php",
                  b"<?php\n" + b"".join(b"$v%d=$v%d.'%c';\n" % (i, i - 1, 97 + i % 26)
                                        for i in range(1, 200)) + b"@$v199(); ?>\n",
                  "a 200-link chain through variables, which the folder follows"))
    seeds.append(("php-dynamic-call.php",
                  b"<?php $f='sys'.'tem'; $$f; ${$f}('id'); @$f('id'); ?>\n",
                  "variable-variable and dynamic-call shapes"))
    seeds.append(("php-b64-gzinflate.php",
                  b"<?php @eval(gzinflate(base64_decode('" + b"A" * 512 + b"'))); ?>\n",
                  "nested decode calls with a long literal"))
    seeds.append(("php-invalid-utf8.php",
                  b"<?php $s=\"" + bytes(range(128, 256)) + b"\"; @eval($s); ?>\n",
                  "bytes that are not valid UTF-8 inside a string literal"))
    seeds.append(("php-unterminated.php", b"<?php $s='" + b"a" * 200,
                  "a string literal that never closes, so the scanner runs to EOF"))
    seeds.append(("php-nested-quotes.php",
                  b"<?php $a=\"a'b\\\"c\".'d\"e\\'f'; @eval($a); ?>\n",
                  "escapes and quote nesting, where a hand-written scanner loses count"))
    seeds.append(("html-phish.html",
                  b"<html><form action='https://example.invalid/x.php' method=post>"
                  b"<input name=password type=password></form></html>\n",
                  "the phishing rules, which read markup rather than PHP"))
    seeds.append(("perl-shell.pl",
                  b"#!/usr/bin/perl\nuse Socket;\nexec('/bin/sh -i');\n",
                  "the perl rules"))
    seeds.append(("binary-noise.bin", bytes((i * 37 + 11) % 256 for i in range(2048)),
                  "bytes that are not text at all, which every rule still sees"))
    seeds.append(("null-dense.bin", b"<?php\x00\x00\x00 eval\x00(\x00$_GET\x00);",
                  "embedded NULs inside otherwise matching text"))
    seeds.append(("one-long-line.php", b"<?php " + b"$x=1;" * 4000 + b"\n",
                  "a single 24 KB line, which the line/column arithmetic has to walk"))
    return seeds


def write_all(check_only):
    groups = {"archive": archive_seeds(), "content": content_seeds()}
    differences = []
    written = 0

    for group, seeds in groups.items():
        directory = os.path.join(SEEDS, group)
        if not check_only:
            os.makedirs(directory, exist_ok=True)
        expected = {name for name, _, _ in seeds}

        for name, payload, _purpose in seeds:
            path = os.path.join(directory, name)
            current = None
            if os.path.exists(path):
                with open(path, "rb") as handle:
                    current = handle.read()
            if current == payload:
                continue
            if check_only:
                differences.append("%s/%s differs from what make-seeds.py writes" % (group, name))
            else:
                with open(path, "wb") as handle:
                    handle.write(payload)
                written += 1

        if os.path.isdir(directory):
            for stray in sorted(os.listdir(directory)):
                if stray not in expected:
                    differences.append("%s/%s is not written by make-seeds.py" % (group, stray))

    total = sum(len(seeds) for seeds in groups.values())
    if check_only:
        for line in differences:
            print("  " + line)
        if differences:
            print("seeds DISAGREE with fuzz/make-seeds.py (%d)" % len(differences))
            return 1
        print("seeds agree with fuzz/make-seeds.py (%d files)" % total)
        return 0

    print("wrote %d of %d seed files under fuzz/seeds/" % (written, total))
    for group, seeds in groups.items():
        print("  %-8s %3d seeds, %6d bytes"
              % (group, len(seeds), sum(len(p) for _, p, _ in seeds)))
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true",
                        help="write nothing; fail if the committed seeds have drifted")
    args = parser.parse_args()
    return write_all(args.check)


if __name__ == "__main__":
    sys.exit(main())
