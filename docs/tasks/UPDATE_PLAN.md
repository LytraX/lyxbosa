# Updating the binary

A plan, not an implementation. **Phases 0 and 1 are built**; phases 2 to 4 - the updater
itself - are not, and nothing in the binary reads a signature yet. What shipped is in
[`docs/RELEASING.md`](../RELEASING.md) under *Release integrity*, and the signing key still
has to be provisioned once before the next release.

## 1. The problem, and what is not the problem

A user who installed `lyxbosa` from a release has no way to learn that a newer one exists
short of visiting GitHub. Detection rules are the whole product, so a stale binary is a
degraded product — `v2.1.0` is missing ten rules including one that closes 46 known misses.

What is **not** the problem: getting Windows or macOS to trust the download. That is code
signing, it is a separate mechanism, and it is deliberately out of scope — see §3.

## 2. Prerequisite: a release you can verify

**When this was written, the `v*` releases published four bare binaries and nothing else.**
No checksums, no signatures. There is nothing for an updater to check a download against, and an updater that
downloads and executes an unverified binary is worse than no updater at all: this scanner runs
as root, on compromised hosts, during incident response. The update path would be the highest
value target in the product.

So the first change is not the updater. The rest of this section is the argument that put
phases 0 and 1 first; both have since shipped, and what follows is left as it was written.

**Phase 0 — checksums.** `.github/workflows/build.yml` already collects every artefact into
`artifacts/` and hands `artifacts/*` to `softprops/action-gh-release`. Generating
`SHA256SUMS` into that directory before the release step is a three-line addition, and the
corpus release path already does exactly this (`corpus/release-assets.sh`), so the pattern is
established rather than invented.

A checksum published beside the file it describes defends against a truncated or corrupted
download. It does **not** defend against anyone who can write to the release, because they can
write the checksum too. That is what signing is for.

**Phase 1 — signatures.** `minisign` (or `signify`): one small public key, embedded in the
binary and committed to the repository; the private key held as a CI secret and used only by
the release job. The updater verifies the signature over `SHA256SUMS` and then the hash of the
asset. Free, no certificate authority, no annual fee.

Two things to design in from the start rather than retrofit:

- **Rotation.** If the key is ever compromised, every installed binary trusts the attacker.
  The verifier should accept a signature from any key in a short embedded list, so a new key
  can ship in release N and the old one be dropped in release N+2.
- **Key handling.** The private key never enters the repository, a build log, or a local
  checkout. `pre-push-check.py` should learn its public form so a private key pasted into a
  tracked file is refused the way a customer identifier is.

## 3. Why the missing EV certificate does not block this

Authenticode signing with an EV certificate makes **Windows** trust an executable — it is
what removes the SmartScreen "unknown publisher" warning. It is expensive, it requires a
hardware token, and it is not owned here.

Update integrity is a different question: it is whether **the updater** trusts the bytes it
just downloaded. That needs a signature the updater itself verifies, and minisign does it with
no CA and no cost. The two are independent, and only the second is needed for a safe updater.

The honest consequence of having no EV certificate: a user downloading a Windows build from a
browser still sees an unknown-publisher warning, exactly as they do today. The updater does not
make that worse, and signing the release does not make it better. If an EV certificate is bought
later it slots in beside minisign rather than replacing it, because it answers the other
question.

## 4. The trust boundary, stated rather than implied

With Phase 1 in place, a verified update proves the bytes were signed by whoever holds the
release key. It defends against a tampered asset, a hostile mirror, a MITM on the download, and
a corrupted transfer.

It does **not** defend against a compromise of this repository or its CI, because the signing
key lives there. That is the same trust boundary as the release itself, and no self-updater can
do better without a separate, offline signing step. Saying so in the documentation is part of
the deliverable — a security tool that overstates its own guarantees is worse than one that
states a modest guarantee accurately.

## 5. When to check — and why not on every run

**Not on every run.** Four reasons, in order of how decisive they are:

1. **`check` is called programmatically.** `corpus/verify.py` runs `lyxbosa check` once per
   sample — 167 invocations in one suite run today. Anything that adds a network call per
   invocation breaks that, and it is exactly how the tool is meant to be used from scripts.
2. **It runs in cron, fanned out.** A scanner scheduled hourly across a hundred hosts is a
   hundred requests an hour to one API. Unauthenticated GitHub API is rate-limited per IP, so
   a shared egress address makes the check fail — and a failed check must never affect a scan.
3. **It runs during incident response.** An outbound request on every invocation tells GitHub,
   and anyone with network visibility on the host, that a scan is starting and when. On an
   engagement that is telemetry about the investigation.
4. **It runs in containers and egress-filtered networks**, where the check will hang or fail.
   Latency added to a 17-minute scan is irrelevant; latency added to a scriptable single-file
   command is not.

**What to do instead**, narrowest thing that still nudges:

| condition | check? |
|---|---|
| `lyxbosa update --check`, explicit | always |
| interactive `scan` — stdout is a terminal, no `--quiet`/`--silent`/`--force` | at most once per interval |
| `check` subcommand | **never** |
| `--quiet`, `--silent`, `--force`, non-interactive, CI detected | **never** |
| no cached state file writable | never, silently |

And the check itself: asynchronous, hard timeout of about two seconds, result cached in a state
file with a timestamp, and **it can never fail a scan or change an exit code**. A scanner that
exits non-zero because GitHub was slow is a broken scanner.

The interval wants to be a day rather than an hour. A rule set does not change hourly and the
point is to catch a user months behind, not minutes.

**Check and tell, not download and replace.** The default reports that a newer version exists
and how to get it. Downloading and swapping the binary happens only when a person types
`lyxbosa update`.

## 6. Command surface

```
lyxbosa update            # download, verify, replace — asks first unless --yes
lyxbosa update --check    # report only; exit 0 up to date, 2 update available
lyxbosa update --to VER   # a specific version, including downgrade
```

`--check`'s exit code matters: it makes the command usable from a monitoring script without
parsing output, which is the same discipline the scan exit codes already follow.

## 7. Replacing a running binary

- **Linux and macOS.** A running executable can be unlinked and replaced; the running process
  keeps its inode. Write the new binary beside the old one, verify it, `fsync`, then
  `os.replace` — atomic, and a crash mid-update leaves the old binary in place. Same discipline
  as `indexio.write_jsonl_atomic`.
- **Windows.** A running `.exe` cannot be replaced. The update writes `lyxbosa.exe.new` and
  renames on next start, or spawns a short-lived helper. This is the one place the platforms
  genuinely differ and it needs its own testing.
- **Permissions.** If the binary is not writable by the current user, refuse with the reason
  rather than escalating. A scanner run under `sudo` that rewrites a system binary because a
  check said so is a footgun.
- **Package managers.** If the binary sits under a path a package manager owns, decline and say
  so. An updater fighting `apt` is worse than no updater.

## 8. Configuration

A new top-level section beside `scan`, `archives`, `builtin_rules` and `actions`:

```yaml
updates:
  check: periodic      # off | on-demand | periodic
  interval: 24h
  # allow_prerelease: false
```

`off` makes the tool never reach the network unless `update` is typed. That option exists
because some environments require it, and because a user who wants it should not have to
discover a flag.

**Which default?** `periodic` nudges the majority who will otherwise run a year-old scanner;
`off` is the most conservative and the most private. The argument for `periodic` is that a stale
security tool is a real harm and most users never check. The argument for `off` is that this
tool is run on hosts where an outbound connection is itself information. The narrowing in §5 —
interactive scans only, never `check`, never non-interactive, cached for a day — is what makes
`periodic` defensible; without it, `off` would be the only honest default. **Operator's call.**

Whichever it is, the privacy consequence is documented in the README next to the setting rather
than left to be discovered: a version check reveals an IP, a version and a timestamp to GitHub.

## 9. Phasing

| phase | ships | why in this order | state |
|---|---|---|---|
| 0 | `SHA256SUMS` in CI | nothing to verify against today | **done** |
| 1 | minisign signature + rotation list | a checksum an attacker can rewrite is not integrity | **done**, except the key itself: the list is `keys/minisign-trusted.txt`, it is not embedded in the binary because nothing in the binary verifies anything yet, and that happens in phase 3 |
| 2 | `update --check`, config, caching | most of the value, none of the replace risk | |
| 3 | `update` — download, verify, atomic replace | Linux and macOS | |
| 4 | Windows replace-on-restart | the one genuinely different platform | |

Each phase is useful alone, and phase 2 could be where this stops if nobody wants
self-replacement.

## 10. Open questions

- Default for `updates.check`: `periodic` or `off`. §8 has the argument both ways.
- Where the version manifest comes from: the GitHub releases API, or a small static JSON
  published as a release asset. The API is one less thing to publish; the asset does not
  break when an API changes shape and is cacheable.
- Whether `update` should verify the *installed* binary's own hash first, so a tampered local
  binary is noticed rather than silently replaced by a good one — which sounds attractive and
  may be out of scope for an updater.
