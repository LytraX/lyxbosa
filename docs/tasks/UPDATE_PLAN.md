# Updating the binary

A plan, and most of it is now built. **Phases 0 to 3 are built**: a release publishes
`SHA256SUMS` and a signature over it, the binary carries the trusted keys and verifies both
before it will install anything, and `lyxbosa update` downloads, verifies and replaces
itself on Linux. Phase 4 - Windows, where a running `.exe` is locked and the replacement has
to happen on the next start - is what remains. What shipped is described in
[`docs/RELEASING.md`](../RELEASING.md) under *Release integrity* and in the README under
*Updating*.

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
| a development build, reporting `0.0.0` | **never** |

The last row was not in this table when it was written and is in the implementation: a build
that is not from a tag is numerically older than every release, so without it the check tells
every developer, on every scan, that everything is newer than what they are running.

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
```

`--check`'s exit code matters: it makes the command usable from a monitoring script without
parsing output, which is the same discipline the scan exit codes already follow.

`--to VER` was in this list and is not in the command. §10 says why.

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
| 2 | `update --check`, config, caching | most of the value, none of the replace risk | **done**; the version source is the releases API, settled in §10 |
| 3 | `update` — download, verify, atomic replace | Linux | **done**; the keyring is compiled in from `keys/minisign-trusted.txt`, and macOS refuses because a release publishes no asset for it |
| 4 | Windows replace-on-restart | the one genuinely different platform | |

Each phase is useful alone, and phase 2 could be where this stops if nobody wants
self-replacement.

## 10. Open questions

Two of these are settled. What settled them is written down rather than deleted, because the
argument against a choice is what says when to revisit it.

**Default for `updates.check`: settled as `periodic`.** The operator's call, made with the
narrowing in §5 built rather than promised — never from `check`, never under
`--quiet`/`--silent`/`--force`, never without a terminal, never in CI, never on a development
build, and at most once a day otherwise. Without that narrowing `off` would have been the only
honest default. It remains one line to flip: `kDefaultUpdateCheck` in
`src-lib/cpp/config/Rules.h`, which the generated YAML prints rather than repeats, with a test
asserting the two agree.

**Where the version comes from: settled as the GitHub releases API**, not a published
manifest. The manifest is the nicer shape in the abstract — bytes we define, served by the
release CDN, no rate limit — and it lost on three specifics:

- The release job cannot be rehearsed. It is gated on a `v*` tag, and
  `.github/scripts/release-checksums.sh` says at length why that makes any change to it code
  that ships without ever having run. Publishing a manifest means changing that job *and*
  changing `--expect 4`, whose entire design is to stop when the asset set changes. The API
  needs no release change at all.
- A manifest exists for no release already published, so shipping one would leave the check
  inert until the release after next — a feature that looks like it works and does nothing.
- Both of the API's real drawbacks fail in the safe direction. The unauthenticated rate limit
  is 60 requests an hour per address, and being refused means no notice today rather than a
  failed scan; a change in the response shape means the field is not found, which is also no
  notice today. Every other failure path in this design already degrades to silence, so
  neither is new behaviour.

The response is not parsed as JSON. One field is extracted, bounded, from a bounded body, and
validated against a strict version grammar — a general parser over 20 KB of network-supplied
text is a larger thing to have in a scanner that runs as root than the problem justifies.

**Revisit it if a rate-limit refusal is ever actually observed.** It is then a release-job
change with its own `--selftest`, rather than a guess about a limit nobody has hit.

**The transport: settled as linked libcurl**, not a spawned `curl` binary and not a wrapper
over one. The subprocess was tried first and was the wrong trade. It makes the feature depend on a program the host may not
have, so it silently does nothing on some machines and nothing says which — the failure mode
this repository has the least patience for — and it needs a hand-written `CreateProcess` path
on Windows that no CI here compiles.

The dependency is smaller than it sounds, and the parts of it that sounded expensive were
checked rather than assumed:

- `curl` is taken with `default-features: false` and the one feature `ssl`, which drops FTP,
  FTPS, LDAP, SMTP, IMAP, POP3, telnet, dict, gopher, TFTP, RTSP and SMB out of the build.
  `CURLOPT_PROTOCOLS_STR` restates HTTPS-only at runtime, on the first request and on
  anything it redirects to.
- `ssl` is **Schannel on Windows**, which is the OS TLS stack and the OS certificate store —
  no library is built there at all. It is **OpenSSL on Linux and macOS**.
- **No certificate bundle is shipped or embedded** — but the host's own store has to be
  found at run time, and that is not free. curl bakes its CA bundle path in at *configure*
  time, so the AlmaLinux 8 release build carries `/etc/pki/tls/certs/ca-bundle.crt`, and on
  the Debian and Ubuntu hosts this project ships binaries to, that file does not exist.
  Measured on the real release artefact, not reasoned about: `Problem with the SSL CA cert
  (path? access rights?)`. `resolveCaLocation()` probes the standard distribution locations
  at run time and points `CURLOPT_CAINFO`/`CAPATH` at whichever is really there, after
  `SSL_CERT_FILE`, `SSL_CERT_DIR` and `CURL_CA_BUNDLE` get their say. Windows needs none of
  it: Schannel uses the store the OS maintains.

  **This was found only by building the release image and running the artefact.** A local
  build works without the probe, because it is configured and run on the same machine — which
  is exactly the shape of check that passes while being blind.
- Cost, measured cold: OpenSSL 3.6.4 59s, curl 8.21.0 38s. The release triplets are
  release-only, so CI pays half of that once and the binary cache carries it.
- The one real surprise: OpenSSL builds with Perl, and the AlmaLinux 8 release image had
  none. `docker/build/Linux/Dockerfile` now installs `perl` and `perl-IPC-Cmd`, which the
  vcpkg port refuses to proceed without.

`cpr` was raised, built and measured rather than argued about. Its own manifest calls it "a
simple wrapper around libcurl" and its vcpkg dependencies are `curl`, `curl[ssl]` and `openssl`
on Linux, so it changes nothing about the dependency, the TLS stack, the certificate problem
below, or the Perl that OpenSSL builds with — the Dockerfile change is needed either way.

Two things it does change, and both were measured:

| | libcurl multi | cpr |
|---|---|---|
| scan wall time, `api.github.com` blackholed | **0.29s** | **2.04s** |
| whole file, non-comment lines | 226 | 207 |

The delay is the decisive one. cpr can only cancel through libcurl's progress callback, and
that callback is not invoked at all while a connect is stalled, so the scan waits out the full
timeout. `curl_multi_poll` notices the cancel flag in 50 ms because it is a poll loop rather
than a blocking perform. Egress-filtered hosts are not the exceptional case for this tool, they
are a stated target environment, and "it cannot delay output" was a requirement rather than a
preference.

The code saving turned out to be 19 lines, not the rewrite it looks like from the request
function alone: the certificate probe, the version extraction and the error mapping are most of
the file and cpr replaces none of them. **If "cannot delay output" is ever relaxed, cpr is the
better code and the swap is one function.**

**`--to VER`: settled as not shipping, at least not alongside the replace.** Three reasons,
and the first is decisive:

- It is the one option that puts a hole in the downgrade rule by construction. A signed old
  release is still signed, so an attacker who can choose which release you fetch can roll you
  backwards into a known defect without forging anything; refusing to move to an older
  version is the whole defence, and `--to` is a flag that turns it off.
- It needs a second API endpoint, `/releases/tags/<tag>`, that nothing else uses, and the tag
  then comes from the command line rather than from a value this program validated.
- It would ship in the same release that first taught this program to replace itself, which
  is the wrong release in which to make the surface bigger.

**Revisit it when there is a reason to install a specific version** - most likely a bad
release that has to be backed out across a fleet. It is then worth having with output that
says in plain words that it is going backwards and what that means, rather than as a
convenience.

**A correction to the transport section above.** It said the run-time probe applies "after
`SSL_CERT_FILE`, `SSL_CERT_DIR` and `CURL_CA_BUNDLE` get their say", and the implementation
stood aside whenever any of them was set. libcurl reads none of them: `CURL_CA_BUNDLE` is a
compile-time macro inside libcurl and an environment variable only for the curl
command-line tool, and `SSL_CERT_FILE` reaches OpenSSL only through a default-paths fallback
that curl skips once it has a `CAINFO` of its own - which it always has, because it bakes one
in at configure time. So setting one turned the probe OFF and left libcurl using a path from
the machine it was BUILT on: worse than setting nothing at all. The values are now read and
passed to `CURLOPT_CAINFO`/`CAPATH`, kind by kind, so the documented knob is the one that
works. Found by running `docs/local/demo-update-apply.sh` against a local origin, which is
what that script is for.

Still open:

- Whether `update` should verify the *installed* binary's own hash first, so a tampered local
  binary is noticed rather than silently replaced by a good one — which sounds attractive and
  may be out of scope for an updater.
- Whether a release should publish a second detached signature per trusted key, so one
  release can be signed by both keys during a rotation and the frozen-keyring gap closes
  entirely. `keys/minisign-trusted.txt` describes it; phase 3 refuses inside that gap rather
  than closing it.
