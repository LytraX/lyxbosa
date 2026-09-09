#pragma once

// Minisign.h - reading the keyring and checking a minisign signature.
//
// This is the file that decides whether a downloaded binary is allowed to replace the
// one running, so everything about it is written to fail closed: every parse returns a
// reason rather than a bool, every unrecognised byte is a refusal, and the verify
// entry point has no path that returns Ok without an Ed25519 check having succeeded.
//
//
// THE FORMAT, MEASURED RATHER THAN REMEMBERED
// --------------------------------------------
// Taken from a real key and a real signature produced by minisign 0.12, not from
// documentation. A public key is 42 bytes of base64:
//
//     "Ed" | key id (8) | Ed25519 public key (32)
//
// A .minisig file is four lines:
//
//     untrusted comment: <anything>
//     base64 of:  alg (2) | key id (8) | Ed25519 signature (64)
//     trusted comment: <text>
//     base64 of:  Ed25519 global signature (64)
//
// The algorithm bytes say what the first signature is over:
//
//     "ED"   the BLAKE2b-512 digest of the file      (minisign's default since 0.6)
//     "Ed"   the raw file
//
// Both are accepted, because both are what the reference implementation produces and
// refusing one would refuse a legitimate release. Neither is weaker than the other:
// the signature is Ed25519 either way.
//
// The GLOBAL signature is over the 64 signature bytes concatenated with the trusted
// comment text - no "trusted comment: " prefix, and no trailing newline; measured
// both ways against a real signature, and the newline is not included. It is what
// binds the trusted comment to the signature, and skipping it would mean the line a
// person reads - the one naming the release tag - is unauthenticated text an attacker
// can write freely. It is checked here, always, and there is no flag to skip it.
//
//
// WHY THE KEYRING IS EMBEDDED, AND WHAT THAT COSTS
// ------------------------------------------------
// The keys are compiled in from keys/minisign-trusted.txt (see EmbeddedKeyring.h,
// which CMake generates from that file so the two cannot drift). A verifier that read
// its keyring from disk at run time would be a verifier an attacker can edit, which is
// no verifier at all.
//
// The consequence is FROZEN AT BUILD TIME and it is designed for rather than
// discovered: a binary from release N-1 has never seen a key introduced at N, so it
// cannot verify a release signed by it. The correct behaviour then is to REFUSE and
// tell the user to download the release by hand - never to proceed unverified - and
// that is what UpdateApply does with UnknownKey. keys/minisign-trusted.txt describes
// the three-release rotation that keeps the gap from ever opening in normal operation,
// and says that a compromised key gets no overlap at all.

#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace lyxbosa::minisign {

// A key as it appears in keys/minisign-trusted.txt.
struct PublicKey {
    std::string role;                 // "signing" or "trusted"
    std::string text;                 // the 56-character RW... form, for messages
    std::array<uint8_t, 8> keyId{};
    std::array<uint8_t, 32> key{};
};

// The result of reading a keyring. A malformed record is an error rather than a
// skipped line: reading past one means verifying against a keyring that is not the
// one somebody wrote.
struct Keyring {
    std::vector<PublicKey> keys;
    std::string error;                // empty when the whole file parsed
    bool ok() const { return error.empty(); }
};

// Parse a keyring file's text: `<role> <key>` records, `#` comments, blank lines
// ignored. The same grammar .github/scripts/release-sign.sh enforces at signing time.
Keyring parseKeyring(std::string_view text);

// The keys this binary was built with. Parsed once; if the embedded text does not
// parse, the result carries the reason and no keys, and every verification refuses.
const Keyring& embeddedKeyring();

struct Signature {
    bool prehashed = false;           // "ED" over BLAKE2b-512(file), else "Ed" over the file
    std::array<uint8_t, 8> keyId{};
    std::array<uint8_t, 64> signature{};
    std::array<uint8_t, 64> globalSignature{};
    std::string trustedComment;       // exactly the bytes the global signature covers
    std::string untrustedComment;     // NOT covered by anything; never shown as fact
};

struct SignatureParse {
    Signature signature;
    std::string error;                // empty when the file parsed
    bool ok() const { return error.empty(); }
};

// Parse a .minisig file's text.
SignatureParse parseSignature(std::string_view text);

enum class VerifyStatus {
    Ok,
    NoVerifier,           // this build has no Ed25519 - see LYXBOSA_UPDATE_VERIFY
    MalformedKeyring,     // the embedded keys did not parse
    UnknownKey,           // no key in the keyring has the signature's key id
    BadSignature,         // Ed25519 over the message failed
    BadGlobalSignature,   // the trusted comment is not the one that was signed
};

struct VerifyResult {
    VerifyStatus status = VerifyStatus::BadSignature;
    std::string detail;               // one sentence, for someone who typed a command

    // Set only when status is Ok. Deliberately not populated on any other path: a
    // trusted comment that has not been verified is attacker-supplied text, and
    // handing it back beside a failure is how it ends up printed as if it were a fact.
    std::string trustedComment;

    bool ok() const { return status == VerifyStatus::Ok; }
};

// Check `signature` over `message` against `keyring`.
//
// The order is the guard, and it is: find the key by id, verify the signature over the
// message, then verify the global signature over (signature bytes | trusted comment).
// There is no early return that reports Ok, and the trusted comment is not copied out
// until both signatures have passed.
VerifyResult verifyDetached(std::string_view message, const Signature& signature,
                            const Keyring& keyring);

// Whether this build can verify anything at all. False on a platform built without
// OpenSSL - Windows, where curl uses Schannel and no OpenSSL is built (see
// docker/build/Linux/Dockerfile's own note). A build that cannot verify must refuse to
// update, and UpdateApply is what says so.
bool verifierAvailable();

// Does `comment` name `tag` as a whitespace-delimited word?
//
// This is the replay defence, and it is not decoration. docs/RELEASING.md records the
// property it defends against in as many words: a SHA256SUMS and SHA256SUMS.minisig
// pair lifted wholesale from an OLDER release verifies perfectly well and describes the
// wrong binaries. The signature says the list is genuine; only the tag inside the
// trusted comment says WHICH release it is the list for.
//
// A whole word, not a substring: "v2.1.0" must not be found inside "v2.1.0-old", and
// "v2.1" must not match "v2.1.0".
bool trustedCommentNamesTag(std::string_view comment, std::string_view tag);

}  // namespace lyxbosa::minisign
