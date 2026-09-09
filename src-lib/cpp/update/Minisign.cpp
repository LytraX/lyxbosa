// The verifier. See Minisign.h for the format, which was measured against a real key
// and a real signature rather than taken from documentation.
//
// Everything in this file that is not the two Ed25519 calls is parsing, and the
// parsing is written to refuse: a decoder that is lenient about padding, length or
// alphabet is a decoder that accepts bytes nobody signed.

#include "update/Minisign.h"

#include "update/EmbeddedKeyring.h"

#include <fmt/format.h>

#include <cstring>

#ifdef LYXBOSA_UPDATE_VERIFY
#include <openssl/evp.h>
#endif

namespace lyxbosa::minisign {

namespace {

// Strict base64. Standard alphabet, padding required, and an exact expected size.
//
// "Strict" is the whole point and every relaxation below was considered and refused:
// no whitespace is skipped (a signature line with a space in it is not one), no
// missing padding is tolerated, and the decoded length must be exactly what the caller
// asked for rather than at least it. A decoder that accepts a short field leaves the
// rest of a fixed-size buffer as whatever it was initialised to, and a zero-filled key
// is a key.
bool decodeBase64Exact(std::string_view text, uint8_t* out, size_t expected) {
    static constexpr int kInvalid = -1;
    auto value = [](char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+') return 62;
        if (c == '/') return 63;
        return kInvalid;
    };

    if (text.size() % 4 != 0 || text.empty()) return false;

    // Padding is only legal at the very end, and at most two characters of it.
    size_t padding = 0;
    while (padding < 2 && text.size() > padding && text[text.size() - 1 - padding] == '=') {
        ++padding;
    }
    // And nowhere else: an '=' inside the body is not padding, it is a character
    // outside the alphabet, and a decoder that skipped past it would accept bytes the
    // signer never wrote.
    const size_t firstPad = text.find('=');
    if (padding == 0 ? firstPad != std::string_view::npos
                     : firstPad != text.size() - padding) {
        return false;
    }

    const size_t decoded = text.size() / 4 * 3 - padding;
    if (decoded != expected) return false;

    size_t written = 0;
    for (size_t i = 0; i < text.size(); i += 4) {
        uint32_t group = 0;
        int have = 0;
        for (size_t j = 0; j < 4; ++j) {
            const char c = text[i + j];
            if (c == '=') break;
            const int v = value(c);
            if (v == kInvalid) return false;
            group = (group << 6) | static_cast<uint32_t>(v);
            ++have;
        }
        if (have < 2) return false;                 // a group of one character encodes nothing
        group <<= 6 * (4 - have);
        for (int j = 0; j < have - 1; ++j) {
            if (written >= expected) return false;
            out[written++] = static_cast<uint8_t>((group >> (16 - 8 * j)) & 0xff);
        }
    }
    return written == expected;
}

// Line splitting that does not care which platform wrote the file. A signature fetched
// over HTTP and a signature read from a checkout must parse identically.
std::vector<std::string_view> splitLines(std::string_view text) {
    std::vector<std::string_view> lines;
    size_t start = 0;
    while (start <= text.size()) {
        const size_t nl = text.find('\n', start);
        std::string_view line =
            nl == std::string_view::npos ? text.substr(start) : text.substr(start, nl - start);
        if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
        lines.push_back(line);
        if (nl == std::string_view::npos) break;
        start = nl + 1;
    }
    return lines;
}

std::string_view trim(std::string_view s) {
    const auto isSpace = [](char c) { return c == ' ' || c == '\t'; };
    while (!s.empty() && isSpace(s.front())) s.remove_prefix(1);
    while (!s.empty() && isSpace(s.back())) s.remove_suffix(1);
    return s;
}

VerifyResult refuse(VerifyStatus status, std::string detail) {
    VerifyResult out;
    out.status = status;
    out.detail = std::move(detail);
    return out;
}

#ifdef LYXBOSA_UPDATE_VERIFY

// Ed25519 is one-shot: EVP_DigestVerify with a null digest, no Update calls. Returns
// true only on an explicit success from OpenSSL - every other outcome, including an
// allocation failure, is false, because "could not check" and "checked and it is bad"
// must lead to the same refusal here.
bool ed25519Verify(const std::array<uint8_t, 32>& key, const uint8_t* signature,
                   const uint8_t* message, size_t messageLen) {
    EVP_PKEY* pkey =
        EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, key.data(), key.size());
    if (pkey == nullptr) return false;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (ctx == nullptr) {
        EVP_PKEY_free(pkey);
        return false;
    }

    bool ok = false;
    if (EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, pkey) == 1) {
        ok = EVP_DigestVerify(ctx, signature, 64, message, messageLen) == 1;
    }

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return ok;
}

// BLAKE2b-512 of the whole message, which is what the "ED" algorithm signs.
bool blake2b512(std::string_view data, std::array<uint8_t, 64>& out) {
    unsigned int length = 0;
    if (EVP_Digest(data.data(), data.size(), out.data(), &length, EVP_blake2b512(),
                   nullptr) != 1) {
        return false;
    }
    return length == out.size();
}

#endif  // LYXBOSA_UPDATE_VERIFY

}  // namespace

bool verifierAvailable() {
#ifdef LYXBOSA_UPDATE_VERIFY
    return true;
#else
    return false;
#endif
}

Keyring parseKeyring(std::string_view text) {
    Keyring out;
    size_t lineNumber = 0;
    for (std::string_view raw : splitLines(text)) {
        ++lineNumber;
        const size_t hash = raw.find('#');
        std::string_view line = trim(hash == std::string_view::npos ? raw : raw.substr(0, hash));
        if (line.empty()) continue;

        const size_t space = line.find_first_of(" \t");
        if (space == std::string_view::npos) {
            out.keys.clear();
            out.error = fmt::format("line {}: a record needs a role and a key", lineNumber);
            return out;
        }
        const std::string_view role = line.substr(0, space);
        const std::string_view rest = trim(line.substr(space));
        if (rest.find_first_of(" \t") != std::string_view::npos) {
            out.keys.clear();
            out.error = fmt::format("line {}: a record has a third field", lineNumber);
            return out;
        }
        if (role != "signing" && role != "trusted") {
            out.keys.clear();
            out.error = fmt::format("line {}: unknown role '{}'", lineNumber, role);
            return out;
        }

        // 42 bytes is exactly 56 base64 characters with no padding, which is why the
        // length is asserted before the decode as well as after it: it is the check
        // that produces a sentence about the key rather than about base64.
        if (rest.size() != 56 || rest.substr(0, 2) != "RW") {
            out.keys.clear();
            out.error = fmt::format(
                "line {}: a {}-character field where a 56-character key beginning 'RW' "
                "was expected", lineNumber, rest.size());
            return out;
        }

        std::array<uint8_t, 42> decoded{};
        if (!decodeBase64Exact(rest, decoded.data(), decoded.size())) {
            out.keys.clear();
            out.error = fmt::format("line {}: the key is not 42 bytes of base64", lineNumber);
            return out;
        }
        if (decoded[0] != 'E' || decoded[1] != 'd') {
            out.keys.clear();
            out.error = fmt::format(
                "line {}: the key does not carry minisign's Ed25519 marker", lineNumber);
            return out;
        }

        PublicKey key;
        key.role = std::string(role);
        key.text = std::string(rest);
        std::memcpy(key.keyId.data(), decoded.data() + 2, key.keyId.size());
        std::memcpy(key.key.data(), decoded.data() + 10, key.key.size());
        out.keys.push_back(std::move(key));
    }

    if (out.keys.empty() && out.error.empty()) {
        out.error = "no keys at all";
    }
    return out;
}

const Keyring& embeddedKeyring() {
    static const Keyring parsed = parseKeyring(kEmbeddedKeyringText);
    return parsed;
}

SignatureParse parseSignature(std::string_view text) {
    SignatureParse out;
    const auto lines = splitLines(text);

    // Four lines, in this order. A trailing empty line from the final newline is fine
    // and anything past it is not: a .minisig with a fifth line of content is a file
    // somebody appended to.
    size_t used = lines.size();
    while (used > 0 && lines[used - 1].empty()) --used;
    if (used != 4) {
        out.error = fmt::format("expected 4 lines, found {}", used);
        return out;
    }

    constexpr std::string_view kUntrusted = "untrusted comment: ";
    constexpr std::string_view kTrusted = "trusted comment: ";

    if (lines[0].size() < kUntrusted.size() || lines[0].substr(0, kUntrusted.size()) != kUntrusted) {
        out.error = "the first line is not an untrusted comment";
        return out;
    }
    if (lines[2].size() < kTrusted.size() || lines[2].substr(0, kTrusted.size()) != kTrusted) {
        out.error = "the third line is not a trusted comment";
        return out;
    }

    std::array<uint8_t, 74> sigLine{};
    if (!decodeBase64Exact(lines[1], sigLine.data(), sigLine.size())) {
        out.error = "the signature line is not 74 bytes of base64";
        return out;
    }

    Signature sig;
    if (sigLine[0] == 'E' && sigLine[1] == 'D') {
        sig.prehashed = true;
    } else if (sigLine[0] == 'E' && sigLine[1] == 'd') {
        sig.prehashed = false;
    } else {
        out.error = "the signature does not carry an algorithm this build knows";
        return out;
    }

    std::memcpy(sig.keyId.data(), sigLine.data() + 2, sig.keyId.size());
    std::memcpy(sig.signature.data(), sigLine.data() + 10, sig.signature.size());

    if (!decodeBase64Exact(lines[3], sig.globalSignature.data(), sig.globalSignature.size())) {
        out.error = "the global signature line is not 64 bytes of base64";
        return out;
    }

    sig.untrustedComment = std::string(lines[0].substr(kUntrusted.size()));
    sig.trustedComment = std::string(lines[2].substr(kTrusted.size()));
    out.signature = std::move(sig);
    return out;
}

VerifyResult verifyDetached(std::string_view message, const Signature& signature,
                            const Keyring& keyring) {
#ifndef LYXBOSA_UPDATE_VERIFY
    (void)message;
    (void)signature;
    (void)keyring;
    return refuse(VerifyStatus::NoVerifier,
                  "this build has no signature verifier compiled into it");
#else
    if (!keyring.ok()) {
        return refuse(VerifyStatus::MalformedKeyring,
                      fmt::format("the keys built into this binary did not parse ({})",
                                  keyring.error));
    }

    // By key id, so that the refusal for a key this build has never seen says exactly
    // that rather than "the signature is bad". They are different problems: one is a
    // release signed by a key introduced after this binary was built, and the answer
    // to it is a manual download rather than a retry.
    const PublicKey* key = nullptr;
    for (const auto& candidate : keyring.keys) {
        if (candidate.keyId == signature.keyId) {
            key = &candidate;
            break;
        }
    }
    if (key == nullptr) {
        return refuse(VerifyStatus::UnknownKey,
                      "it is signed by a key this build does not carry");
    }

    // What was signed: the digest for "ED", the file itself for "Ed".
    std::array<uint8_t, 64> digest{};
    const uint8_t* signedBytes = nullptr;
    size_t signedLen = 0;
    if (signature.prehashed) {
        if (!blake2b512(message, digest)) {
            return refuse(VerifyStatus::BadSignature,
                          "the digest of the signed file could not be computed");
        }
        signedBytes = digest.data();
        signedLen = digest.size();
    } else {
        signedBytes = reinterpret_cast<const uint8_t*>(message.data());
        signedLen = message.size();
    }

    if (!ed25519Verify(key->key, signature.signature.data(), signedBytes, signedLen)) {
        return refuse(VerifyStatus::BadSignature,
                      "the signature does not match the file it is supposed to cover");
    }

    // And the global signature, over the 64 signature bytes followed by the trusted
    // comment text. Without this the comment is unauthenticated - an attacker who
    // replays a genuine signature could write any tag they liked above it, and the tag
    // is what says which release the list describes.
    std::string globalMessage;
    globalMessage.reserve(signature.signature.size() + signature.trustedComment.size());
    globalMessage.append(reinterpret_cast<const char*>(signature.signature.data()),
                         signature.signature.size());
    globalMessage.append(signature.trustedComment);

    if (!ed25519Verify(key->key, signature.globalSignature.data(),
                       reinterpret_cast<const uint8_t*>(globalMessage.data()),
                       globalMessage.size())) {
        return refuse(VerifyStatus::BadGlobalSignature,
                      "the trusted comment is not the one that was signed");
    }

    VerifyResult out;
    out.status = VerifyStatus::Ok;
    out.trustedComment = signature.trustedComment;
    out.detail = fmt::format("verified under {}", key->text);
    return out;
#endif
}

bool trustedCommentNamesTag(std::string_view comment, std::string_view tag) {
    if (tag.empty()) return false;
    size_t i = 0;
    while (i < comment.size()) {
        while (i < comment.size() && (comment[i] == ' ' || comment[i] == '\t')) ++i;
        const size_t start = i;
        while (i < comment.size() && comment[i] != ' ' && comment[i] != '\t') ++i;
        if (i > start && comment.substr(start, i - start) == tag) return true;
    }
    return false;
}

}  // namespace lyxbosa::minisign
