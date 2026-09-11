// Tests for `lyxbosa update` - download, verify, replace. Nothing here touches a
// network and nothing here writes outside a temporary directory.
//
// THE CONTROLS THAT MATTER ARE THE REFUSALS
// ------------------------------------------
// A successful update is one case. The nine ways it must refuse are the round, and each
// one has to be observed rather than assumed: a bad signature, a good signature by a key
// the build does not carry, a good signature over a mutated list, a signed list for a
// different release, a list that does not name the asset, a hash mismatch, a truncated
// download, a download that never completes, an unwritable target, and a downgrade.
//
// Every one of them asserts the same three things afterwards, because a refusal that
// leaves a half-written file is not a refusal:
//
//   the old binary is byte-for-byte what it was
//   the old binary still runs
//   nothing else is left in the install directory
//
// expectNothingHappened() is that assertion, in one place, so no case can quietly assert
// less than the others.
//
// WHERE THE SIGNATURES COME FROM
// -------------------------------
// Two sources, and both are needed.
//
//   A fixture produced by REAL minisign 0.12, committed as text. Its secret key was
//   destroyed after it was made and its public half is not in keys/minisign-trusted.txt,
//   so it can verify nothing but itself. It is the positive control that this verifier
//   agrees with the reference implementation, which no amount of signing with our own
//   code could establish.
//
//   A key generated inside the test, so the negative cases can be BUILT rather than
//   hand-edited: sign one list and present another, mutate the trusted comment, sign
//   with a second key. Its private half is a seed of 0,1,2..31 - not key material, and
//   deliberately not in minisign's secret-key format, which corpus/pre-push-check.py
//   refuses by shape.
//
// WHAT THE STAND-IN BINARY IS, PER PLATFORM
// ------------------------------------------
// Every case that installs something needs an "old binary" that really runs, because
// the smoke test really executes it and expectNothingHappened() asserts afterwards that
// it still does. On POSIX that is a shell script. On Windows a script is not an
// executable, and the only executable a test can count on finding is itself: the test
// binary answers --version (tests/test_main.cpp), so a copy of it is the old binary and
// the same bytes with a few appended past the last section - which the loader ignores
// and the hash does not - are the new one. oldBinaryBytes() and newBinaryBytes() are
// those two, and the cases never say which platform they are on.
//
// The Windows replace is two moves rather than one rename, and the cases about it are
// Windows-only because they are about what Windows does: a running image can be
// renamed and cannot be deleted, a file something has open without share-delete cannot
// be moved, and a rollback exists because between the two moves there is no binary.
// Each of those is observed on a real filesystem, with a real running process where the
// subject is a running process, and never assumed from documentation.
//
// LYXBOSA_UPDATE_VERIFY guards every case whose subject is a signature, because a build
// with no Ed25519 cannot BUILD one to present. CMakeLists.txt sets it on every platform
// it configures; the #else arms below are what a build without it would owe - that the
// verifier refuses rather than accepts, that the hasher answers nothing rather than
// zero, that the updater refuses before it fetches a byte - so that a suite which
// silently contained nothing could never report no failures and read as green.

#include <gtest/gtest.h>

#include "update/Checksums.h"
#include "update/EmbeddedKeyring.h"
#include "update/InstallPath.h"
#include "update/Minisign.h"
#include "update/ReleaseAssets.h"
#include "update/UpdateApply.h"
#include "update/Version.h"
#include "update/VersionSource.h"

#include "PlatformSkips.h"

#ifdef LYXBOSA_UPDATE_VERIFY
#include <openssl/evp.h>
#endif

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <map>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#include <aclapi.h>
#else
#include <sys/stat.h>
#include <unistd.h>
#endif

using namespace lyxbosa;

namespace {

namespace fs = std::filesystem;

// ---------------------------------------------------------------------------
// Small helpers.
// ---------------------------------------------------------------------------

class TempDir {
public:
    TempDir() {
        const auto tick = std::chrono::steady_clock::now().time_since_epoch().count();
        path_ = fs::temp_directory_path() /
                ("lyxbosa-apply-test-" + std::to_string(tick) + "-" +
                 std::to_string(counter_++));
        fs::create_directories(path_);
    }
    ~TempDir() {
        std::error_code ec;
        // A case that made a directory unwritable has to be able to clean up after
        // itself, and on a machine where the tests do not run as root it cannot until
        // the bits go back.
        fs::permissions(path_, fs::perms::owner_all, fs::perm_options::add, ec);
        fs::remove_all(path_, ec);
    }
    const fs::path& path() const { return path_; }
    fs::path file(const std::string& name) const { return path_ / name; }

private:
    fs::path path_;
    static inline int counter_ = 0;
};

void writeFile(const fs::path& path, std::string_view content) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out.write(content.data(), static_cast<std::streamsize>(content.size()));
}

std::string readFile(const fs::path& path) {
    std::ifstream in(path, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

std::string executableText(std::string_view says) {
    return std::string("#!/bin/sh\necho ") + std::string(says) + "\n";
}

#ifndef _WIN32
// A stand-in for an installed binary: a script that runs and prints something. It has
// to be a real executable, because the smoke test really execs it.
void writeExecutable(const fs::path& path, std::string_view says, uint32_t mode = 0755) {
    writeFile(path, executableText(says));
    ::chmod(path.string().c_str(), static_cast<mode_t>(mode));
}
#endif

// The installed binary's name, the mode it is installed with, and two sets of bytes
// that both really run on this host - see the top of this file for why they are what
// they are on each platform.
#ifdef _WIN32
constexpr const char* kTargetName = "lyxbosa.exe";
constexpr uint32_t kInstalledMode = 0;
#else
constexpr const char* kTargetName = "lyxbosa";
constexpr uint32_t kInstalledMode = 0755;
#endif

const std::string& oldBinaryBytes() {
#ifdef _WIN32
    static const std::string bytes = readFile(runningExecutablePath());
#else
    static const std::string bytes = executableText("old");
#endif
    return bytes;
}

const std::string& newBinaryBytes() {
#ifdef _WIN32
    // Past the last section, so the loader never maps it and the file still runs;
    // different bytes, so the hash and the byte comparison both tell the two apart.
    static const std::string bytes = oldBinaryBytes() + "\r\n[lyxbosa test: new]\r\n";
#else
    static const std::string bytes = executableText("new");
#endif
    return bytes;
}

void installBinary(const fs::path& path, const std::string& bytes) {
    writeFile(path, bytes);
#ifndef _WIN32
    ::chmod(path.string().c_str(), 0755);
#endif
}

#ifdef _WIN32

// A handle that shares reads and writes and NOT deletion, which is how a real-time
// scanner holds a file it is looking at and exactly what makes a rename of that file
// fail with a sharing violation - a rename needs DELETE access to the file, and nothing
// else about it is refused. Closed on destruction or on demand.
class OpenWithoutShareDelete {
public:
    explicit OpenWithoutShareDelete(const fs::path& path)
        : handle_(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                              nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr)) {}
    ~OpenWithoutShareDelete() { close(); }
    OpenWithoutShareDelete(const OpenWithoutShareDelete&) = delete;
    OpenWithoutShareDelete& operator=(const OpenWithoutShareDelete&) = delete;

    bool ok() const { return handle_ != INVALID_HANDLE_VALUE; }
    void close() {
        if (handle_ != INVALID_HANDLE_VALUE) {
            CloseHandle(handle_);
            handle_ = INVALID_HANDLE_VALUE;
        }
    }

private:
    HANDLE handle_;
};

// A process running from `image` - a copy of this test binary - which tests/test_main.cpp
// keeps alive until `stopFile` appears. While it runs, `image` is a mapped executable
// exactly the way an installed lyxbosa.exe is while `lyxbosa update` runs from it.
class RunningImage {
public:
    RunningImage(const fs::path& image, fs::path stopFile) : stopFile_(std::move(stopFile)) {
        std::wstring commandLine =
            L"\"" + image.wstring() + L"\" --hold-open \"" + stopFile_.wstring() + L"\"";
        STARTUPINFOW startup{};
        startup.cb = sizeof(startup);
        PROCESS_INFORMATION process{};
        if (CreateProcessW(image.c_str(), commandLine.data(), nullptr, nullptr, FALSE,
                           CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process)) {
            CloseHandle(process.hThread);
            process_ = process.hProcess;
        }
    }
    ~RunningImage() { stop(); }
    RunningImage(const RunningImage&) = delete;
    RunningImage& operator=(const RunningImage&) = delete;

    bool running() const { return process_ != nullptr; }

    // Tell the child to exit and wait until it has. The image stops being mapped only
    // once the process is gone, which is why this waits rather than returns.
    void stop() {
        if (process_ == nullptr) return;
        writeFile(stopFile_, "stop");
        if (WaitForSingleObject(process_, 30 * 1000) != WAIT_OBJECT_0) {
            TerminateProcess(process_, 1);
            WaitForSingleObject(process_, 5 * 1000);
        }
        CloseHandle(process_);
        process_ = nullptr;
    }

private:
    fs::path stopFile_;
    HANDLE process_ = nullptr;
};

// The Mark of the Web is a Zone.Identifier alternate data stream, and this is the whole
// of how it is read and written: a browser attaches one to what it downloads, and
// SmartScreen consults it when the file is launched.
bool hasZoneIdentifier(const fs::path& path) {
    const std::wstring stream = path.wstring() + L":Zone.Identifier";
    const HANDLE handle = CreateFileW(stream.c_str(), GENERIC_READ,
                                      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                      nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle == INVALID_HANDLE_VALUE) return false;
    CloseHandle(handle);
    return true;
}

bool writeZoneIdentifier(const fs::path& path) {
    const std::wstring stream = path.wstring() + L":Zone.Identifier";
    const HANDLE handle = CreateFileW(stream.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                                      FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle == INVALID_HANDLE_VALUE) return false;
    const char body[] = "[ZoneTransfer]\r\nZoneId=3\r\n";
    DWORD written = 0;
    const bool ok = WriteFile(handle, body, static_cast<DWORD>(sizeof(body) - 1), &written,
                              nullptr) &&
                    written == sizeof(body) - 1;
    CloseHandle(handle);
    return ok;
}

// Deny this user the right to create files in `directory`, by an explicit deny entry in
// its DACL for this process's own SID. A deny entry is honoured ahead of every allow,
// an administrator's included, which is what makes the case observable on a CI runner
// that runs elevated - and is also exactly the shape of a directory under Program Files
// seen from a process that is not elevated. PlatformSkips.h is right that
// std::filesystem::permissions cannot do this; the security API can.
bool denyAddingFilesTo(const fs::path& directory) {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
    DWORD size = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &size);
    std::vector<char> user(size);
    const BOOL haveUser = GetTokenInformation(token, TokenUser, user.data(), size, &size);
    CloseHandle(token);
    if (!haveUser) return false;

    std::wstring name = directory.wstring();
    PACL oldDacl = nullptr;
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (GetNamedSecurityInfoW(name.c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, nullptr,
                              nullptr, &oldDacl, nullptr, &descriptor) != ERROR_SUCCESS) {
        return false;
    }

    EXPLICIT_ACCESS_W deny{};
    deny.grfAccessPermissions = FILE_ADD_FILE;
    deny.grfAccessMode = DENY_ACCESS;
    deny.grfInheritance = NO_INHERITANCE;
    deny.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    deny.Trustee.TrusteeType = TRUSTEE_IS_USER;
    deny.Trustee.ptstrName =
        reinterpret_cast<LPWSTR>(reinterpret_cast<TOKEN_USER*>(user.data())->User.Sid);

    PACL newDacl = nullptr;
    bool ok = false;
    if (SetEntriesInAclW(1, &deny, oldDacl, &newDacl) == ERROR_SUCCESS) {
        ok = SetNamedSecurityInfoW(name.data(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
                                   nullptr, nullptr, newDacl, nullptr) == ERROR_SUCCESS;
        LocalFree(newDacl);
    }
    LocalFree(descriptor);
    return ok;
}

// Reap, and keep trying for a moment. A moved-aside copy that nothing runs is deleted
// on the first attempt everywhere this suite has run; the retry is for a host whose
// real-time scanner opens the file first, which a single attempt would report as the
// replace having left something behind when it had not.
bool reapedWithin(const fs::path& target, std::chrono::milliseconds patience) {
    const auto deadline = std::chrono::steady_clock::now() + patience;
    for (;;) {
        if (reapMovedAsideBinary(target)) return true;
        if (std::chrono::steady_clock::now() >= deadline) return false;
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
}

#endif  // _WIN32

std::vector<std::string> namesIn(const fs::path& directory) {
    std::vector<std::string> names;
    std::error_code ec;
    for (const auto& entry : fs::directory_iterator(directory, ec)) {
        names.push_back(entry.path().filename().string());
    }
    std::sort(names.begin(), names.end());
    return names;
}

// ---------------------------------------------------------------------------
// Signing, inside the test. Needs Ed25519, so a build without a verifier has no way
// to construct any of the material the cases below present.
// ---------------------------------------------------------------------------

#ifdef LYXBOSA_UPDATE_VERIFY

std::string base64Encode(const std::vector<uint8_t>& bytes) {
    static constexpr char kAlphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    for (size_t i = 0; i < bytes.size(); i += 3) {
        const size_t have = std::min<size_t>(3, bytes.size() - i);
        uint32_t group = 0;
        for (size_t j = 0; j < 3; ++j) {
            group = (group << 8) | (j < have ? bytes[i + j] : 0);
        }
        for (size_t j = 0; j < 4; ++j) {
            if (j <= have) {
                out.push_back(kAlphabet[(group >> (18 - 6 * j)) & 0x3f]);
            } else {
                out.push_back('=');
            }
        }
    }
    return out;
}

// An Ed25519 key made from a seed the test chooses, so every signature below is
// reproducible and no key material is stored anywhere.
class TestKey {
public:
    explicit TestKey(uint8_t first) {
        std::array<uint8_t, 32> seed{};
        for (size_t i = 0; i < seed.size(); ++i) {
            seed[i] = static_cast<uint8_t>(first + i);
        }
        pkey_ = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, seed.data(),
                                             seed.size());
        size_t length = publicKey_.size();
        EVP_PKEY_get_raw_public_key(pkey_, publicKey_.data(), &length);
        for (size_t i = 0; i < keyId_.size(); ++i) {
            keyId_[i] = static_cast<uint8_t>(0xA0 + first + i);
        }
    }
    ~TestKey() { EVP_PKEY_free(pkey_); }
    TestKey(const TestKey&) = delete;
    TestKey& operator=(const TestKey&) = delete;

    // The 56-character `RW...` form that goes in a keyring file.
    std::string keyringText() const {
        std::vector<uint8_t> raw{'E', 'd'};
        raw.insert(raw.end(), keyId_.begin(), keyId_.end());
        raw.insert(raw.end(), publicKey_.begin(), publicKey_.end());
        return base64Encode(raw);
    }

    std::vector<uint8_t> sign(const std::string& message) const {
        std::vector<uint8_t> signature(64);
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, pkey_);
        size_t length = signature.size();
        EVP_DigestSign(ctx, signature.data(), &length,
                       reinterpret_cast<const uint8_t*>(message.data()), message.size());
        EVP_MD_CTX_free(ctx);
        signature.resize(length);
        return signature;
    }

    const std::array<uint8_t, 8>& keyId() const { return keyId_; }

private:
    EVP_PKEY* pkey_ = nullptr;
    std::array<uint8_t, 32> publicKey_{};
    std::array<uint8_t, 8> keyId_{};
};

std::string blake2b512(const std::string& message) {
    std::string out(64, '\0');
    unsigned int length = 0;
    EVP_Digest(message.data(), message.size(), reinterpret_cast<unsigned char*>(out.data()),
               &length, EVP_blake2b512(), nullptr);
    return out;
}

// A .minisig, built the way minisign builds one. `listOverride` is what makes the
// negative cases possible: sign one thing and hand the verifier another.
std::string makeSignature(const TestKey& key, const std::string& signedContent,
                          const std::string& trustedComment) {
    const std::vector<uint8_t> signature = key.sign(blake2b512(signedContent));

    std::vector<uint8_t> sigLine{'E', 'D'};
    sigLine.insert(sigLine.end(), key.keyId().begin(), key.keyId().end());
    sigLine.insert(sigLine.end(), signature.begin(), signature.end());

    std::string globalMessage(reinterpret_cast<const char*>(signature.data()),
                              signature.size());
    globalMessage += trustedComment;
    const std::vector<uint8_t> globalSignature = key.sign(globalMessage);

    return "untrusted comment: a test signature\n" + base64Encode(sigLine) + "\n" +
           "trusted comment: " + trustedComment + "\n" + base64Encode(globalSignature) + "\n";
}

minisign::Keyring keyringOf(const TestKey& key) {
    return minisign::parseKeyring("signing  " + key.keyringText() + "\n");
}

#endif  // LYXBOSA_UPDATE_VERIFY

// ---------------------------------------------------------------------------
// A real minisign 0.12 fixture. Its secret key was destroyed after it was made.
// ---------------------------------------------------------------------------

constexpr const char* kRealPublicKey =
    "RWTo7/SlSR3/ECPYhgrpRrejkUxpLzSAAKRm5FFzXWxUkDbM6jD+c72g";

constexpr const char* kRealChecksumList =
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  lyxbosa-linux-amd64\n"
    "c865f6c5ab8d1b0bcd383a5e1e3879d22681c96bf462c269b7581d523fbe70ab  lyxbosa-linux-arm64\n"
    "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb  lyxbosa-windows-amd64.exe\n"
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  lyxbosa-windows-arm64.exe\n";

// A second key, for the one case about a keyring holding more than one. Shape only:
// 56 characters beginning RW, decoding to 42 bytes that carry minisign's "Ed" marker,
// which is everything parseKeyring checks. Nothing ever verifies with it. A literal
// rather than a generated key, because generating one needs Ed25519 and this case is
// about the parser - which is also why it now builds on a platform that has none.
constexpr const char* kSecondPublicKey =
    "RWQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

constexpr const char* kRealSignature =
    "untrusted comment: verify with: minisign -Vm SHA256SUMS -P <key from "
    "keys/minisign-trusted.txt>\n"
    "RUTo7/SlSR3/EPIy2UUmJ5Y5ihEQa7tIGkik42Il0h6htTBuTogV9nSoLUUS4LkXbnWYXnUTzYSBFuLT0mW"
    "L/BHVWVIwmn2AnQY=\n"
    "trusted comment: LyxBoSa v2.3.0 SHA256SUMS (LytraX/LyxBoSa)\n"
    "W1YDK0Z3MjNLajyHeWqAMDgOMHSDLO0gt2zN3+oGUn0J9uy28MIbSRfF6q2TPsrs4ratRolrmqyht8YESnf"
    "PDg==\n";

// ---------------------------------------------------------------------------
// The seams.
// ---------------------------------------------------------------------------

class FakeVersionSource : public VersionSource {
public:
    explicit FakeVersionSource(std::string tag) : tag_(std::move(tag)) {}

    FetchOutcome fetchLatest(std::chrono::milliseconds, const std::atomic<bool>&) override {
        calls.fetch_add(1, std::memory_order_relaxed);
        FetchOutcome out;
        if (tag_.empty()) {
            out.status = FetchOutcome::Status::RequestFailed;
            out.detail = "no route to host";
            return out;
        }
        out.status = FetchOutcome::Status::Ok;
        out.version = tag_;
        return out;
    }

    std::atomic<int> calls{0};

private:
    std::string tag_;
};

// A release, served from memory. Every asset can be told to fail in one specific way,
// which is how each refusal below gets exactly one thing wrong.
class FakeAssetSource : public AssetSource {
public:
    struct Entry {
        std::string body;
        http::Outcome::Status status = http::Outcome::Status::Ok;

        // Bytes to write before reporting `status`. The interesting case is a transport
        // that writes a short file and reports success anyway - which is what makes the
        // hash check, rather than the transport's honesty, the thing being tested.
        std::optional<size_t> writeOnly;
    };

    std::map<std::string, Entry> entries;
    std::vector<std::string> fetched;

    http::Outcome fetch(std::string_view tag, std::string_view assetName,
                        const fs::path& destination, uint64_t maxBytes) override {
        fetched.push_back(std::string(tag) + "/" + std::string(assetName));

        const auto it = entries.find(std::string(assetName));
        http::Outcome outcome;
        if (it == entries.end()) {
            outcome.status = http::Outcome::Status::HttpError;
            outcome.httpStatus = 404;
            outcome.detail = "the server answered HTTP 404";
            std::error_code ec;
            fs::remove(destination, ec);
            return outcome;
        }

        const Entry& entry = it->second;
        std::string body = entry.body;
        if (entry.writeOnly) body = body.substr(0, std::min(*entry.writeOnly, body.size()));

        if (body.size() > maxBytes) {
            outcome.status = http::Outcome::Status::TooLarge;
            outcome.detail = "it is larger than this is willing to read";
            std::error_code ec;
            fs::remove(destination, ec);
            return outcome;
        }

        writeFile(destination, body);
        outcome.bytes = body.size();
        outcome.status = entry.status;
        if (entry.status != http::Outcome::Status::Ok) {
            // The real transport leaves nothing behind on failure, and a fake that did
            // otherwise would let a bug in the caller pass unnoticed.
            std::error_code ec;
            fs::remove(destination, ec);
            switch (entry.status) {
                case http::Outcome::Status::Truncated:
                    outcome.detail = "the transfer ended early";
                    break;
                case http::Outcome::Status::TimedOut:
                    outcome.detail = "the transfer stopped making progress";
                    break;
                default:
                    outcome.detail = "it did not arrive";
                    break;
            }
        }
        return outcome;
    }
};

// ---------------------------------------------------------------------------
// A whole release, and the one thing each case spoils. Needs the verifier to sign
// with and to hash with.
// ---------------------------------------------------------------------------

#ifdef LYXBOSA_UPDATE_VERIFY

std::string sha256Hex(const std::string& content) {
    TempDir dir;
    const auto path = dir.file("blob");
    writeFile(path, content);
    return sha256File(path).value_or("");
}

struct Release {
    std::string tag = "v2.3.0";
    std::string assetBody = newBinaryBytes();
    std::string list;
    std::string signature;
    std::string trustedComment;
};

// A release that is entirely correct, which every case below then breaks in one place.
Release goodRelease(const TestKey& key, const std::string& tag = "v2.3.0") {
    Release release;
    release.tag = tag;
    release.assetBody = newBinaryBytes();
    release.list = sha256Hex(release.assetBody) + "  " + std::string(platformAssetName()) +
                   "\n" +
                   "0000000000000000000000000000000000000000000000000000000000000000  "
                   "lyxbosa-somewhere-else\n";
    release.trustedComment = "LyxBoSa " + tag + " SHA256SUMS (LytraX/LyxBoSa)";
    release.signature = makeSignature(key, release.list, release.trustedComment);
    return release;
}

void serve(FakeAssetSource& assets, const Release& release) {
    assets.entries[std::string(kChecksumListName)] = {release.list, http::Outcome::Status::Ok, {}};
    assets.entries[std::string(kChecksumSignatureName)] = {release.signature,
                                                          http::Outcome::Status::Ok, {}};
    assets.entries[std::string(platformAssetName())] = {release.assetBody,
                                                       http::Outcome::Status::Ok, {}};
}

struct Fixture {
    TempDir dir;
    fs::path target;
    std::string oldBinary = oldBinaryBytes();

    Fixture() {
        target = dir.file(kTargetName);
        installBinary(target, oldBinary);
    }

    ApplyOptions options(const minisign::Keyring& keyring, Version running = Version{2, 2, 1}) {
        ApplyOptions options;
        options.target = target;
        options.running = running;
        options.assumeYes = true;
        options.keyring = &keyring;
        options.statePath = dir.file("state");
        options.now = [] { return uint64_t{1'757'000'000}; };
        return options;
    }

    // The three assertions every refusal owes. Written once so no case can assert less.
    void expectNothingHappened() const {
        EXPECT_EQ(readFile(target), oldBinary) << "the old binary was modified";
        EXPECT_TRUE(stagedBinaryRuns(target)) << "the old binary no longer runs";
        // The state file is the only other thing a run is allowed to leave here.
        std::vector<std::string> allowed{kTargetName, "state"};
        auto found = namesIn(dir.path());
        for (const auto& name : found) {
            EXPECT_NE(std::find(allowed.begin(), allowed.end(), name), allowed.end())
                << "a refusal left " << name << " behind";
        }
    }
};

#endif  // LYXBOSA_UPDATE_VERIFY

}  // namespace

// ===========================================================================
// The keyring, both directions.
// ===========================================================================

TEST(KeyringTest, ReadsRoleAndKey) {
    const auto keyring = minisign::parseKeyring(
        std::string("# a comment\n\n  signing  ") + kRealPublicKey + "   # in use\n");
    ASSERT_TRUE(keyring.ok()) << keyring.error;
    ASSERT_EQ(keyring.keys.size(), 1u);
    EXPECT_EQ(keyring.keys[0].role, "signing");
    EXPECT_EQ(keyring.keys[0].text, kRealPublicKey);
}

TEST(KeyringTest, ReadsMoreThanOneKeyForRotation) {
    const auto keyring = minisign::parseKeyring(
        std::string("signing ") + kRealPublicKey + "\ntrusted " + kSecondPublicKey + "\n");
    ASSERT_TRUE(keyring.ok()) << keyring.error;
    ASSERT_EQ(keyring.keys.size(), 2u);
    EXPECT_EQ(keyring.keys[0].role, "signing");
    EXPECT_EQ(keyring.keys[1].role, "trusted");
    EXPECT_EQ(keyring.keys[1].text, kSecondPublicKey);
}

TEST(KeyringTest, RefusesEverythingMalformed) {
    const std::string key = kRealPublicKey;
    // A malformed record is an error and NOT a skipped line. Skipping is how a keyring
    // that is not the one somebody wrote reads as a keyring with fewer keys in it.
    EXPECT_FALSE(minisign::parseKeyring("signing").ok());                  // no key
    EXPECT_FALSE(minisign::parseKeyring("retired " + key).ok());           // unknown role
    EXPECT_FALSE(minisign::parseKeyring("signing " + key + " extra").ok());  // third field
    EXPECT_FALSE(minisign::parseKeyring("signing " + key.substr(0, 55)).ok());
    EXPECT_FALSE(minisign::parseKeyring("signing " + key + "A").ok());
    EXPECT_FALSE(minisign::parseKeyring("signing AB" + key.substr(2)).ok());  // not RW
    EXPECT_FALSE(minisign::parseKeyring("signing RW" + std::string(54, '!')).ok());
    EXPECT_FALSE(minisign::parseKeyring("").ok());                         // no keys at all
    EXPECT_FALSE(minisign::parseKeyring("# only a comment\n").ok());
}

TEST(KeyringTest, ARefusedKeyringYieldsNoKeysAtAll) {
    // Not merely an error alongside whatever parsed: a caller that read `keys` and
    // ignored `error` must not be handed a partial keyring.
    const auto keyring =
        minisign::parseKeyring(std::string("signing ") + kRealPublicKey + "\nnonsense\n");
    EXPECT_FALSE(keyring.ok());
    EXPECT_TRUE(keyring.keys.empty());
}

// ===========================================================================
// The keyring this binary actually ships with.
// ===========================================================================

TEST(EmbeddedKeyringTest, IsByteForByteTheFileInTheRepository) {
    // The generated header and keys/minisign-trusted.txt cannot drift, because CMake
    // writes one from the other. This is the control that says so out loud - and it is
    // the one that would fire if the generation were ever replaced by a hand-copied
    // list, which is how every stale copy in this repository has started.
    std::ifstream in(LYXBOSA_KEYRING_FILE_PATH, std::ios::binary);
    ASSERT_TRUE(in) << "no keyring at " << LYXBOSA_KEYRING_FILE_PATH;
    const std::string onDisk((std::istreambuf_iterator<char>(in)),
                             std::istreambuf_iterator<char>());
    EXPECT_EQ(onDisk, std::string(minisign::kEmbeddedKeyringText));
}

TEST(EmbeddedKeyringTest, ParsesAndCarriesExactlyOneSigningKey) {
    const auto& keyring = minisign::embeddedKeyring();
    ASSERT_TRUE(keyring.ok()) << keyring.error;
    ASSERT_FALSE(keyring.keys.empty());

    int signing = 0;
    for (const auto& key : keyring.keys) {
        if (key.role == "signing") ++signing;
    }
    // .github/scripts/release-sign.sh refuses a release with zero or two signing keys;
    // this is the same assertion on the consuming side, so a keyring that would fail the
    // release job fails the build's tests first.
    EXPECT_EQ(signing, 1);
}

// ===========================================================================
// A signature made by real minisign 0.12, then the parser, then the global
// signature. Every case needs Ed25519 - to verify with, or to build the material it
// presents - so the whole run of them is one region, and the #else below is what a
// build without a verifier owes instead.
// ===========================================================================

#ifdef LYXBOSA_UPDATE_VERIFY

TEST(MinisignFixtureTest, VerifiesWhatTheReferenceImplementationProduced) {
    const auto keyring = minisign::parseKeyring(std::string("signing ") + kRealPublicKey);
    ASSERT_TRUE(keyring.ok()) << keyring.error;

    const auto parsed = minisign::parseSignature(kRealSignature);
    ASSERT_TRUE(parsed.ok()) << parsed.error;
    EXPECT_TRUE(parsed.signature.prehashed) << "minisign's default is ED, over a digest";

    const auto verified =
        minisign::verifyDetached(kRealChecksumList, parsed.signature, keyring);
    EXPECT_EQ(verified.status, minisign::VerifyStatus::Ok) << verified.detail;
    EXPECT_EQ(verified.trustedComment, "LyxBoSa v2.3.0 SHA256SUMS (LytraX/LyxBoSa)");
}

TEST(MinisignFixtureTest, RefusesTheSameListWithOneByteChanged) {
    // The other direction, on the fixture. Without it the case above would pass just as
    // happily against a verifier that returned Ok unconditionally - the shape AGENTS.md
    // records as a status check reading a 404 body as success.
    const auto keyring = minisign::parseKeyring(std::string("signing ") + kRealPublicKey);
    const auto parsed = minisign::parseSignature(kRealSignature);
    ASSERT_TRUE(parsed.ok());

    std::string mutated = kRealChecksumList;
    mutated[7] = mutated[7] == 'f' ? 'e' : 'f';
    const auto verified = minisign::verifyDetached(mutated, parsed.signature, keyring);
    EXPECT_EQ(verified.status, minisign::VerifyStatus::BadSignature);
    EXPECT_TRUE(verified.trustedComment.empty())
        << "a comment that did not verify must not be handed back";
}

TEST(MinisignFixtureTest, RefusesAKeyItWasNotSignedBy) {
    TestKey other(7);
    const auto keyring = keyringOf(other);
    const auto parsed = minisign::parseSignature(kRealSignature);
    ASSERT_TRUE(parsed.ok());

    const auto verified = minisign::verifyDetached(kRealChecksumList, parsed.signature, keyring);
    EXPECT_EQ(verified.status, minisign::VerifyStatus::UnknownKey);
}

TEST(MinisignFixtureTest, RefusesAMalformedKeyring) {
    const auto keyring = minisign::parseKeyring("nonsense");
    ASSERT_FALSE(keyring.ok());
    const auto parsed = minisign::parseSignature(kRealSignature);
    const auto verified = minisign::verifyDetached(kRealChecksumList, parsed.signature, keyring);
    EXPECT_EQ(verified.status, minisign::VerifyStatus::MalformedKeyring);
}

// ===========================================================================
// Parsing a signature file.
// ===========================================================================

TEST(SignatureParseTest, ReadsBothAlgorithms) {
    TestKey key(1);
    const auto ed = minisign::parseSignature(makeSignature(key, "hello", "a comment"));
    ASSERT_TRUE(ed.ok()) << ed.error;
    EXPECT_TRUE(ed.signature.prehashed);
    EXPECT_EQ(ed.signature.trustedComment, "a comment");
    EXPECT_EQ(ed.signature.untrustedComment, "a test signature");
}

TEST(SignatureParseTest, RefusesEverythingThatIsNotOne) {
    TestKey key(1);
    const std::string good = makeSignature(key, "hello", "a comment");

    EXPECT_FALSE(minisign::parseSignature("").ok());
    EXPECT_FALSE(minisign::parseSignature("only one line\n").ok());
    EXPECT_FALSE(minisign::parseSignature(good + "a fifth line\n").ok());

    // Line by line, so that each of the four has its own way of being wrong.
    std::vector<std::string> lines;
    for (size_t start = 0; start < good.size();) {
        const size_t nl = good.find('\n', start);
        lines.push_back(good.substr(start, nl - start));
        start = nl + 1;
    }
    ASSERT_EQ(lines.size(), 4u);

    auto rebuild = [&lines](int index, const std::string& replacement) {
        std::string out;
        for (size_t i = 0; i < lines.size(); ++i) {
            out += (static_cast<int>(i) == index ? replacement : lines[i]);
            out += "\n";
        }
        return out;
    };

    EXPECT_FALSE(minisign::parseSignature(rebuild(0, "comment: no")).ok());
    EXPECT_FALSE(minisign::parseSignature(rebuild(1, "not base64!")).ok());
    EXPECT_FALSE(minisign::parseSignature(rebuild(1, lines[1].substr(0, 96) + "A===")).ok());
    EXPECT_FALSE(minisign::parseSignature(rebuild(2, "untrusted comment: no")).ok());
    EXPECT_FALSE(minisign::parseSignature(rebuild(3, "AAAA")).ok());

    // An algorithm nobody knows, made by rewriting the two marker bytes. "Ed" and "ED"
    // are the only two, and a third must not be treated as one of them.
    std::string wrongAlgorithm = lines[1];
    wrongAlgorithm[0] = 'X';
    EXPECT_FALSE(minisign::parseSignature(rebuild(1, wrongAlgorithm)).ok());
}

TEST(SignatureParseTest, ToleratesCarriageReturnsAndATrailingNewline) {
    TestKey key(1);
    std::string good = makeSignature(key, "hello", "a comment");
    std::string crlf;
    for (const char c : good) {
        if (c == '\n') crlf += '\r';
        crlf += c;
    }
    EXPECT_TRUE(minisign::parseSignature(crlf).ok());
    EXPECT_TRUE(minisign::parseSignature(good + "\n").ok());
}

// ===========================================================================
// The global signature, which is what makes the trusted comment worth reading.
// ===========================================================================

TEST(GlobalSignatureTest, RefusesAnEditedTrustedComment) {
    TestKey key(1);
    const std::string list = "abc  lyxbosa-linux-amd64\n";
    const std::string good = makeSignature(key, list, "LyxBoSa v2.3.0 SHA256SUMS");

    // The comment rewritten, the two signatures left as they were - which is exactly
    // what an attacker replaying a genuine signature would do. Without the global
    // signature check this would verify, and the tag a person reads would be theirs.
    std::string tampered = good;
    const size_t at = tampered.find("v2.3.0");
    ASSERT_NE(at, std::string::npos);
    tampered.replace(at, 6, "v9.9.9");

    const auto parsed = minisign::parseSignature(tampered);
    ASSERT_TRUE(parsed.ok());
    const auto verified = minisign::verifyDetached(list, parsed.signature, keyringOf(key));
    EXPECT_EQ(verified.status, minisign::VerifyStatus::BadGlobalSignature);
}

TEST(GlobalSignatureTest, AcceptsTheCommentThatWasSigned) {
    TestKey key(1);
    const std::string list = "abc  lyxbosa-linux-amd64\n";
    const auto parsed =
        minisign::parseSignature(makeSignature(key, list, "LyxBoSa v2.3.0 SHA256SUMS"));
    ASSERT_TRUE(parsed.ok());
    const auto verified = minisign::verifyDetached(list, parsed.signature, keyringOf(key));
    EXPECT_EQ(verified.status, minisign::VerifyStatus::Ok) << verified.detail;
}

#else  // LYXBOSA_UPDATE_VERIFY

// What this build owes in place of everything above. The point is not that the cases
// are absent - it is that "no verifier" must mean REFUSE and never "nothing checked it,
// so it must be fine". The fixture is a real minisign 0.12 signature over a real list
// by the matching key, so it is the strongest input available: if anything were going
// to be waved through here, this would be it.
TEST(MinisignFixtureTest, ABuildWithNoVerifierRefusesTheSignatureItCannotCheck) {
    EXPECT_FALSE(minisign::verifierAvailable());

    // Parsing is not verification and stays compiled in, so the refusal below is about
    // the signature rather than about failing to read the file.
    const auto keyring = minisign::parseKeyring(std::string("signing ") + kRealPublicKey);
    ASSERT_TRUE(keyring.ok()) << keyring.error;
    const auto parsed = minisign::parseSignature(kRealSignature);
    ASSERT_TRUE(parsed.ok()) << parsed.error;
    EXPECT_TRUE(parsed.signature.prehashed);

    const auto verified =
        minisign::verifyDetached(kRealChecksumList, parsed.signature, keyring);
    EXPECT_EQ(verified.status, minisign::VerifyStatus::NoVerifier);
    EXPECT_TRUE(verified.trustedComment.empty())
        << "a comment that was never verified must not be handed back";
}

#endif  // LYXBOSA_UPDATE_VERIFY

TEST(TrustedCommentTest, MatchesAWholeWordAndNotASubstring) {
    EXPECT_TRUE(minisign::trustedCommentNamesTag("LyxBoSa v2.3.0 SHA256SUMS", "v2.3.0"));
    EXPECT_TRUE(minisign::trustedCommentNamesTag("v2.3.0", "v2.3.0"));
    EXPECT_TRUE(minisign::trustedCommentNamesTag("  a  v2.3.0  b ", "v2.3.0"));

    EXPECT_FALSE(minisign::trustedCommentNamesTag("LyxBoSa v2.3.0-old SUMS", "v2.3.0"));
    EXPECT_FALSE(minisign::trustedCommentNamesTag("LyxBoSa v2.3.01 SUMS", "v2.3.0"));
    EXPECT_FALSE(minisign::trustedCommentNamesTag("LyxBoSa v2.3.0 SUMS", "v2.3"));
    EXPECT_FALSE(minisign::trustedCommentNamesTag("LyxBoSa v2.2.0 SUMS", "v2.3.0"));
    EXPECT_FALSE(minisign::trustedCommentNamesTag("", "v2.3.0"));
    EXPECT_FALSE(minisign::trustedCommentNamesTag("anything", ""));
}

// ===========================================================================
// The checksum list.
// ===========================================================================

TEST(ChecksumListTest, ReadsWhatReleaseChecksumsWrites) {
    const auto list = parseChecksumList(kRealChecksumList);
    ASSERT_TRUE(list.ok()) << list.error;
    ASSERT_EQ(list.entries.size(), 4u);
    ASSERT_NE(list.find("lyxbosa-linux-amd64"), nullptr);
    EXPECT_EQ(list.find("lyxbosa-linux-amd64")->hash,
              "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    EXPECT_EQ(list.find("lyxbosa-linux-amd"), nullptr) << "a prefix is not a name";
    EXPECT_EQ(list.find("nothing-like-it"), nullptr);
}

TEST(ChecksumListTest, RefusesEverythingElse) {
    EXPECT_FALSE(parseChecksumList("").ok());
    EXPECT_FALSE(parseChecksumList("\n\n").ok());                       // no entries
    EXPECT_FALSE(parseChecksumList(std::string(64, 'a') + " one-space  x\n").ok());
    EXPECT_FALSE(parseChecksumList(std::string(63, 'a') + "  short\n").ok());
    EXPECT_FALSE(parseChecksumList(std::string(64, 'A') + "  uppercase\n").ok());
    EXPECT_FALSE(parseChecksumList(std::string(64, 'z') + "  nothex\n").ok());
    EXPECT_FALSE(parseChecksumList(std::string(64, 'a') + "  \n").ok());  // no name
    // A path rather than a bare name. release-checksums.sh asserts bare names on every
    // release; refusing one here also means a list can never name a file outside the
    // directory being verified.
    EXPECT_FALSE(parseChecksumList(std::string(64, 'a') + "  ../escape\n").ok());
    EXPECT_FALSE(parseChecksumList(std::string(64, 'a') + "  sub/dir\n").ok());
}

TEST(ChecksumListTest, AMalformedLineDiscardsTheWholeList) {
    // Not "the good lines survive". A list with a line nobody could read is a list that
    // describes something else, and reading past it turns that into "the asset is simply
    // not mentioned" - a different and much softer refusal.
    const auto list =
        parseChecksumList(std::string(kRealChecksumList) + "this is not a checksum\n");
    EXPECT_FALSE(list.ok());
    EXPECT_TRUE(list.entries.empty());
}

#ifdef LYXBOSA_UPDATE_VERIFY

TEST(ChecksumTest, HashesAFileAndCatchesOneChangedByte) {
    TempDir dir;
    writeFile(dir.file("a"), "abc");
    const auto hash = sha256File(dir.file("a"));
    ASSERT_TRUE(hash.has_value());
    // The published SHA-256 of "abc", from FIPS 180-4 rather than from this repository.
    EXPECT_EQ(*hash, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

    writeFile(dir.file("a"), "abd");
    EXPECT_NE(*sha256File(dir.file("a")), *hash);
    EXPECT_FALSE(sha256File(dir.file("missing")).has_value());
}

#else  // LYXBOSA_UPDATE_VERIFY

// SHA-256 comes from the same library as Ed25519, so a build without one has neither.
// What matters is which shape "cannot hash" takes: nullopt, never an empty or
// all-zero digest, because hashesEqual() would compare two of those as equal and a
// download would match a list it was never in.
TEST(ChecksumTest, ABuildWithNoHasherAnswersNothingRatherThanAnEmptyDigest) {
    TempDir dir;
    writeFile(dir.file("a"), "abc");
    EXPECT_FALSE(sha256File(dir.file("a")).has_value());
    EXPECT_FALSE(sha256File(dir.file("missing")).has_value());
    EXPECT_FALSE(hashesEqual("", ""));
}

#endif  // LYXBOSA_UPDATE_VERIFY

TEST(ChecksumTest, ComparisonIsCaseInsensitiveAndTotal) {
    EXPECT_TRUE(hashesEqual("ABCD", "abcd"));
    EXPECT_FALSE(hashesEqual("abcd", "abce"));
    EXPECT_FALSE(hashesEqual("abcd", "abc"));
    EXPECT_FALSE(hashesEqual("", ""));
}

// ===========================================================================
// Where the binary is, and whether it may be replaced.
// ===========================================================================

TEST(InstallPathTest, PackageManagerPathsAreRefusedAndLocalOnesAreNot) {
    EXPECT_FALSE(packageManagerOwning("/usr/bin/lyxbosa").empty());
    EXPECT_FALSE(packageManagerOwning("/usr/sbin/lyxbosa").empty());
    EXPECT_FALSE(packageManagerOwning("/bin/lyxbosa").empty());
    EXPECT_FALSE(packageManagerOwning("/snap/lyxbosa/current/bin/lyxbosa").empty());
    EXPECT_FALSE(packageManagerOwning("/nix/store/abc/bin/lyxbosa").empty());
    EXPECT_FALSE(packageManagerOwning("/opt/homebrew/bin/lyxbosa").empty());

    // The other direction, and it is the half that decides whether the updater is
    // usable at all: /usr/local/bin is the FHS's own answer for a local install and no
    // distribution package writes there.
    EXPECT_TRUE(packageManagerOwning("/usr/local/bin/lyxbosa").empty());
    EXPECT_TRUE(packageManagerOwning("/home/someone/bin/lyxbosa").empty());
    EXPECT_TRUE(packageManagerOwning("/opt/lyxbosa/lyxbosa").empty());
    // Component-wise, not a string prefix: /usr/binary-thing is not inside /usr/bin.
    EXPECT_TRUE(packageManagerOwning("/usr/binary-thing/lyxbosa").empty());
    EXPECT_TRUE(packageManagerOwning("/usr/local/bin-tools/lyxbosa").empty());
}

TEST(InstallPathTest, AWritableDirectoryIsAcceptedAndAMissingOneIsNot) {
    TempDir dir;
    EXPECT_TRUE(canReplace(dir.file("lyxbosa")).ok);
    EXPECT_FALSE(canReplace(dir.file("no-such-directory") / "lyxbosa").ok);
    EXPECT_FALSE(canReplace("lyxbosa").ok) << "a bare name has no install directory";
}

TEST(InstallPathTest, AnUnwritableDirectoryIsRefused) {
    // Stated rather than skipped silently: where the permission bits this case sets are
    // ignored - as root, or on a platform that has none - it cannot observe anything
    // here and says which instead of passing.
    if (const auto why = test::whyCannotDenyOwnAccess()) {
        GTEST_SKIP() << *why;
    }
    // No preprocessor guard: everything below is std::filesystem and canReplace(), so
    // it compiles anywhere. The skip above is what stops it running where it could not
    // observe anything.
    TempDir dir;
    const auto locked = dir.file("locked");
    fs::create_directories(locked);
    fs::permissions(locked, fs::perms::owner_read | fs::perms::owner_exec,
                    fs::perm_options::replace);

    const auto access = canReplace(locked / "lyxbosa");
    EXPECT_FALSE(access.ok);
    EXPECT_FALSE(access.reason.empty());

    fs::permissions(locked, fs::perms::owner_all, fs::perm_options::add);
}

TEST(InstallPathTest, TheProbeLeavesNothingBehind) {
    TempDir dir;
    ASSERT_TRUE(canReplace(dir.file("lyxbosa")).ok);
    EXPECT_TRUE(namesIn(dir.path()).empty());
}

TEST(InstallPathTest, StagingSitsBesideTheTargetSoTheRenameStaysOnOneFilesystem) {
    const auto staged = stagingPathFor("/opt/lyxbosa/bin/lyxbosa");
    EXPECT_EQ(staged.parent_path(), fs::path("/opt/lyxbosa/bin"));
    EXPECT_NE(staged.filename(), fs::path("lyxbosa"));

    // And the name the running image is moved to on Windows, for the same reason: a
    // move that left the directory could leave the volume, and a move across volumes
    // is a copy wearing a rename's name.
    const auto aside = movedAsidePathFor("/opt/lyxbosa/bin/lyxbosa.exe");
    EXPECT_EQ(aside.parent_path(), fs::path("/opt/lyxbosa/bin"));
    EXPECT_EQ(aside.filename(), fs::path("lyxbosa.exe.old"));
}

TEST(InstallPathTest, ReapingRemovesAMovedAsideCopyAndIsQuietAboutItsAbsence) {
    TempDir dir;
    const auto target = dir.file(kTargetName);
    EXPECT_TRUE(reapMovedAsideBinary(target)) << "nothing to reap is not a failure";

    writeFile(movedAsidePathFor(target), "an old binary nobody is running");
    EXPECT_TRUE(reapMovedAsideBinary(target));
    EXPECT_FALSE(fs::exists(movedAsidePathFor(target)));
    EXPECT_TRUE(namesIn(dir.path()).empty());
}

#ifndef _WIN32

TEST(InstallPathTest, ReplaceIsAtomicAndCarriesTheOldModeOver) {
    TempDir dir;
    const auto target = dir.file("lyxbosa");
    writeExecutable(target, "old", 0700);
    const auto staged = stagingPathFor(target);
    writeFile(staged, executableText("new"));
    ::chmod(staged.string().c_str(), 0644);

    EXPECT_EQ(replaceAtomically(staged, target), "");
    EXPECT_EQ(readFile(target), executableText("new"));
    EXPECT_EQ(fileMode(target).value_or(0), 0700u)
        << "a download arrives 0644 and installing it unchanged is an update nobody can run";
    EXPECT_FALSE(fs::exists(staged));
}

TEST(InstallPathTest, TheSmokeTestTellsARunnableBinaryFromOneThatIsNot) {
    TempDir dir;
    writeExecutable(dir.file("runs"), "hello");
    EXPECT_TRUE(stagedBinaryRuns(dir.file("runs")));

    writeFile(dir.file("garbage"), "this is not a program");
    ::chmod(dir.file("garbage").string().c_str(), 0755);
    EXPECT_FALSE(stagedBinaryRuns(dir.file("garbage")));

    // Present, executable, and it exits non-zero: a binary that starts and fails is not
    // one to install either.
    writeFile(dir.file("fails"), "#!/bin/sh\nexit 3\n");
    ::chmod(dir.file("fails").string().c_str(), 0755);
    EXPECT_FALSE(stagedBinaryRuns(dir.file("fails")));

    EXPECT_FALSE(stagedBinaryRuns(dir.file("absent")));
}

#else  // _WIN32

// The first of the two POSIX cases above is about mode bits, which this platform has
// none of. The contract instead is that fileMode() says there is no mode rather than
// guessing one, because replaceAtomically() carries whatever it returns onto the new
// binary.
TEST(InstallPathTest, ThereAreNoModeBitsToCarryOnThisPlatform) {
    TempDir dir;
    writeFile(dir.file(kTargetName), "x");
    const auto mode = fileMode(dir.file(kTargetName));
    ASSERT_TRUE(mode.has_value()) << "a file that is there has an answer";
    EXPECT_EQ(*mode, 0u) << "and the answer is that there is no mode to carry over";
    EXPECT_FALSE(fileMode(dir.file("absent")).has_value());
}

TEST(InstallPathTest, TheSmokeTestTellsARunnableBinaryFromOneThatIsNot) {
    TempDir dir;
    installBinary(dir.file("runs.exe"), oldBinaryBytes());
    EXPECT_TRUE(stagedBinaryRuns(dir.file("runs.exe")))
        << "a copy of this very test binary did not answer --version";

    installBinary(dir.file("overlay.exe"), newBinaryBytes());
    EXPECT_TRUE(stagedBinaryRuns(dir.file("overlay.exe")))
        << "bytes appended past the last section stop the loader, and the cases that "
           "install newBinaryBytes() would be installing something that cannot run";

    // Present, named like an executable, and not one: the loader refuses it before it
    // starts, which is the shape a download for the wrong architecture takes.
    writeFile(dir.file("garbage.exe"), "this is not a program");
    EXPECT_FALSE(stagedBinaryRuns(dir.file("garbage.exe")));

    EXPECT_FALSE(stagedBinaryRuns(dir.file("absent.exe")));
}

// ---------------------------------------------------------------------------
// The two moves. Each case here is about something Windows does that Linux does not,
// and each observes it on the real filesystem rather than through a fake.
// ---------------------------------------------------------------------------

TEST(InstallPathTest, ReplacesARunningImageByMovingItAsideAndReapsItOnceItHasExited) {
    // The premise the whole Windows design rests on, observed on a real running
    // process: its image can be renamed, cannot be deleted, and can be deleted once
    // the process is gone.
    TempDir dir;
    const auto target = dir.file(kTargetName);
    installBinary(target, oldBinaryBytes());
    const auto staged = stagingPathFor(target);
    writeFile(staged, newBinaryBytes());
    const auto aside = movedAsidePathFor(target);

    RunningImage running(target, dir.file("stop"));
    ASSERT_TRUE(running.running()) << "the copy of this test binary did not start";

    EXPECT_EQ(replaceAtomically(staged, target), "");
    EXPECT_EQ(readFile(target), newBinaryBytes()) << "the new binary is not in place";
    EXPECT_TRUE(fs::exists(aside)) << "the running image should have been moved aside";
    EXPECT_EQ(readFile(aside), oldBinaryBytes());
    EXPECT_FALSE(fs::exists(staged));

    // Still running from the moved-aside file, so it cannot go yet - and that is
    // reported as "not reaped", never as an error.
    EXPECT_FALSE(reapMovedAsideBinary(target));
    EXPECT_TRUE(fs::exists(aside)) << "a running image was deleted, which Windows does not allow";
    EXPECT_TRUE(stagedBinaryRuns(target)) << "the new binary does not run";

    running.stop();
    EXPECT_TRUE(reapedWithin(target, std::chrono::seconds(5)))
        << "once nothing has it open the moved-aside copy has to go";
    EXPECT_FALSE(fs::exists(aside));
    EXPECT_EQ(namesIn(dir.path()), (std::vector<std::string>{kTargetName, "stop"}));
}

TEST(InstallPathTest, RollsBackWhenTheSecondMoveFailsSoThereIsAlwaysABinary) {
    // Between the two moves the target does not exist. The staged file is held open
    // without share-delete - which is how a real-time scanner holds a file - so move
    // two fails after its retries, and the assertion is that move one was undone: the
    // old binary is back under its own name, byte for byte, and runs.
    TempDir dir;
    const auto target = dir.file(kTargetName);
    installBinary(target, oldBinaryBytes());
    const auto staged = stagingPathFor(target);
    writeFile(staged, newBinaryBytes());
    const auto aside = movedAsidePathFor(target);

    OpenWithoutShareDelete lock(staged);
    ASSERT_TRUE(lock.ok());

    const auto started = std::chrono::steady_clock::now();
    const std::string failure = replaceByMovingAside(staged, target, std::chrono::milliseconds(300));
    const auto took = std::chrono::steady_clock::now() - started;

    ASSERT_FALSE(failure.empty()) << "a move against a held-open file cannot have succeeded";
    EXPECT_NE(failure.find("put back"), std::string::npos) << failure;
    EXPECT_NE(failure.find("error 32"), std::string::npos)
        << "the real reason - a sharing violation - has to be in the message: " << failure;
    EXPECT_GE(took, std::chrono::milliseconds(300))
        << "it gave up before the retry bound, so the bound was not what was retried";

    EXPECT_TRUE(fs::exists(target)) << "no binary at all is the outcome the rollback exists to prevent";
    EXPECT_EQ(readFile(target), oldBinaryBytes()) << "the old binary was not put back intact";
    EXPECT_FALSE(fs::exists(aside)) << "the rollback left the moved-aside copy behind";
    EXPECT_TRUE(fs::exists(staged)) << "the staged file is the caller's to remove, not this function's";
    EXPECT_TRUE(stagedBinaryRuns(target));
}

TEST(InstallPathTest, LeavesEverythingAloneWhenTheFirstMoveFails) {
    TempDir dir;
    const auto target = dir.file(kTargetName);
    installBinary(target, oldBinaryBytes());
    const auto staged = stagingPathFor(target);
    writeFile(staged, newBinaryBytes());

    OpenWithoutShareDelete lock(target);
    ASSERT_TRUE(lock.ok());

    const std::string failure = replaceByMovingAside(staged, target, std::chrono::milliseconds(300));
    ASSERT_FALSE(failure.empty());
    EXPECT_NE(failure.find("nothing was changed"), std::string::npos) << failure;
    EXPECT_NE(failure.find("error 32"), std::string::npos) << failure;

    EXPECT_EQ(readFile(target), oldBinaryBytes());
    EXPECT_FALSE(fs::exists(movedAsidePathFor(target)));
    EXPECT_TRUE(fs::exists(staged));
}

TEST(InstallPathTest, RetriesAgainstALockThatIsReleasedInTime) {
    // The positive control for the retry: the same lock as above, released after a
    // fraction of the bound, and the replace succeeds where the case above failed.
    // Without this the bound could be a sleep followed by one attempt and nothing
    // here would know.
    TempDir dir;
    const auto target = dir.file(kTargetName);
    installBinary(target, oldBinaryBytes());
    const auto staged = stagingPathFor(target);
    writeFile(staged, newBinaryBytes());

    OpenWithoutShareDelete lock(staged);
    ASSERT_TRUE(lock.ok());
    std::thread releaser([&lock] {
        std::this_thread::sleep_for(std::chrono::milliseconds(350));
        lock.close();
    });

    const auto started = std::chrono::steady_clock::now();
    const std::string failure = replaceByMovingAside(staged, target, std::chrono::seconds(3));
    const auto took = std::chrono::steady_clock::now() - started;
    releaser.join();

    EXPECT_EQ(failure, "");
    EXPECT_GE(took, std::chrono::milliseconds(300)) << "it did not wait for the lock to go";
    EXPECT_EQ(readFile(target), newBinaryBytes());
    EXPECT_FALSE(fs::exists(movedAsidePathFor(target)))
        << "nothing was running from the moved-aside copy, so the replace reaps it itself";
    EXPECT_FALSE(fs::exists(staged));
}

TEST(InstallPathTest, TheRetryBoundIsAFewSecondsAndNotForever) {
    // Where the number comes from is in InstallPath.h. What this asserts is that it is
    // a bound a person watching would sit through and that it is not zero, because a
    // zero bound is one attempt and the retry would be decoration.
    EXPECT_GE(kReplaceRetryFor, std::chrono::seconds(1));
    EXPECT_LE(kReplaceRetryFor, std::chrono::seconds(30));
}

TEST(InstallPathTest, AMovedAsideCopyLeftByAnEarlierUpdateIsReplacedByTheNext) {
    // The reaper failed on every start since the last update - say the old binary was
    // still running each time - and now another update runs. Its first move lands on
    // the existing name, and MOVEFILE_REPLACE_EXISTING is what makes that a
    // replacement rather than a refusal.
    TempDir dir;
    const auto target = dir.file(kTargetName);
    installBinary(target, oldBinaryBytes());
    const auto aside = movedAsidePathFor(target);
    writeFile(aside, "the update before this one");
    const auto staged = stagingPathFor(target);
    writeFile(staged, newBinaryBytes());

    EXPECT_EQ(replaceAtomically(staged, target), "");
    EXPECT_EQ(readFile(target), newBinaryBytes());
    EXPECT_FALSE(fs::exists(aside)) << "reaped: nothing was running from it";
    EXPECT_EQ(namesIn(dir.path()), (std::vector<std::string>{kTargetName}))
        << "one .old at most, ever; a stale one does not accumulate beside a new one";
}

TEST(InstallPathTest, AFileTheUpdaterWritesCarriesNoMarkOfTheWeb) {
    // SmartScreen's unknown-publisher warning is raised for a file that carries a
    // Zone.Identifier stream, which a browser attaches to what it downloads. The
    // updater writes its download through std::fopen, the call HttpAssetSource::fetch
    // makes, and this is the evidence that nothing attaches one on the way: the file
    // that ends up installed has no mark, even where the binary it replaced had one.
    TempDir dir;
    const auto target = dir.file(kTargetName);
    installBinary(target, oldBinaryBytes());

    // The positive control first. A filesystem that cannot carry the stream at all
    // cannot observe anything here, and says so.
    if (!writeZoneIdentifier(target)) {
        GTEST_SKIP() << "this filesystem does not carry alternate data streams (error "
                     << GetLastError() << "), so a Mark of the Web cannot be observed on it";
    }
    ASSERT_TRUE(hasZoneIdentifier(target)) << "the stream just written cannot be read back";

    const auto staged = stagingPathFor(target);
    const std::string& body = newBinaryBytes();
    std::FILE* out = std::fopen(staged.string().c_str(), "wb");
    ASSERT_NE(out, nullptr);
    ASSERT_EQ(std::fwrite(body.data(), 1, body.size(), out), body.size());
    std::fclose(out);
    EXPECT_FALSE(hasZoneIdentifier(staged)) << "fopen attached a zone identifier";

    EXPECT_EQ(replaceAtomically(staged, target), "");
    EXPECT_EQ(readFile(target), body);
    EXPECT_FALSE(hasZoneIdentifier(target))
        << "the installed binary carries a Mark of the Web, so SmartScreen would engage";
}

TEST(InstallPathTest, ADirectoryThisUserMayNotWriteIsRefusedWithTheReason) {
    // What Program Files looks like from a process that is not elevated, built here
    // with an explicit deny so that it is observed on a runner that IS elevated. The
    // positive control is the same directory a moment earlier, before the deny.
    TempDir dir;
    const auto locked = dir.file("locked");
    fs::create_directories(locked);
    ASSERT_TRUE(canReplace(locked / kTargetName).ok) << "writable before the deny, or the case observes nothing";

    ASSERT_TRUE(denyAddingFilesTo(locked)) << "the DACL could not be changed (error " << GetLastError() << ")";

    const auto access = canReplace(locked / kTargetName);
    EXPECT_FALSE(access.ok) << "the deny entry was not honoured";
    EXPECT_NE(access.reason.find("not writable by this user"), std::string::npos) << access.reason;
    EXPECT_TRUE(namesIn(locked).empty()) << "a refused probe left something behind";
}

#endif  // _WIN32

// ===========================================================================
// The whole thing: one case per way of refusing. Each one builds a whole release and
// installs it over a stand-in binary that really runs, so it needs Ed25519 to sign
// with. The #else below is what a build without a verifier owes instead.
// ===========================================================================

#ifdef LYXBOSA_UPDATE_VERIFY

TEST(ApplyTest, ReplacesTheBinaryWhenEverythingChecksOut) {
    TestKey key(1);
    Fixture fixture;
    FakeVersionSource versions("v2.3.0");
    FakeAssetSource assets;
    const Release release = goodRelease(key);
    serve(assets, release);

    const auto keyring = keyringOf(key);
    const auto result = applyUpdate(versions, assets, fixture.options(keyring));

    ASSERT_EQ(result.outcome, ApplyOutcome::Replaced) << result.detail;
    EXPECT_EQ(readFile(fixture.target), release.assetBody);
    EXPECT_EQ(fileMode(fixture.target).value_or(0), kInstalledMode);
    EXPECT_TRUE(stagedBinaryRuns(fixture.target));
    EXPECT_EQ(result.trustedComment, release.trustedComment);
    ASSERT_TRUE(result.plan.has_value());
    EXPECT_EQ(toString(result.plan->to), "2.3.0");

    // The list, the signature and the staging file are all gone - and on Windows the
    // moved-aside copy too, because nothing was running from it.
#ifdef _WIN32
    EXPECT_TRUE(reapedWithin(fixture.target, std::chrono::seconds(5)));
#endif
    EXPECT_EQ(namesIn(fixture.dir.path()), (std::vector<std::string>{kTargetName, "state"}));

    // The signature was fetched and checked before the binary was, which is the order
    // the whole round is about. Asserted on what was actually requested, in sequence.
    ASSERT_EQ(assets.fetched.size(), 3u);
    EXPECT_EQ(assets.fetched[0], "v2.3.0/SHA256SUMS");
    EXPECT_EQ(assets.fetched[1], "v2.3.0/SHA256SUMS.minisig");
    EXPECT_EQ(assets.fetched[2], "v2.3.0/" + std::string(platformAssetName()));
}

TEST(ApplyTest, RefusesABadSignature) {
    TestKey key(1);
    Fixture fixture;
    FakeVersionSource versions("v2.3.0");
    FakeAssetSource assets;
    Release release = goodRelease(key);
    // A signature over something else entirely - which is what a rewritten list leaves
    // behind, and the only thing an attacker who cannot sign can produce.
    release.signature = makeSignature(key, "a different list\n", release.trustedComment);
    serve(assets, release);

    const auto keyring = keyringOf(key);
    const auto result = applyUpdate(versions, assets, fixture.options(keyring));

    EXPECT_EQ(result.outcome, ApplyOutcome::SignatureBad) << result.detail;
    EXPECT_TRUE(result.trustedComment.empty());
    // And the binary was never even asked for: the signature gates the download.
    EXPECT_EQ(std::count(assets.fetched.begin(), assets.fetched.end(),
                         "v2.3.0/" + std::string(platformAssetName())),
              0);
    fixture.expectNothingHappened();
}

TEST(ApplyTest, RefusesAGoodSignatureByAKeyItDoesNotCarry) {
    TestKey release_key(1);
    TestKey stranger(80);
    Fixture fixture;
    FakeVersionSource versions("v2.3.0");
    FakeAssetSource assets;
    Release release = goodRelease(stranger);
    serve(assets, release);

    // Perfectly valid, and signed by somebody this build has never heard of. This is
    // also the frozen-keyring case from keys/minisign-trusted.txt: a binary from before
    // a key was introduced cannot verify a release signed by it, and refusing is the
    // designed outcome rather than a gap.
    const auto keyring = keyringOf(release_key);
    const auto result = applyUpdate(versions, assets, fixture.options(keyring));

    EXPECT_EQ(result.outcome, ApplyOutcome::UnknownKey) << result.detail;
    EXPECT_NE(result.detail.find("download the release"), std::string::npos)
        << "the refusal has to say what to do instead";
    fixture.expectNothingHappened();
}

TEST(ApplyTest, RefusesAGoodSignatureOverAMutatedList) {
    TestKey key(1);
    Fixture fixture;
    FakeVersionSource versions("v2.3.0");
    FakeAssetSource assets;
    Release release = goodRelease(key);
    serve(assets, release);

    // The list rewritten after it was signed, to point at bytes the attacker controls.
    // The signature is genuine and no longer covers what arrived.
    std::string tampered = release.list;
    tampered[0] = tampered[0] == 'a' ? 'b' : 'a';
    assets.entries[std::string(kChecksumListName)].body = tampered;

    const auto keyring = keyringOf(key);
    const auto result = applyUpdate(versions, assets, fixture.options(keyring));

    EXPECT_EQ(result.outcome, ApplyOutcome::SignatureBad) << result.detail;
    fixture.expectNothingHappened();
}

TEST(ApplyTest, RefusesAnOlderReleasesListReplayedAtThisTag) {
    TestKey key(1);
    Fixture fixture;
    FakeVersionSource versions("v2.3.0");
    FakeAssetSource assets;
    Release release = goodRelease(key);
    // Everything genuine: the list is signed, the global signature is signed, and the
    // trusted comment names a DIFFERENT release. docs/RELEASING.md records this exact
    // shape - an older pair verifies perfectly and describes the wrong binaries - and
    // the tag inside the comment is the only thing that catches it.
    release.trustedComment = "LyxBoSa v2.0.0 SHA256SUMS (LytraX/LyxBoSa)";
    release.signature = makeSignature(key, release.list, release.trustedComment);
    serve(assets, release);

    const auto keyring = keyringOf(key);
    const auto result = applyUpdate(versions, assets, fixture.options(keyring));

    EXPECT_EQ(result.outcome, ApplyOutcome::WrongRelease) << result.detail;
    fixture.expectNothingHappened();
}

TEST(ApplyTest, RefusesATrustedCommentThatWasEditedAfterSigning) {
    TestKey key(1);
    Fixture fixture;
    FakeVersionSource versions("v2.3.0");
    FakeAssetSource assets;
    Release release = goodRelease(key);
    // The comment rewritten to name the right tag, the signatures untouched. Only the
    // global signature can tell, and this is the case that proves it is checked.
    std::string tampered = release.signature;
    const size_t at = tampered.find("v2.3.0");
    ASSERT_NE(at, std::string::npos);
    tampered.replace(at, 6, "v2.3.1");
    release.signature = tampered;
    serve(assets, release);

    const auto keyring = keyringOf(key);
    const auto result = applyUpdate(versions, assets, fixture.options(keyring));

    EXPECT_EQ(result.outcome, ApplyOutcome::TrustedCommentBad) << result.detail;
    fixture.expectNothingHappened();
}

TEST(ApplyTest, RefusesAListThatDoesNotMentionThisPlatformsBinary) {
    TestKey key(1);
    Fixture fixture;
    FakeVersionSource versions("v2.3.0");
    FakeAssetSource assets;
    Release release = goodRelease(key);
    release.list = std::string(64, 'a') + "  lyxbosa-somewhere-else\n";
    release.signature = makeSignature(key, release.list, release.trustedComment);
    serve(assets, release);

    const auto keyring = keyringOf(key);
    const auto result = applyUpdate(versions, assets, fixture.options(keyring));

    EXPECT_EQ(result.outcome, ApplyOutcome::AssetNotListed) << result.detail;
    fixture.expectNothingHappened();
}

TEST(ApplyTest, RefusesAHashMismatch) {
    TestKey key(1);
    Fixture fixture;
    FakeVersionSource versions("v2.3.0");
    FakeAssetSource assets;
    Release release = goodRelease(key);
    serve(assets, release);
    // The signed list is right and the bytes are not - a swapped asset, which is the
    // whole reason the list is signed.
    assets.entries[std::string(platformAssetName())].body = executableText("substituted");

    const auto keyring = keyringOf(key);
    const auto result = applyUpdate(versions, assets, fixture.options(keyring));

    EXPECT_EQ(result.outcome, ApplyOutcome::HashMismatch) << result.detail;
    fixture.expectNothingHappened();
}

TEST(ApplyTest, RefusesATruncatedDownloadTheTransportReports) {
    TestKey key(1);
    Fixture fixture;
    FakeVersionSource versions("v2.3.0");
    FakeAssetSource assets;
    serve(assets, goodRelease(key));
    assets.entries[std::string(platformAssetName())].status =
        http::Outcome::Status::Truncated;

    const auto keyring = keyringOf(key);
    const auto result = applyUpdate(versions, assets, fixture.options(keyring));

    EXPECT_EQ(result.outcome, ApplyOutcome::DownloadFailed) << result.detail;
    fixture.expectNothingHappened();
}

TEST(ApplyTest, RefusesATruncatedDownloadTheTransportCallsASuccess) {
    TestKey key(1);
    Fixture fixture;
    FakeVersionSource versions("v2.3.0");
    FakeAssetSource assets;
    const Release release = goodRelease(key);
    serve(assets, release);
    // The stronger version of the case above: the transport writes a short file and
    // reports success. The hash, and not the transport's honesty, is what catches it.
    assets.entries[std::string(platformAssetName())].writeOnly = 4;

    const auto keyring = keyringOf(key);
    const auto result = applyUpdate(versions, assets, fixture.options(keyring));

    EXPECT_EQ(result.outcome, ApplyOutcome::HashMismatch) << result.detail;
    fixture.expectNothingHappened();
}

TEST(ApplyTest, RefusesADownloadThatNeverCompletes) {
    TestKey key(1);
    Fixture fixture;
    FakeVersionSource versions("v2.3.0");
    FakeAssetSource assets;
    serve(assets, goodRelease(key));
    assets.entries[std::string(platformAssetName())].status = http::Outcome::Status::TimedOut;

    const auto keyring = keyringOf(key);
    const auto result = applyUpdate(versions, assets, fixture.options(keyring));

    EXPECT_EQ(result.outcome, ApplyOutcome::DownloadFailed) << result.detail;
    fixture.expectNothingHappened();
}

TEST(ApplyTest, RefusesWhenTheChecksumListItselfCannotBeFetched) {
    TestKey key(1);
    Fixture fixture;
    FakeVersionSource versions("v2.3.0");
    FakeAssetSource assets;
    const Release release = goodRelease(key);
    serve(assets, release);
    assets.entries.erase(std::string(kChecksumSignatureName));

    const auto keyring = keyringOf(key);
    const auto result = applyUpdate(versions, assets, fixture.options(keyring));

    EXPECT_EQ(result.outcome, ApplyOutcome::ListUnavailable) << result.detail;
    // A release published before signing existed lands here, and the answer is the same
    // as for a missing one: nothing gets installed.
    fixture.expectNothingHappened();
}

TEST(ApplyTest, RefusesADowngrade) {
    TestKey key(1);
    Fixture fixture;
    FakeVersionSource versions("v2.1.0");
    FakeAssetSource assets;
    serve(assets, goodRelease(key, "v2.1.0"));

    const auto keyring = keyringOf(key);
    const auto result = applyUpdate(versions, assets, fixture.options(keyring, Version{2, 2, 1}));

    EXPECT_EQ(result.outcome, ApplyOutcome::Downgrade) << result.detail;
    // Nothing was fetched at all - the refusal happens before the release is touched,
    // which is what stops an attacker who can choose the release from making this
    // program do any work on their bytes.
    EXPECT_TRUE(assets.fetched.empty());
    fixture.expectNothingHappened();
}

TEST(ApplyTest, DoesNothingWhenAlreadyOnTheNewestRelease) {
    TestKey key(1);
    Fixture fixture;
    FakeVersionSource versions("v2.2.1");
    FakeAssetSource assets;

    const auto keyring = keyringOf(key);
    const auto result = applyUpdate(versions, assets, fixture.options(keyring, Version{2, 2, 1}));

    EXPECT_EQ(result.outcome, ApplyOutcome::AlreadyCurrent);
    EXPECT_TRUE(assets.fetched.empty());
    fixture.expectNothingHappened();
}

TEST(ApplyTest, RefusesAnUnwritableTarget) {
    TestKey key(1);
    Fixture fixture;
    FakeVersionSource versions("v2.3.0");
    FakeAssetSource assets;
    serve(assets, goodRelease(key));

    const auto keyring = keyringOf(key);
    auto options = fixture.options(keyring);
    // A directory that is not there. Chosen over chmod because it refuses for root as
    // well, and a control that can only fire for one kind of user is half a control.
    options.target = fixture.dir.file("no-such-directory") / "lyxbosa";

    const auto result = applyUpdate(versions, assets, options);

    EXPECT_EQ(result.outcome, ApplyOutcome::NotWritable) << result.detail;
#ifdef _WIN32
    EXPECT_NE(result.detail.find("administrator"), std::string::npos)
        << "the refusal has to say why it is not escalating";
#else
    EXPECT_NE(result.detail.find("sudo"), std::string::npos)
        << "the refusal has to say why it is not escalating";
#endif
    EXPECT_TRUE(assets.fetched.empty());
    fixture.expectNothingHappened();
}

#ifdef _WIN32

TEST(ApplyTest, RefusesADirectoryThisUserMayNotWriteBeforeFetchingAByte) {
    // The Program Files question, end to end: a binary in a directory this user may
    // not add files to - built with a deny entry, so that it is observed on a runner
    // that runs elevated - is refused by the same guard as on Linux, before the
    // network is asked anything, and the refusal says it will not elevate itself.
    TestKey key(1);
    Fixture fixture;
    FakeVersionSource versions("v2.3.0");
    FakeAssetSource assets;
    serve(assets, goodRelease(key));

    const auto locked = fixture.dir.file("program-files");
    fs::create_directories(locked);
    installBinary(locked / kTargetName, oldBinaryBytes());
    ASSERT_TRUE(denyAddingFilesTo(locked)) << "the DACL could not be changed";

    const auto keyring = keyringOf(key);
    auto options = fixture.options(keyring);
    options.target = locked / kTargetName;

    const auto result = applyUpdate(versions, assets, options);

    EXPECT_EQ(result.outcome, ApplyOutcome::NotWritable) << result.detail;
    EXPECT_NE(result.detail.find("administrator"), std::string::npos) << result.detail;
    EXPECT_TRUE(assets.fetched.empty()) << "a user who cannot install is not made to download";
    EXPECT_EQ(versions.calls.load(), 0) << "and is not made to ask what is newest";
    EXPECT_EQ(readFile(locked / kTargetName), oldBinaryBytes());
    EXPECT_EQ(namesIn(locked), (std::vector<std::string>{kTargetName}));
}

#endif  // _WIN32

TEST(ApplyTest, DeclinesAPackageManagedInstall) {
    TestKey key(1);
    Fixture fixture;
    FakeVersionSource versions("v2.3.0");
    FakeAssetSource assets;
    serve(assets, goodRelease(key));

    const auto keyring = keyringOf(key);
    auto options = fixture.options(keyring);
    options.target = "/usr/bin/lyxbosa";

    const auto result = applyUpdate(versions, assets, options);

    EXPECT_EQ(result.outcome, ApplyOutcome::PackageManaged) << result.detail;
    // Nothing was fetched, and - the part that matters for a test pointed at a real
    // system path - nothing was written anywhere.
    EXPECT_TRUE(assets.fetched.empty());
    EXPECT_EQ(versions.calls.load(), 0);
    fixture.expectNothingHappened();
}

TEST(ApplyTest, RefusesADevelopmentBuild) {
    TestKey key(1);
    Fixture fixture;
    FakeVersionSource versions("v2.3.0");
    FakeAssetSource assets;
    serve(assets, goodRelease(key));

    const auto keyring = keyringOf(key);
    const auto result = applyUpdate(versions, assets, fixture.options(keyring, Version{}));

    EXPECT_EQ(result.outcome, ApplyOutcome::DevelopmentBuild);
    EXPECT_EQ(versions.calls.load(), 0) << "nothing was even asked";
    fixture.expectNothingHappened();
}

TEST(ApplyTest, RefusesWhenTheReleasesApiDoesNotAnswer) {
    TestKey key(1);
    Fixture fixture;
    FakeVersionSource versions("");  // fails the way an egress-filtered host does
    FakeAssetSource assets;

    const auto keyring = keyringOf(key);
    const auto result = applyUpdate(versions, assets, fixture.options(keyring));

    EXPECT_EQ(result.outcome, ApplyOutcome::VersionUnavailable);
    EXPECT_EQ(result.detail, "no route to host");
    fixture.expectNothingHappened();
}

TEST(ApplyTest, RefusesATagItWillNotBuildAUrlFrom) {
    TestKey key(1);
    Fixture fixture;
    // Parses as 2.3.0 and is not spelled the way this project tags. The tag is the one
    // network-supplied value that reaches a URL path, so it is rebuilt from the parsed
    // version rather than escaped, and anything else is refused.
    FakeVersionSource versions("V2.3.0");
    FakeAssetSource assets;
    serve(assets, goodRelease(key));

    const auto keyring = keyringOf(key);
    const auto result = applyUpdate(versions, assets, fixture.options(keyring));

    EXPECT_EQ(result.outcome, ApplyOutcome::TagUnusable) << result.detail;
    EXPECT_TRUE(assets.fetched.empty());
    fixture.expectNothingHappened();
}

TEST(ApplyTest, RefusesABinaryThatVerifiesAndWillNotRunHere) {
    TestKey key(1);
    Fixture fixture;
    FakeVersionSource versions("v2.3.0");
    FakeAssetSource assets;
    serve(assets, goodRelease(key));

    const auto keyring = keyringOf(key);
    auto options = fixture.options(keyring);
    options.smokeTest = [](const fs::path&) { return false; };

    const auto result = applyUpdate(versions, assets, options);

    EXPECT_EQ(result.outcome, ApplyOutcome::StagedBinaryUnusable) << result.detail;
    fixture.expectNothingHappened();
}

TEST(ApplyTest, DoesNothingWhenTheAnswerIsNo) {
    TestKey key(1);
    Fixture fixture;
    FakeVersionSource versions("v2.3.0");
    FakeAssetSource assets;
    serve(assets, goodRelease(key));

    const auto keyring = keyringOf(key);
    auto options = fixture.options(keyring);
    options.assumeYes = false;
    options.confirm = [](const ApplyPlan&) { return false; };

    const auto result = applyUpdate(versions, assets, options);

    EXPECT_EQ(result.outcome, ApplyOutcome::Declined);
    EXPECT_TRUE(assets.fetched.empty()) << "a refused update downloads nothing";
    fixture.expectNothingHappened();
}

TEST(ApplyTest, ACallerThatSuppliedNoWayToAskGetsARefusal) {
    // No default yes. A missing prompt must never become a silent replacement.
    TestKey key(1);
    Fixture fixture;
    FakeVersionSource versions("v2.3.0");
    FakeAssetSource assets;
    serve(assets, goodRelease(key));

    const auto keyring = keyringOf(key);
    auto options = fixture.options(keyring);
    options.assumeYes = false;
    options.confirm = nullptr;

    const auto result = applyUpdate(versions, assets, options);

    EXPECT_EQ(result.outcome, ApplyOutcome::Declined);
    fixture.expectNothingHappened();
}

TEST(ApplyTest, TheDefaultKeyringIsTheOneCompiledIn) {
    // Every case above hands applyUpdate a keyring of its own, so none of them can tell
    // whether the DEFAULT is the embedded keyring or something that accepts anything.
    // This one leaves it unset: a release signed by the test key must be refused,
    // because the test key is not in keys/minisign-trusted.txt and never will be.
    TestKey key(1);
    Fixture fixture;
    FakeVersionSource versions("v2.3.0");
    FakeAssetSource assets;
    serve(assets, goodRelease(key));

    auto options = fixture.options(minisign::embeddedKeyring());
    options.keyring = nullptr;

    const auto result = applyUpdate(versions, assets, options);

    EXPECT_EQ(result.outcome, ApplyOutcome::UnknownKey) << result.detail;
    fixture.expectNothingHappened();
}

#else  // LYXBOSA_UPDATE_VERIFY

// The refusals above cannot be built without a verifier, and the one that matters in
// such a build is a different one: applyUpdate refuses on its NoVerifier guard, before
// it asks anything or fetches anything. The assertion is that no byte was requested - a
// build that downloaded a release it then declined to install would be reaching the
// network on every `lyxbosa update` for nothing, and would look identical in the exit
// code.
TEST(ApplyTest, ABuildWithNoVerifierRefusesBeforeItFetchesAByte) {
    FakeVersionSource versions("v2.3.0");
    FakeAssetSource assets;

    ApplyOptions options;
    options.running = Version{2, 2, 1};
    options.assumeYes = true;

    const auto result = applyUpdate(versions, assets, options);

    EXPECT_NE(result.outcome, ApplyOutcome::Replaced);
    EXPECT_FALSE(result.detail.empty()) << "a refusal owes a reason";
    EXPECT_TRUE(assets.fetched.empty()) << "it must refuse before it fetches";
    EXPECT_EQ(versions.calls.load(), 0) << "and before it asks what the newest is";
}

#endif  // LYXBOSA_UPDATE_VERIFY

TEST(ApplyTest, AShippedBuildTalksToGitHubAndNowhereElse) {
    // The origin override is compiled out unless a local demo build asks for it, and a
    // released binary has no code path that reads the variable at all. Asserted here so
    // that a build with it accidentally left on fails its own tests.
#ifdef LYXBOSA_UPDATE_TEST_ORIGIN
    GTEST_SKIP() << "this build was configured with LYXBOSA_UPDATE_TEST_ORIGIN=ON, which "
                    "no release preset sets";
#else
    EXPECT_FALSE(usingTestOrigin());
    EXPECT_EQ(releasesLatestUrl(), "https://api.github.com/repos/LytraX/lyxbosa/releases/latest");
    EXPECT_EQ(releaseAssetUrl("v2.3.0", "lyxbosa-linux-amd64"),
              "https://github.com/LytraX/lyxbosa/releases/download/v2.3.0/lyxbosa-linux-amd64");
#endif
}

TEST(ApplyTest, TheLinuxAssetNamesTheCLibraryThisBinaryWasBuiltAgainst) {
    // Two independent detections of the same fact. CMake reads the compiler's target
    // triple and defines LYXBOSA_LIBC_MUSL for a musl build; glibc's own headers define
    // __GLIBC__ and musl's do not. A binary whose asset name disagrees with the C
    // library it links would update itself onto the other one, so the two have to
    // agree here, in both build jobs, before either ships.
    //
    // The assertion is the WHOLE name and not just the suffix, because the name is a
    // contract with three other files - the workflow that uploads it, the checksum
    // fixture that pins the six, and the build script that renames the binary - and a
    // suffix check would still pass if the stem drifted. Whichever build is running
    // these tests asserts its own name exactly; between the two CI jobs, both rows of
    // the table below are asserted on every release.
#if defined(__linux__)
    const std::string name(platformAssetName());
    const bool namesPortable = name.ends_with("-portable");

#if defined(__aarch64__)
    const std::string stem = "lyxbosa-linux-arm64";
#elif defined(__x86_64__)
    const std::string stem = "lyxbosa-linux-amd64";
#else
    GTEST_SKIP() << "a release publishes no Linux asset for this architecture";
#endif

#if defined(__GLIBC__)
    EXPECT_FALSE(namesPortable)
        << name << " is named as the portable asset by a glibc build";
    EXPECT_EQ(name, stem) << "the standard build must name the unsuffixed asset";
#else
    EXPECT_TRUE(namesPortable) << name << " is named as the standard asset by a build "
                                          "that does not link glibc";
    EXPECT_EQ(name, stem + "-portable")
        << "the portable build must name the -portable asset";
#endif

    // The stem is shared, which is what makes one name a strict prefix of the other -
    // the relation .github/scripts/release-checksums.sh's fixture exists to pin, and
    // the reason `sha256sum -c` matching whole lines is load-bearing rather than
    // incidental.
    EXPECT_TRUE(name.starts_with(stem)) << name << " does not share the common stem";
#else
    GTEST_SKIP() << "the C-library suffix is a rule about Linux asset names";
#endif
}

TEST(ApplyTest, ThisPlatformKnowsWhichAssetItWouldInstall) {
    // A platform with no asset must produce an empty name rather than a guess, and the
    // one running these tests is a platform a release publishes for.
    EXPECT_FALSE(platformAssetName().empty());
    EXPECT_FALSE(runningExecutablePath().empty());

    // Every platform a release is built for can replace its running binary - Linux by
    // a rename over the inode, Windows by moving the image aside - and every one has
    // the verifier compiled in. A build that quietly lost either should fail here and
    // be looked at rather than be discovered by a user typing `update`.
    EXPECT_TRUE(platformCanReplaceRunningBinary());
#ifdef LYXBOSA_UPDATE_VERIFY
    EXPECT_TRUE(minisign::verifierAvailable());
#else
    EXPECT_FALSE(minisign::verifierAvailable())
        << "a build without OpenSSL refuses rather than degrading";
#endif
}
