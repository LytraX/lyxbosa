// regex_engines - RE2 (as the engine uses it) vs RE2::Set vs Hyperscan, measured
// against this project's real rule set rather than synthetic patterns.
//
// Why the comparison is not pattern-for-pattern: MatchEngine runs one RE2 pass per
// pattern over every file, while RE2::Set and Hyperscan compile every pattern into
// a single automaton and answer "which of these match?" in one pass. That
// difference is the entire reason to look at them, so each engine is measured the
// way it would actually be used.
//
// Neither multi-pattern engine can replace RE2 outright: both report which pattern
// matched and where it ended, but findings need the start offset and the matched
// text. So the shape being evaluated is a *prefilter* - one fast pass to decide
// which rules are worth running, then the existing RE2 only for those.
//
// Build:  cmake -B build -DLYXBOSA_BENCHMARKS=ON
// Run:    ./build/lyxbosa_bench_regex <corpus-dir> [cap-MB] [--agree]
//
// --agree runs the correctness gate instead of the timings: for every file, the
// patterns Hyperscan reports must be a superset of what RE2 finds. Over-reporting
// is free (the follow-up pass discards it); under-reporting is missed malware.

#include "rules/Registry.hpp"

#include <re2/re2.h>
#include <re2/set.h>

#ifdef LYXBOSA_HAVE_HYPERSCAN
#include <hs/hs.h>
#endif

#include <chrono>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <set>
#include <string>
#include <vector>

using namespace lyxbosa::rules;
using Clock = std::chrono::steady_clock;

namespace {

double secs(Clock::time_point a, Clock::time_point b) {
    return std::chrono::duration<double>(b - a).count();
}

struct Pattern {
    std::string code;
    std::string regex;
    bool caseInsensitive;
};

std::vector<Pattern> collectPatterns() {
    std::vector<Pattern> out;
    for (const auto* rule : getAllBuiltinRules()) {
        for (const auto& p : rule->patterns) {
            out.push_back({rule->code.toString(), std::string(p.regex), p.case_insensitive});
        }
    }
    return out;
}

// Mirrors the options PatternCache uses, so the baseline is the real thing.
RE2::Options engineOptions(bool caseInsensitive) {
    RE2::Options o;
    o.set_log_errors(false);
    o.set_dot_nl(true);
    o.set_case_sensitive(!caseInsensitive);
    o.set_max_mem(64 << 20);
    return o;
}

std::vector<std::string> loadCorpus(const char* root, size_t capBytes, size_t& totalBytes) {
    std::vector<std::string> files;
    totalBytes = 0;
    std::error_code ec;
    for (auto it = std::filesystem::recursive_directory_iterator(
             root, std::filesystem::directory_options::skip_permission_denied, ec);
         it != std::filesystem::recursive_directory_iterator(); ++it) {
        if (!it->is_regular_file(ec)) continue;
        const auto size = it->file_size(ec);
        if (ec || size == 0 || size > (4u << 20)) continue;
        std::ifstream f(it->path(), std::ios::binary);
        if (!f) continue;
        files.emplace_back((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
        totalBytes += files.back().size();
        if (totalBytes >= capBytes) break;
    }
    return files;
}

#ifdef LYXBOSA_HAVE_HYPERSCAN
// HS_FLAG_UTF8 is needed for patterns with \x{...} above 0xFF - without it the
// Japanese-keyword rule is the one pattern Hyperscan rejects.
//
// It is applied per pattern rather than globally on purpose: switching the whole
// database to UTF-8 mode took compilation from 0.3 s to 4.4 s and tripled the
// database, for the sake of one rule. Hyperscan takes flags per expression, so
// only the rule that needs it pays.
bool needsUtf8(const std::string& rx) {
    for (size_t i = rx.find("\\x{"); i != std::string::npos; i = rx.find("\\x{", i + 3)) {
        const size_t end = rx.find('}', i);
        if (end == std::string::npos) break;
        const std::string hex = rx.substr(i + 3, end - i - 3);
        if (hex.size() > 2) return true;               // > 0xFF
        if (hex.size() == 2 && std::stoul(hex, nullptr, 16) > 0xFF) return true;
    }
    return false;
}

unsigned hyperscanFlags(const Pattern& p) {
    unsigned f = HS_FLAG_DOTALL | HS_FLAG_SINGLEMATCH;
    if (p.caseInsensitive) f |= HS_FLAG_CASELESS;
    if (needsUtf8(p.regex)) f |= HS_FLAG_UTF8;
    return f;
}

int collectId(unsigned id, unsigned long long, unsigned long long, unsigned, void* ctx) {
    static_cast<std::set<unsigned>*>(ctx)->insert(id);
    return 0;
}

int countHit(unsigned, unsigned long long, unsigned long long, unsigned, void* ctx) {
    ++*static_cast<size_t*>(ctx);
    return 0;
}
#endif

}  // namespace

int main(int argc, char** argv) {
    const char* root = argc > 1 ? argv[1] : "trail-data/CMS";
    const size_t capMB = argc > 2 ? std::stoul(argv[2]) : 64;
    bool agreeMode = false;
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--agree") == 0) agreeMode = true;
    }

    const auto pats = collectPatterns();
    std::printf("rule set: %zu patterns from the live registry\n", pats.size());

    // ---- individual RE2, exactly as MatchEngine builds them -------------------
    std::vector<std::unique_ptr<RE2>> singles;
    auto t0 = Clock::now();
    for (const auto& p : pats) {
        singles.push_back(std::make_unique<RE2>(p.regex, engineOptions(p.caseInsensitive)));
    }
    const double tCompileSingles = secs(t0, Clock::now());
    size_t re2Bad = 0;
    for (size_t i = 0; i < singles.size(); ++i) {
        if (!singles[i]->ok()) {
            ++re2Bad;
            std::printf("  RE2 rejected %-8s %s\n", pats[i].code.c_str(), singles[i]->error().c_str());
        }
    }

    // ---- RE2::Set ------------------------------------------------------------
    RE2::Options setOpts = engineOptions(false);
    setOpts.set_max_mem(256 << 20);
    RE2::Set set(setOpts, RE2::UNANCHORED);
    size_t setBad = 0;
    t0 = Clock::now();
    for (const auto& p : pats) {
        // One option set covers everything if the caseless ones are folded inline.
        const std::string rx = p.caseInsensitive ? "(?i:" + p.regex + ")" : p.regex;
        std::string err;
        if (set.Add(rx, &err) < 0) {
            ++setBad;
            std::printf("  RE2::Set rejected %-8s %s\n", p.code.c_str(), err.c_str());
        }
    }
    const bool setOk = set.Compile();
    const double tCompileSet = secs(t0, Clock::now());

#ifdef LYXBOSA_HAVE_HYPERSCAN
    // ---- Hyperscan -----------------------------------------------------------
    std::vector<std::string> hsKept;
    std::vector<unsigned> hsFlags, hsIds;
    size_t hsBad = 0;
    for (size_t i = 0; i < pats.size(); ++i) {
        hs_database_t* probe = nullptr;
        hs_compile_error_t* err = nullptr;
        if (hs_compile(pats[i].regex.c_str(), hyperscanFlags(pats[i]), HS_MODE_BLOCK,
                       nullptr, &probe, &err) == HS_SUCCESS) {
            hs_free_database(probe);
            hsKept.push_back(pats[i].regex);
            hsFlags.push_back(hyperscanFlags(pats[i]));
            hsIds.push_back(static_cast<unsigned>(i));
        } else {
            ++hsBad;
            std::printf("  Hyperscan rejected %-8s %s\n    %s\n", pats[i].code.c_str(),
                        err && err->message ? err->message : "?", pats[i].regex.c_str());
            if (err) hs_free_compile_error(err);
        }
    }
    std::vector<const char*> hsExpr;
    hsExpr.reserve(hsKept.size());
    for (const auto& e : hsKept) hsExpr.push_back(e.c_str());

    hs_database_t* hsdb = nullptr;
    hs_compile_error_t* hsErr = nullptr;
    t0 = Clock::now();
    const bool hsOk = !hsExpr.empty() &&
                      hs_compile_multi(hsExpr.data(), hsFlags.data(), hsIds.data(),
                                       static_cast<unsigned>(hsExpr.size()), HS_MODE_BLOCK,
                                       nullptr, &hsdb, &hsErr) == HS_SUCCESS;
    const double tCompileHs = secs(t0, Clock::now());
    size_t hsDbBytes = 0;
    if (hsOk) hs_database_size(hsdb, &hsDbBytes);
#endif

    std::printf("\n=== compatibility ===\n");
    std::printf("  RE2       %3zu / %zu\n", pats.size() - re2Bad, pats.size());
    std::printf("  RE2::Set  %3zu / %zu%s\n", pats.size() - setBad, pats.size(),
                setOk ? "" : "  (Compile() FAILED)");
#ifdef LYXBOSA_HAVE_HYPERSCAN
    std::printf("  Hyperscan %3zu / %zu%s\n", hsKept.size(), pats.size(),
                hsOk ? "" : "  (multi-compile FAILED)");
#else
    std::printf("  Hyperscan  -- not built (configure with hyperscan available)\n");
#endif

    std::printf("\n=== one-time compile cost ===\n");
    std::printf("  RE2 singles : %7.1f ms\n", tCompileSingles * 1000);
    std::printf("  RE2::Set    : %7.1f ms\n", tCompileSet * 1000);
#ifdef LYXBOSA_HAVE_HYPERSCAN
    std::printf("  Hyperscan   : %7.1f ms   (database %.0f KB)\n", tCompileHs * 1000,
                hsDbBytes / 1024.0);
#endif

    size_t totalBytes = 0;
    std::printf("\nloading corpus: %s\n", root);
    const auto files = loadCorpus(root, capMB * 1024 * 1024, totalBytes);
    const double mb = totalBytes / 1048576.0;
    std::printf("  %zu files, %.1f MB\n", files.size(), mb);
    if (files.empty()) {
        std::printf("nothing to scan\n");
        return 1;
    }

    // ---- correctness gate ----------------------------------------------------
    if (agreeMode) {
#ifndef LYXBOSA_HAVE_HYPERSCAN
        std::printf("\n--agree needs Hyperscan\n");
        return 1;
#else
        if (!hsOk) return 1;
        hs_scratch_t* scratch = nullptr;
        hs_alloc_scratch(hsdb, &scratch);
        size_t missed = 0, extra = 0, exact = 0;
        for (const auto& data : files) {
            std::set<unsigned> fromHs;
            hs_scan(hsdb, data.data(), static_cast<unsigned>(data.size()), 0, scratch,
                    collectId, &fromHs);

            std::set<unsigned> fromRe2;
            const re2::StringPiece sp(data.data(), data.size());
            for (size_t i = 0; i < singles.size(); ++i) {
                if (singles[i]->ok() && RE2::PartialMatch(sp, *singles[i])) {
                    fromRe2.insert(static_cast<unsigned>(i));
                }
            }

            for (unsigned id : fromRe2) {
                if (!fromHs.count(id)) {
                    ++missed;
                    if (missed <= 10) std::printf("  MISS %s\n", pats[id].code.c_str());
                }
            }
            for (unsigned id : fromHs) extra += fromRe2.count(id) ? 0 : 1;
            exact += (fromRe2 == fromHs);
        }
        hs_free_scratch(scratch);
        std::printf("\n=== prefilter correctness over %.1f MB ===\n", mb);
        std::printf("  exact agreement : %zu / %zu files\n", exact, files.size());
        std::printf("  under-reported  : %zu   <- must be 0, anything here is missed malware\n", missed);
        std::printf("  over-reported   : %zu   (harmless; the follow-up pass discards it)\n", extra);
        hs_free_database(hsdb);
        return missed ? 1 : 0;
#endif
    }

    // ---- warm every engine, then time ---------------------------------------
    // RE2 builds its DFA lazily, so without this whichever variant runs first
    // pays the construction cost for all of them.
    {
        std::vector<int> ids;
        for (const auto& data : files) {
            const re2::StringPiece sp(data.data(), data.size());
            for (auto& re : singles) if (re->ok()) RE2::PartialMatch(sp, *re);
            ids.clear();
            set.Match(sp, &ids);
        }
    }

    // A: today - every pattern tried on every file, and it does not stop at the
    // first hit, because all findings are collected.
    size_t hitA = 0;
    t0 = Clock::now();
    for (const auto& data : files) {
        const re2::StringPiece sp(data.data(), data.size());
        bool any = false;
        for (auto& re : singles) {
            if (re->ok() && RE2::PartialMatch(sp, *re)) any = true;
        }
        hitA += any;
    }
    const double tA = secs(t0, Clock::now());

    // B: RE2::Set as the prefilter.
    size_t hitB = 0;
    std::vector<int> ids;
    t0 = Clock::now();
    for (const auto& data : files) {
        ids.clear();
        if (set.Match(re2::StringPiece(data.data(), data.size()), &ids)) ++hitB;
    }
    const double tB = secs(t0, Clock::now());

    std::printf("\n=== scan %.1f MB / %zu files ===\n", mb, files.size());
    std::printf("  A  RE2, one pass per pattern (today) : %7.2f s  %8.1f MB/s  %zu files hit\n",
                tA, mb / tA, hitA);
    std::printf("  B  RE2::Set prefilter                : %7.2f s  %8.1f MB/s  %zu files hit\n",
                tB, mb / tB, hitB);

#ifdef LYXBOSA_HAVE_HYPERSCAN
    if (hsOk) {
        hs_scratch_t* scratch = nullptr;
        hs_alloc_scratch(hsdb, &scratch);
        for (const auto& data : files) {  // warm
            size_t n = 0;
            hs_scan(hsdb, data.data(), static_cast<unsigned>(data.size()), 0, scratch, countHit, &n);
        }
        size_t hitC = 0;
        t0 = Clock::now();
        for (const auto& data : files) {
            size_t n = 0;
            hs_scan(hsdb, data.data(), static_cast<unsigned>(data.size()), 0, scratch, countHit, &n);
            if (n) ++hitC;
        }
        const double tC = secs(t0, Clock::now());
        std::printf("  C  Hyperscan prefilter               : %7.2f s  %8.1f MB/s  %zu files hit\n",
                    tC, mb / tC, hitC);
        std::printf("\n  A -> B  %.1fx      A -> C  %.1fx\n", tA / tB, tA / tC);
        hs_free_scratch(scratch);
        hs_free_database(hsdb);
    }
#else
    std::printf("\n  A -> B  %.1fx\n", tA / tB);
#endif
    return 0;
}
