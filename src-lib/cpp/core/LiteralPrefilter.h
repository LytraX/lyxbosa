#pragma once

// LiteralPrefilter.h - skip patterns whose required text is not in the file.
//
// The scanner runs every pattern over every file, and on real trees almost nothing
// matches: stock CMS produces 0 findings across 51,294 files, a production site 4
// across 22,416. Virtually all of the work is proving absence, one pattern at a
// time.
//
// A pattern that requires the literal "base64_decode" cannot match a file that does
// not contain it. So: find which literals are present in one pass, then run only the
// patterns whose literals are all there. Measured on this rule set, the number of
// patterns run per file drops from 163 to a handful.
//
// This is an optimisation that must never change a result, and its correctness is a
// property of each pattern rather than something observed on a corpus - a gate entry
// names text every match must contain, which can be checked rule by rule. That is
// why this is preferred over a second regex engine as a prefilter: the guarantee is
// provable rather than measured, and it keeps one engine on every platform.

#include "rules/RuleDefinition.hpp"

#include <re2/re2.h>
#include <re2/set.h>

#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace lyxbosa {

class LiteralPrefilter {
public:
    // Which literals a file contains. Indices are into the prefilter's own table.
    using Present = std::vector<char>;

    // Register a pattern's gate and return a handle used to test it later.
    // Returns kAlwaysRun for patterns without a gate.
    static constexpr size_t kAlwaysRun = static_cast<size_t>(-1);

    size_t add(const rules::Pattern& pattern) {
        bool any = false;
        for (const auto& entry : pattern.gate) {
            if (!entry.empty()) { any = true; break; }
        }
        if (!any) {
            return kAlwaysRun;
        }

        Requirement req;
        for (const auto& entry : pattern.gate) {
            if (entry.empty()) continue;
            std::vector<int> alternatives;
            size_t start = 0;
            while (start <= entry.size()) {
                const size_t bar = entry.find('|', start);
                const size_t end = (bar == std::string_view::npos) ? entry.size() : bar;
                if (end > start) {
                    alternatives.push_back(intern(entry.substr(start, end - start)));
                }
                if (bar == std::string_view::npos) break;
                start = bar + 1;
            }
            if (!alternatives.empty()) {
                req.groups.push_back(std::move(alternatives));
            }
        }
        if (req.groups.empty()) {
            return kAlwaysRun;
        }
        requirements_.push_back(std::move(req));
        return requirements_.size() - 1;
    }

    // Build the matcher. Call once after every pattern has been added.
    bool compile() {
        RE2::Options opts;
        opts.set_log_errors(false);
        opts.set_case_sensitive(false);
        opts.set_max_mem(64 << 20);

        set_ = std::make_unique<RE2::Set>(opts, RE2::UNANCHORED);
        for (const auto& literal : literals_) {
            if (set_->Add(RE2::QuoteMeta(literal), nullptr) < 0) {
                set_.reset();
                return false;
            }
        }
        compiled_ = !literals_.empty() && set_->Compile();
        if (!compiled_) set_.reset();
        return compiled_;
    }

    bool ready() const { return compiled_; }
    size_t literalCount() const { return literals_.size(); }

    // One pass over the file. Returns an empty vector when the prefilter is not
    // usable, which callers must treat as "run everything".
    Present scan(std::string_view content) const {
        Present present;
        if (!compiled_) return present;
        present.assign(literals_.size(), 0);
        std::vector<int> found;
        if (set_->Match(re2::StringPiece(content.data(), content.size()), &found)) {
            for (int id : found) {
                if (id >= 0 && static_cast<size_t>(id) < present.size()) present[id] = 1;
            }
        }
        return present;
    }

    // False only when the file provably cannot contain a match for this pattern.
    bool allows(size_t handle, const Present& present) const {
        if (handle == kAlwaysRun || present.empty()) return true;
        const auto& req = requirements_[handle];
        for (const auto& group : req.groups) {
            bool satisfied = false;
            for (int id : group) {
                if (present[static_cast<size_t>(id)]) { satisfied = true; break; }
            }
            if (!satisfied) return false;
        }
        return true;
    }

private:
    struct Requirement {
        std::vector<std::vector<int>> groups;  // AND of ORs
    };

    int intern(std::string_view text) {
        std::string key;
        key.reserve(text.size());
        for (char c : text) {
            key += static_cast<char>(c >= 'A' && c <= 'Z' ? c - 'A' + 'a' : c);
        }
        auto it = index_.find(key);
        if (it != index_.end()) return it->second;
        const int id = static_cast<int>(literals_.size());
        literals_.push_back(key);
        index_.emplace(std::move(key), id);
        return id;
    }

    std::vector<std::string> literals_;
    std::unordered_map<std::string, int> index_;
    std::vector<Requirement> requirements_;
    std::unique_ptr<RE2::Set> set_;
    bool compiled_ = false;
};

}  // namespace lyxbosa
