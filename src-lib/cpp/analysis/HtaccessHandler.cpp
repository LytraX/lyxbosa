#include "HtaccessHandler.h"

#include "core/FileWalker.h"

#include <re2/re2.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <string>
#include <vector>

namespace lyxbosa::analysis::htaccess {

namespace {

std::string lower(std::string_view s) {
    std::string out(s);
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

std::string_view stripQuotes(std::string_view s) {
    if (s.size() >= 2 && (s.front() == '"' || s.front() == '\'') && s.back() == s.front()) {
        return s.substr(1, s.size() - 2);
    }
    return s;
}

bool isBlank(char c) { return c == ' ' || c == '\t'; }

// One directive as Apache reads it: from `offset` to the end of the line, with a backslash
// that ends a line joining the next one ("there must be no other characters or white space
// between the backslash and the end of the line"). Bounded, because a line is a directive
// and not a file.
std::string logicalLine(std::string_view content, size_t offset) {
    constexpr size_t kMaxLine = 64 * 1024;
    std::string out;
    size_t i = offset;
    while (i < content.size() && out.size() < kMaxLine) {
        const char c = content[i];
        if (c == '\\' && i + 1 < content.size() && content[i + 1] == '\n') {
            out += ' ';
            i += 2;
            continue;
        }
        if (c == '\\' && i + 2 < content.size() && content[i + 1] == '\r' &&
            content[i + 2] == '\n') {
            out += ' ';
            i += 3;
            continue;
        }
        if (c == '\n' || c == '\r') break;
        out += c;
        ++i;
    }
    return out;
}

// Words as ap_getword_conf() splits them: on blanks, with a double- or single-quoted run kept
// as one word whose quotes are removed, and a backslash inside the quotes escaping the quote.
std::vector<std::string> words(std::string_view line) {
    std::vector<std::string> out;
    size_t i = 0;
    while (i < line.size()) {
        while (i < line.size() && isBlank(line[i])) ++i;
        if (i >= line.size()) break;
        std::string word;
        const char quote = line[i];
        if (quote == '"' || quote == '\'') {
            ++i;
            while (i < line.size() && line[i] != quote) {
                if (line[i] == '\\' && i + 1 < line.size() && line[i + 1] == quote) ++i;
                word += line[i++];
            }
            if (i < line.size()) ++i;   // the closing quote
        } else {
            while (i < line.size() && !isBlank(line[i])) word += line[i++];
        }
        out.push_back(std::move(word));
    }
    return out;
}

// The start of each line before the one holding `offset`, nearest first.
template <typename F>
void eachLineBefore(std::string_view content, size_t offset, F&& f) {
    size_t lineStart = std::min(offset, content.size());
    while (lineStart > 0 && content[lineStart - 1] != '\n') --lineStart;
    while (lineStart > 0) {
        const size_t end = lineStart - 1;   // the newline that ends the line above
        size_t start = end;
        while (start > 0 && content[start - 1] != '\n') --start;
        if (f(content.substr(start, end - start))) return;
        lineStart = start;
    }
}

std::string_view trimLeft(std::string_view s) {
    size_t i = 0;
    while (i < s.size() && (isBlank(s[i]) || s[i] == '\r')) ++i;
    return s.substr(i);
}

bool startsWithIgnoreCase(std::string_view s, std::string_view prefix) {
    if (s.size() < prefix.size()) return false;
    for (size_t i = 0; i < prefix.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(s[i])) != prefix[i]) return false;
    }
    return true;
}

// Whether the file turns ExecCGI on. mod_cgi and mod_fcgid both refuse to run a file under
// their handler unless it is: "Options ExecCGI is off in this directory". Read in order, as
// the Options lines merge: a list whose words carry no sign replaces the set, so it enables
// ExecCGI only by naming it or `All`; a signed word adds or removes it. A file that never
// says leaves the inherited setting, and that is read as off - see the rule's header.
bool enablesExecCgi(std::string_view content) {
    bool enabled = false;
    size_t pos = 0;
    while (pos < content.size()) {
        size_t eol = content.find('\n', pos);
        if (eol == std::string_view::npos) eol = content.size();
        const std::string_view line = trimLeft(content.substr(pos, eol - pos));
        if (startsWithIgnoreCase(line, "options") && line.size() > 7 && isBlank(line[7])) {
            const auto w = words(logicalLine(content, static_cast<size_t>(line.data() - content.data())));
            bool unsigned_ = false;
            for (size_t i = 1; i < w.size(); ++i) {
                if (!w[i].empty() && w[i][0] != '+' && w[i][0] != '-') unsigned_ = true;
            }
            if (unsigned_) {
                enabled = false;
                for (size_t i = 1; i < w.size(); ++i) {
                    const std::string word = lower(w[i]);
                    if (word == "execcgi" || word == "all") enabled = true;
                }
            } else {
                for (size_t i = 1; i < w.size(); ++i) {
                    if (lower(std::string_view(w[i]).substr(1)) == "execcgi") {
                        enabled = w[i][0] == '+';
                    }
                }
            }
        }
        pos = eol + 1;
    }
    return enabled;
}

// The <Files> or <FilesMatch> block a line sits in, if any. Blocks of that kind do not nest,
// so the nearest opener or closer above the line decides.
struct Selector {
    bool regex = false;
    std::string text;
};

std::optional<Selector> enclosingFilesBlock(std::string_view content, size_t offset) {
    std::optional<Selector> found;
    eachLineBefore(content, offset, [&](std::string_view raw) {
        const std::string_view line = trimLeft(raw);
        if (line.empty() || line[0] == '#') return false;
        if (startsWithIgnoreCase(line, "</files")) return true;   // outside any block
        if (!startsWithIgnoreCase(line, "<files")) return false;

        Selector sel;
        std::string_view rest = line.substr(6);
        if (startsWithIgnoreCase(rest, "match")) {
            sel.regex = true;
            rest.remove_prefix(5);
        }
        const size_t close = rest.rfind('>');
        if (close != std::string_view::npos) rest = rest.substr(0, close);
        rest = trimLeft(rest);
        if (!rest.empty() && rest[0] == '~') {
            sel.regex = true;
            rest = trimLeft(rest.substr(1));
        }
        while (!rest.empty() && (isBlank(rest.back()) || rest.back() == '\r')) rest.remove_suffix(1);
        sel.text = std::string(stripQuotes(rest));
        found = std::move(sel);
        return true;
    });
    return found;
}

ExtensionClass nameClass(std::string_view name) {
    const size_t dot = name.find_last_of('.');
    if (dot == std::string_view::npos || dot == 0) return ExtensionClass::Data;
    return classifyExtension(name.substr(dot + 1));
}

// Names a selector is tried against. Every class is represented, so that a selector reaching
// any data name, any document name or only script names says so.
constexpr std::array<std::string_view, 36> kProbes = {
    "x", ".htaccess", "x.htaccess", "x.jpg", "x.jpeg", "x.png", "x.gif", "x.webp", "x.bmp",
    "x.ico", "x.svg", "x.zip", "x.rar", "x.7z", "x.gz", "x.tar", "x.mdb", "x.pdf", "x.doc",
    "x.docx", "x.xls", "x.txt", "x.csv", "x.json", "x.xml", "x.log", "x.css", "x.js",
    "x.html", "x.htm", "x.php", "x.php5", "x.phtml", "x.phar", "x.cgi", "x.pl",
};

// Which names a <Files> glob or <FilesMatch> regex selects, as the widest class among them.
//
// A selector is a program, not a list, so it is asked rather than parsed: tried against the
// probe names above, and against names built from the literal runs it spells - `shell\.jpg`
// is tried as `shell.jpg`, `(alfa|xyz)` as `x.alfa` and `x.xyz` - so that one naming a single
// upload, or an invented extension, is not read as selecting nothing. An extension it spells
// at the end of an alternative (`\.jpg$`, `\.jpg)`, `*.jpg`) counts whether or not a probe
// reached it, so that a selector cannot hide a data name behind a script alternative.
//
// Matched without regard to case, as Apache matches <FilesMatch> on Windows. A regex RE2
// cannot compile is a selector nothing here can bound, and it is read as reaching data.
ExtensionClass selectorClass(const Selector& sel) {
    std::vector<std::string> probes(kProbes.begin(), kProbes.end());
    std::optional<ExtensionClass> widest;
    const auto widen = [&widest](ExtensionClass c) {
        if (!widest || c > *widest) widest = c;
    };

    std::string run;
    const auto endRun = [&](char terminator) {
        if (run.empty()) return;
        const std::string r = lower(run);
        run.clear();
        if (r.find('.') == std::string::npos) {
            probes.push_back(r);
            probes.push_back("x." + r);
            return;
        }
        // `\.php` is the end of a name, not a dotfile called `.php`.
        probes.push_back(r[0] == '.' ? "x" + r : r);
        const size_t dot = r.find_last_of('.');
        const bool terminal = terminator == '\0' || terminator == '$' || terminator == ')' ||
                              terminator == '|' || terminator == '"' || terminator == '\'';
        if (terminal && dot + 1 < r.size()) widen(classifyExtension(r.substr(dot + 1)));
    };
    const std::string_view text = sel.text;
    for (size_t i = 0; i < text.size(); ++i) {
        const unsigned char c = static_cast<unsigned char>(text[i]);
        if (sel.regex && c == '\\' && i + 1 < text.size() && text[i + 1] == '.') {
            run += '.';
            ++i;
        } else if (std::isalnum(c) || c == '_' || c == '-' || (!sel.regex && c == '.')) {
            run += static_cast<char>(c);
        } else {
            endRun(static_cast<char>(c));
        }
    }
    endRun('\0');

    if (sel.regex) {
        RE2::Options opts;
        opts.set_log_errors(false);
        opts.set_case_sensitive(false);
        const RE2 re(sel.text, opts);
        if (!re.ok()) return ExtensionClass::Data;
        for (const auto& probe : probes) {
            if (RE2::PartialMatch(probe, re)) widen(nameClass(probe));
        }
    } else {
        const std::string pattern = lower(sel.text);
        for (const auto& probe : probes) {
            if (FileWalker::globMatch(pattern, probe)) widen(nameClass(probe));
        }
    }
    return widest.value_or(ExtensionClass::Data);
}

}  // namespace

ExtensionClass classifyExtension(std::string_view extension) {
    std::string e = lower(stripQuotes(extension));
    if (!e.empty() && e[0] == '.') e.erase(0, 1);
    if (e.empty()) return ExtensionClass::Data;

    // .php with any version digits: cPanel writes `.php81` beside `.php`.
    if (e.rfind("php", 0) == 0 &&
        std::all_of(e.begin() + 3, e.end(), [](unsigned char c) { return std::isdigit(c); })) {
        return ExtensionClass::Script;
    }
    static constexpr std::array<std::string_view, 30> kScript = {
        // PHP's own, and the source conventions OBF036 and SEO008 already read as PHP
        "phtml", "pht", "phtm", "phps", "phar", "inc", "module", "install", "theme",
        "profile", "engine", "tpl", "ctp",
        // CGI and the other server-side script families
        "cgi", "fcgi", "pl", "pm", "py", "rb", "sh",
        "asp", "aspx", "ashx", "asmx", "jsp", "jspx", "cfm", "cfml",
        "shtml", "stm",
    };
    for (auto s : kScript) {
        if (e == s) return ExtensionClass::Script;
    }
    if (e == "html" || e == "htm") return ExtensionClass::Document;
    return ExtensionClass::Data;
}

HandlerKind classifyHandler(std::string_view token) {
    const std::string h = lower(stripQuotes(token));
    if (h.rfind("proxy:", 0) == 0) {
        return h.find("fcgi:") != std::string::npos ? HandlerKind::PhpFpm : HandlerKind::None;
    }
    if (h == "cgi-script" || h == "fcgid-script") return HandlerKind::Cgi;
    // A media type under text/ names a type a browser renders, never a handler.
    if (h.rfind("text/", 0) == 0) return HandlerKind::None;
    // application/x-httpd-php-source highlights the file instead of running it.
    if (h.find("php-source") != std::string::npos) return HandlerKind::None;
    if (h.find("php") != std::string::npos) return HandlerKind::Php;
    return HandlerKind::None;
}

bool isAccessFileName(std::string_view finalComponent) {
    std::string_view name = finalComponent;
    while (!name.empty() && (name.back() == '.' || name.back() == ' ')) name.remove_suffix(1);
    if (name.size() != 9) return false;
    return startsWithIgnoreCase(name, ".htaccess");
}

std::optional<ExtensionClass> executedClass(std::string_view content, size_t offset) {
    if (offset >= content.size()) return std::nullopt;
    const auto w = words(logicalLine(content, offset));
    if (w.size() < 2) return std::nullopt;

    const HandlerKind kind = classifyHandler(w[1]);
    if (kind == HandlerKind::None) return std::nullopt;
    if (kind == HandlerKind::Cgi && !enablesExecCgi(content)) return std::nullopt;

    const std::string directive = lower(w[0]);
    if (directive == "addtype" || directive == "addhandler") {
        if (w.size() < 3) return std::nullopt;
        ExtensionClass widest = ExtensionClass::Script;
        for (size_t i = 2; i < w.size(); ++i) {
            widest = std::max(widest, classifyExtension(w[i]));
        }
        return widest;
    }
    if (directive == "sethandler" || directive == "forcetype") {
        const auto block = enclosingFilesBlock(content, offset);
        return block ? selectorClass(*block) : ExtensionClass::Data;
    }
    return std::nullopt;
}

}  // namespace lyxbosa::analysis::htaccess
