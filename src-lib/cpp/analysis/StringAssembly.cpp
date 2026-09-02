#include "analysis/StringAssembly.h"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <optional>
#include <unordered_map>
#include <unordered_set>

namespace lyxbosa::analysis {

namespace {

// Folding limits - keep a hostile file from turning into a CPU sink
constexpr size_t MAX_DEPTH = 12;          // nested calls / parentheses
constexpr size_t MAX_VALUE_LENGTH = 8192; // longest folded value we keep
constexpr size_t MAX_TERMS = 256;         // terms in a single concat chain
constexpr size_t MAX_ARGS = 8;            // arguments to a folded call
constexpr size_t MAX_ARRAY_ITEMS = 256;   // elements in a folded array literal

bool isIdentStart(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
}

bool isIdentChar(char c) {
    return isIdentStart(c) || (c >= '0' && c <= '9');
}

bool isDigit(char c) {
    return c >= '0' && c <= '9';
}

int hexDigit(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

std::string toLower(std::string_view s) {
    std::string out(s);
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

// A folded value: either a scalar string or an array of scalars (for implode)
struct Value {
    std::string text;
    std::vector<std::string> items;
    bool isArray = false;
    size_t fragments = 0;    // atomic literals that went into it
    size_t transforms = 0;   // decode/transform calls applied to it
    bool viaVariables = false;  // at least one piece came through a variable
};

Value makeLiteral(std::string text) {
    Value v;
    // An empty piece is not a piece - `ucfirst($a) . 'Name' . ucfirst($b)` with
    // both variables empty must not read as a three-fragment assembly
    v.fragments = text.empty() ? 0 : 1;
    v.text = std::move(text);
    return v;
}

// ---------------------------------------------------------------------------
// Pure string builtins the folder can evaluate
// ---------------------------------------------------------------------------

std::string rot13(std::string_view s) {
    std::string out(s);
    for (char& c : out) {
        if (c >= 'a' && c <= 'z') c = static_cast<char>('a' + (c - 'a' + 13) % 26);
        else if (c >= 'A' && c <= 'Z') c = static_cast<char>('A' + (c - 'A' + 13) % 26);
    }
    return out;
}

std::optional<std::string> base64Decode(std::string_view s) {
    auto sextet = [](char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return 26 + (c - 'a');
        if (c >= '0' && c <= '9') return 52 + (c - '0');
        if (c == '+') return 62;
        if (c == '/') return 63;
        return -1;
    };

    std::string out;
    uint32_t buffer = 0;
    int bits = 0;

    for (char c : s) {
        if (c == '=' || c == '\n' || c == '\r' || c == ' ' || c == '\t') continue;
        int value = sextet(c);
        if (value < 0) return std::nullopt;  // not base64 - refuse to guess

        buffer = (buffer << 6) | static_cast<uint32_t>(value);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out += static_cast<char>((buffer >> bits) & 0xFF);
            if (out.size() > MAX_VALUE_LENGTH) return std::nullopt;
        }
    }

    return out;
}

std::optional<std::string> hexDecode(std::string_view s) {
    if (s.empty() || s.size() % 2 != 0) return std::nullopt;

    std::string out;
    out.reserve(s.size() / 2);
    for (size_t i = 0; i + 1 < s.size(); i += 2) {
        int high = hexDigit(s[i]);
        int low = hexDigit(s[i + 1]);
        if (high < 0 || low < 0) return std::nullopt;
        out += static_cast<char>((high << 4) | low);
    }
    return out;
}

std::string replaceAll(std::string_view subject, std::string_view search,
                       std::string_view replacement) {
    if (search.empty()) return std::string(subject);

    std::string out;
    size_t pos = 0;
    while (pos < subject.size()) {
        size_t hit = subject.find(search, pos);
        if (hit == std::string_view::npos) break;
        out.append(subject.substr(pos, hit - pos));
        out.append(replacement);
        pos = hit + search.size();
        if (out.size() > MAX_VALUE_LENGTH) return out;
    }
    out.append(subject.substr(pos));
    return out;
}

// ---------------------------------------------------------------------------
// Security-sensitive identifiers
// ---------------------------------------------------------------------------

const std::unordered_set<std::string_view>& sensitiveNames() {
    static const std::unordered_set<std::string_view> names = {
        // Code execution
        "eval", "assert", "create_function", "call_user_func", "call_user_func_array",
        "preg_replace", "preg_replace_callback", "array_map", "array_filter",
        "register_shutdown_function", "register_tick_function", "forward_static_call",
        // Shell
        "system", "exec", "shell_exec", "passthru", "popen", "proc_open", "pcntl_exec",
        "escapeshellcmd", "escapeshellarg", "expect_popen", "dl",
        // Encoders / decoders used to hide payloads
        "base64_decode", "base64_encode", "gzinflate", "gzuncompress", "gzdecode",
        "gzdeflate", "str_rot13", "convert_uudecode", "hex2bin", "bin2hex",
        "pack", "unpack", "unserialize", "urldecode", "rawurldecode", "strrev",
        "openssl_decrypt", "mcrypt_decrypt", "zlib_decode",
        // Filesystem
        "file_get_contents", "file_put_contents", "fopen", "fwrite", "fputs", "fread",
        "unlink", "rename", "copy", "mkdir", "rmdir", "chmod", "chown", "touch",
        "move_uploaded_file", "readfile", "scandir", "opendir", "readdir", "glob",
        "tempnam", "sys_get_temp_dir", "symlink", "link",
        // Includes
        "include", "include_once", "require", "require_once",
        // Network
        "curl_init", "curl_exec", "curl_setopt", "fsockopen", "pfsockopen",
        "socket_create", "socket_connect", "stream_socket_client", "get_headers",
        "file", "fpassthru", "mail",
        // Environment tampering
        "ini_set", "ini_restore", "error_reporting", "set_time_limit", "putenv",
        "getenv", "phpinfo", "extract", "parse_str", "header", "die", "exit",
        // Superglobals and request data
        "_post", "_get", "_request", "_cookie", "_server", "_files", "_env",
        "_session", "globals", "http_raw_post_data", "php_uname",
        // WordPress/CMS abuse primitives commonly assembled by injectors
        "wp_insert_user", "wp_create_user", "add_action", "add_filter",
        "update_option", "wp_remote_get", "wp_remote_post",
    };
    return names;
}

// ---------------------------------------------------------------------------
// The folder
// ---------------------------------------------------------------------------

class Folder {
public:
    explicit Folder(std::string_view src) : src_(src) {}

    std::vector<AssembledString> run();

private:
    // Lexing helpers
    void skipTrivia();
    char peek(size_t ahead = 0) const {
        return (pos_ + ahead < src_.size()) ? src_[pos_ + ahead] : '\0';
    }
    bool atEnd() const { return pos_ >= src_.size(); }
    std::string readIdentifier();

    // Grammar
    std::optional<Value> parseExpression(size_t depth);
    std::optional<Value> parseTerm(size_t depth);
    std::optional<Value> parseStringLiteral();
    std::optional<Value> parseNumber();
    std::optional<Value> parseArrayLiteral(char closer, size_t depth);
    std::optional<Value> parseCall(std::string_view name, size_t depth);
    std::optional<std::vector<Value>> parseArguments(size_t depth);

    void record(size_t offset, size_t length, std::string variable, const Value& value);

    std::string_view src_;
    size_t pos_ = 0;
    std::unordered_map<std::string, Value> env_;
    std::vector<AssembledString> findings_;
};

void Folder::skipTrivia() {
    while (pos_ < src_.size()) {
        char c = src_[pos_];

        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
            ++pos_;
            continue;
        }

        // Line comments: // and #
        if ((c == '/' && peek(1) == '/') || c == '#') {
            while (pos_ < src_.size() && src_[pos_] != '\n') ++pos_;
            continue;
        }

        // Block comments
        if (c == '/' && peek(1) == '*') {
            size_t end = src_.find("*/", pos_ + 2);
            pos_ = (end == std::string_view::npos) ? src_.size() : end + 2;
            continue;
        }

        return;
    }
}

std::string Folder::readIdentifier() {
    size_t start = pos_;
    while (pos_ < src_.size() && isIdentChar(src_[pos_])) ++pos_;
    return std::string(src_.substr(start, pos_ - start));
}

// A quoted literal. Always consumes the whole literal (so the caller can keep
// scanning), but yields nothing when the value depends on interpolation.
std::optional<Value> Folder::parseStringLiteral() {
    const char quote = src_[pos_];
    size_t i = pos_ + 1;
    std::string out;
    bool resolvable = true;

    while (i < src_.size()) {
        char c = src_[i];

        if (c == '\\' && i + 1 < src_.size()) {
            char esc = src_[i + 1];

            if (quote == '\'') {
                // Single quotes only escape \ and '
                if (esc == '\\' || esc == '\'') {
                    out += esc;
                    i += 2;
                } else {
                    out += c;
                    ++i;
                }
                continue;
            }

            i += 2;
            switch (esc) {
                case 'n': out += '\n'; break;
                case 'r': out += '\r'; break;
                case 't': out += '\t'; break;
                case 'v': out += '\v'; break;
                case 'f': out += '\f'; break;
                case 'e': out += '\x1b'; break;
                case '\\': out += '\\'; break;
                case '$': out += '$'; break;
                case '"': out += '"'; break;
                case 'x': {
                    std::string hex;
                    while (i < src_.size() && hex.size() < 2 && hexDigit(src_[i]) >= 0) {
                        hex += src_[i++];
                    }
                    if (hex.empty()) {
                        out += "\\x";
                    } else {
                        int value = 0;
                        for (char h : hex) value = value * 16 + hexDigit(h);
                        out += static_cast<char>(value);
                    }
                    break;
                }
                case 'u': {
                    // \u{...} - unicode escapes are not worth folding
                    resolvable = false;
                    if (i < src_.size() && src_[i] == '{') {
                        size_t close = src_.find('}', i);
                        i = (close == std::string_view::npos) ? src_.size() : close + 1;
                    }
                    break;
                }
                default:
                    if (esc >= '0' && esc <= '7') {
                        int value = esc - '0';
                        size_t digits = 1;
                        while (i < src_.size() && digits < 3 && src_[i] >= '0' && src_[i] <= '7') {
                            value = value * 8 + (src_[i++] - '0');
                            ++digits;
                        }
                        out += static_cast<char>(value & 0xFF);
                    } else {
                        out += '\\';
                        out += esc;
                    }
                    break;
            }
            continue;
        }

        if (c == quote) {
            pos_ = i + 1;
            if (!resolvable || out.size() > MAX_VALUE_LENGTH) return std::nullopt;
            return makeLiteral(std::move(out));
        }

        // Double-quoted strings interpolate - the written text is not the value
        if (quote == '"' && (c == '$' || c == '{')) {
            char next = (i + 1 < src_.size()) ? src_[i + 1] : '\0';
            if ((c == '$' && (isIdentStart(next) || next == '{')) ||
                (c == '{' && next == '$')) {
                resolvable = false;
            }
        }

        out += c;
        ++i;
    }

    pos_ = src_.size();  // unterminated literal
    return std::nullopt;
}

std::optional<Value> Folder::parseNumber() {
    size_t start = pos_;
    if (peek() == '-' || peek() == '+') ++pos_;
    while (pos_ < src_.size() && isDigit(src_[pos_])) ++pos_;

    if (pos_ == start) return std::nullopt;
    return makeLiteral(std::string(src_.substr(start, pos_ - start)));
}

// array(...) / [...] of scalars - the input side of implode()
std::optional<Value> Folder::parseArrayLiteral(char closer, size_t depth) {
    Value result;
    result.isArray = true;

    skipTrivia();
    if (peek() == closer) {
        ++pos_;
        return result;
    }

    while (!atEnd()) {
        auto item = parseExpression(depth + 1);
        if (!item || item->isArray) return std::nullopt;

        if (result.items.size() >= MAX_ARRAY_ITEMS) return std::nullopt;
        result.items.push_back(item->text);
        result.fragments += item->fragments;
        result.transforms += item->transforms;
        result.viaVariables |= item->viaVariables;

        skipTrivia();
        if (peek() == ',') {
            ++pos_;
            skipTrivia();
            if (peek() == closer) {  // trailing comma
                ++pos_;
                return result;
            }
            continue;
        }
        if (peek() == closer) {
            ++pos_;
            return result;
        }
        return std::nullopt;
    }

    return std::nullopt;
}

// Arguments of a known-pure call. Fails (leaving pos_ inside the call) as soon
// as one argument cannot be folded, so the outer scan still walks the rest.
std::optional<std::vector<Value>> Folder::parseArguments(size_t depth) {
    std::vector<Value> args;

    skipTrivia();
    if (peek() == ')') {
        ++pos_;
        return args;
    }

    while (!atEnd()) {
        auto arg = parseExpression(depth + 1);
        if (!arg) return std::nullopt;

        if (args.size() >= MAX_ARGS) return std::nullopt;
        args.push_back(std::move(*arg));

        skipTrivia();
        if (peek() == ',') {
            ++pos_;
            continue;
        }
        if (peek() == ')') {
            ++pos_;
            return args;
        }
        return std::nullopt;
    }

    return std::nullopt;
}

// `pos_` sits on the '(' of a call to `name`.
std::optional<Value> Folder::parseCall(std::string_view name, size_t depth) {
    const std::string fn = toLower(name);

    static const std::unordered_set<std::string_view> foldable = {
        "strrev", "strtolower", "strtoupper", "lcfirst", "ucfirst", "trim",
        "ltrim", "rtrim", "str_rot13", "base64_decode", "hex2bin", "chr",
        "str_replace", "str_ireplace", "implode", "join", "substr", "pack",
        "strval", "str_repeat",
    };

    if (foldable.find(fn) == foldable.end()) {
        // Unknown call: step just past '(' so the arguments still get scanned
        ++pos_;
        return std::nullopt;
    }

    ++pos_;  // consume '('
    auto args = parseArguments(depth + 1);
    if (!args) return std::nullopt;

    size_t fragments = 0;
    size_t transforms = 1;  // the call itself is one transformation
    bool viaVariables = false;
    for (const auto& arg : *args) {
        fragments += arg.fragments;
        transforms += arg.transforms;
        viaVariables |= arg.viaVariables;
    }

    auto scalar = [&](size_t index) -> const std::string* {
        if (index >= args->size() || (*args)[index].isArray) return nullptr;
        return &(*args)[index].text;
    };

    auto finish = [&](std::string text) -> std::optional<Value> {
        if (text.size() > MAX_VALUE_LENGTH) return std::nullopt;
        Value v;
        v.text = std::move(text);
        v.fragments = fragments;
        v.transforms = transforms;
        v.viaVariables = viaVariables;
        return v;
    };

    if (fn == "implode" || fn == "join") {
        // implode(glue, array) and implode(array)
        const Value* list = nullptr;
        std::string glue;
        if (args->size() == 1 && (*args)[0].isArray) {
            list = &(*args)[0];
        } else if (args->size() == 2 && (*args)[1].isArray && !(*args)[0].isArray) {
            glue = (*args)[0].text;
            list = &(*args)[1];
        } else if (args->size() == 2 && (*args)[0].isArray && !(*args)[1].isArray) {
            glue = (*args)[1].text;  // legacy implode(array, glue)
            list = &(*args)[0];
        }
        if (!list) return std::nullopt;

        std::string text;
        for (size_t i = 0; i < list->items.size(); ++i) {
            if (i) text += glue;
            text += list->items[i];
        }
        // Every element was written separately - that is the fragmentation
        transforms = list->transforms;
        fragments = list->fragments;
        viaVariables = list->viaVariables;
        return finish(std::move(text));
    }

    if (args->size() == 1) {
        const std::string* s = scalar(0);
        if (!s) return std::nullopt;

        if (fn == "strrev") {
            std::string text(*s);
            std::reverse(text.begin(), text.end());
            return finish(std::move(text));
        }
        if (fn == "strtolower") return finish(toLower(*s));
        if (fn == "strtoupper") {
            std::string text(*s);
            std::transform(text.begin(), text.end(), text.begin(),
                           [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
            return finish(std::move(text));
        }
        if (fn == "lcfirst" || fn == "ucfirst") {
            std::string text(*s);
            if (!text.empty()) {
                text[0] = static_cast<char>(fn == "ucfirst" ? std::toupper(static_cast<unsigned char>(text[0]))
                                                            : std::tolower(static_cast<unsigned char>(text[0])));
            }
            return finish(std::move(text));
        }
        if (fn == "trim" || fn == "ltrim" || fn == "rtrim") {
            std::string_view text(*s);
            if (fn != "rtrim") {
                size_t first = text.find_first_not_of(" \t\n\r\0\x0B", 0, 6);
                text = (first == std::string_view::npos) ? std::string_view{} : text.substr(first);
            }
            if (fn != "ltrim" && !text.empty()) {
                size_t last = text.find_last_not_of(" \t\n\r\0\x0B", std::string_view::npos, 6);
                text = (last == std::string_view::npos) ? std::string_view{} : text.substr(0, last + 1);
            }
            return finish(std::string(text));
        }
        if (fn == "str_rot13") return finish(rot13(*s));
        if (fn == "strval") return finish(*s);
        if (fn == "base64_decode") {
            auto decoded = base64Decode(*s);
            if (!decoded) return std::nullopt;
            return finish(std::move(*decoded));
        }
        if (fn == "hex2bin") {
            auto decoded = hexDecode(*s);
            if (!decoded) return std::nullopt;
            return finish(std::move(*decoded));
        }
        if (fn == "chr") {
            long code = 0;
            for (char c : *s) {
                if (!isDigit(c)) return std::nullopt;
                code = code * 10 + (c - '0');
                if (code > 255) return std::nullopt;
            }
            return finish(std::string(1, static_cast<char>(code & 0xFF)));
        }
        return std::nullopt;
    }

    if (fn == "pack" && args->size() == 2) {
        const std::string* format = scalar(0);
        const std::string* data = scalar(1);
        if (!format || !data) return std::nullopt;
        if (toLower(*format) != "h*") return std::nullopt;
        auto decoded = hexDecode(*data);
        if (!decoded) return std::nullopt;
        return finish(std::move(*decoded));
    }

    if ((fn == "str_replace" || fn == "str_ireplace") && args->size() == 3) {
        const std::string* search = scalar(0);
        const std::string* replacement = scalar(1);
        const std::string* subject = scalar(2);
        if (!search || !replacement || !subject) return std::nullopt;
        return finish(replaceAll(*subject, *search, *replacement));
    }

    if (fn == "str_repeat" && args->size() == 2) {
        const std::string* s = scalar(0);
        const std::string* countText = scalar(1);
        if (!s || !countText || countText->empty()) return std::nullopt;

        long count = 0;
        for (char c : *countText) {
            if (!isDigit(c)) return std::nullopt;
            count = count * 10 + (c - '0');
            if (count > static_cast<long>(MAX_VALUE_LENGTH) ||
                count * static_cast<long>(s->size()) > static_cast<long>(MAX_VALUE_LENGTH)) {
                return std::nullopt;
            }
        }

        std::string text;
        for (long i = 0; i < count; ++i) text += *s;
        return finish(std::move(text));
    }

    if (fn == "substr" && (args->size() == 2 || args->size() == 3)) {
        const std::string* s = scalar(0);
        const std::string* startText = scalar(1);
        if (!s || !startText) return std::nullopt;

        auto toInt = [](const std::string& text, long& out) {
            if (text.empty()) return false;
            size_t i = 0;
            long sign = 1;
            if (text[0] == '-') { sign = -1; i = 1; }
            else if (text[0] == '+') { i = 1; }
            if (i >= text.size()) return false;
            long value = 0;
            for (; i < text.size(); ++i) {
                if (!isDigit(text[i])) return false;
                value = value * 10 + (text[i] - '0');
            }
            out = sign * value;
            return true;
        };

        long start = 0;
        if (!toInt(*startText, start)) return std::nullopt;

        const long size = static_cast<long>(s->size());
        if (start < 0) start = std::max(0L, size + start);
        if (start > size) return finish(std::string{});

        long length = size - start;
        if (args->size() == 3) {
            const std::string* lengthText = scalar(2);
            if (!lengthText || !toInt(*lengthText, length)) return std::nullopt;
            if (length < 0) length = std::max(0L, (size - start) + length);
            length = std::min(length, size - start);
        }

        return finish(s->substr(static_cast<size_t>(start), static_cast<size_t>(length)));
    }

    return std::nullopt;
}

std::optional<Value> Folder::parseTerm(size_t depth) {
    if (depth > MAX_DEPTH) return std::nullopt;

    skipTrivia();
    if (atEnd()) return std::nullopt;

    const char c = src_[pos_];

    if (c == '"' || c == '\'') return parseStringLiteral();

    if (c == '$') {
        if (!isIdentStart(peek(1))) {
            ++pos_;
            return std::nullopt;
        }

        ++pos_;
        const std::string name = readIdentifier();
        const size_t afterName = pos_;

        // $var(...), $var[...], $var->x, $var::x are not plain string reads
        skipTrivia();
        const char next = peek();
        if (next == '(' || next == '[' || next == '{' ||
            (next == '-' && peek(1) == '>') || (next == ':' && peek(1) == ':')) {
            pos_ = afterName;
            return std::nullopt;
        }
        pos_ = afterName;

        auto it = env_.find(name);
        if (it == env_.end() || it->second.isArray) return std::nullopt;

        Value value = it->second;
        value.viaVariables = true;
        return value;
    }

    if (c == '(') {
        ++pos_;
        auto inner = parseExpression(depth + 1);
        skipTrivia();
        if (peek() != ')') return std::nullopt;
        ++pos_;
        return inner;
    }

    if (c == '[') {
        ++pos_;
        return parseArrayLiteral(']', depth);
    }

    if (isDigit(c) || ((c == '-' || c == '+') && isDigit(peek(1)))) {
        return parseNumber();
    }

    if (isIdentStart(c)) {
        const size_t nameStart = pos_;
        const std::string name = readIdentifier();
        skipTrivia();

        if (peek() == '(') {
            if (toLower(name) == "array") {
                ++pos_;
                return parseArrayLiteral(')', depth);
            }
            return parseCall(name, depth);
        }

        pos_ = nameStart + name.size();
        return std::nullopt;  // bareword constant - unknown value
    }

    return std::nullopt;
}

// term ('.' term)*
std::optional<Value> Folder::parseExpression(size_t depth) {
    if (depth > MAX_DEPTH) return std::nullopt;

    auto head = parseTerm(depth);
    if (!head) return std::nullopt;

    Value result = std::move(*head);
    size_t terms = 1;

    while (true) {
        const size_t save = pos_;
        skipTrivia();

        // '.' is concatenation, but '.=' ends the expression and a digit after
        // it makes a float - neither continues the chain
        if (peek() != '.' || peek(1) == '=' || isDigit(peek(1))) {
            pos_ = save;
            break;
        }
        ++pos_;

        auto next = parseTerm(depth);
        if (!next || next->isArray || result.isArray) return std::nullopt;

        if (++terms > MAX_TERMS) return std::nullopt;
        if (result.text.size() + next->text.size() > MAX_VALUE_LENGTH) return std::nullopt;

        result.text += next->text;
        result.fragments += next->fragments;
        result.transforms += next->transforms;
        result.viaVariables |= next->viaVariables;
    }

    return result;
}

void Folder::record(size_t offset, size_t length, std::string variable, const Value& value) {
    if (value.isArray) return;
    if (value.fragments < 2 && value.transforms == 0) return;  // written out in one piece

    // Only identifiers matter: assembled paths, SQL and messages are not what
    // this looks for, and they are where the false positives live.
    if (value.text.size() < 2 || value.text.size() > 64) return;
    if (!isIdentStart(value.text[0])) return;
    for (char c : value.text) {
        if (!isIdentChar(c)) return;
    }

    AssembledString found;
    found.offset = offset;
    found.length = length;
    found.value = value.text;
    found.fragments = value.fragments;
    found.transforms = value.transforms;
    found.variable = std::move(variable);
    found.viaVariables = value.viaVariables;
    found.sensitive = isSensitiveIdentifier(value.text);

    // A `.=` chain records once per append. Collapse the intermediate states
    // ("ba", "base", "base64", ...) into the one finding for the finished name.
    if (!found.variable.empty()) {
        for (size_t i = findings_.size(); i-- > 0;) {
            if (findings_[i].variable != found.variable) continue;
            if (found.value.rfind(findings_[i].value, 0) == 0) {
                found.offset = findings_[i].offset;
                found.length = (offset + length) - findings_[i].offset;
                findings_.erase(findings_.begin() + static_cast<long>(i));
            }
            break;
        }
    }

    findings_.push_back(std::move(found));
}

std::vector<AssembledString> Folder::run() {
    // Only five bytes can start anything the folder cares about: '$' begins an
    // assignment, a quote begins a literal, and '/' or '#' may begin a comment
    // that skipTrivia has to consume so a quote inside it is not read as code.
    // Everything else - whitespace, operators, punctuation, bare identifiers -
    // is inert, so jump to the next candidate instead of walking to it a byte at
    // a time through skipTrivia().
    static constexpr std::string_view kCandidates = "$\"'/#";

    while (pos_ < src_.size()) {
        const size_t jump = src_.find_first_of(kCandidates, pos_);
        if (jump == std::string_view::npos) break;
        pos_ = jump;

        const size_t loopStart = pos_;

        skipTrivia();
        if (atEnd()) break;

        const char c = src_[pos_];

        // Assignment: $var = <expr>  /  $var .= <expr>
        if (c == '$' && isIdentStart(peek(1))) {
            const size_t varStart = pos_;
            ++pos_;
            const std::string name = readIdentifier();
            const size_t afterName = pos_;

            skipTrivia();
            bool append = false;
            if (peek() == '=' && peek(1) != '=' && peek(1) != '>') {
                ++pos_;
            } else if (peek() == '.' && peek(1) == '=') {
                pos_ += 2;
                append = true;
            } else {
                pos_ = afterName;
                continue;
            }

            auto parsed = parseExpression(0);

            // The chain must be the whole right-hand side. Anything else - a
            // `?:` fallback, a comparison, a parameter default's `,` or `)` -
            // means the folded value is not what the variable ends up holding.
            const size_t afterExpression = pos_;
            skipTrivia();
            const bool wholeStatement =
                atEnd() || peek() == ';' || (peek() == '?' && peek(1) == '>');
            pos_ = afterExpression;

            if (parsed && !parsed->isArray && wholeStatement) {
                Value value = std::move(*parsed);

                if (append) {
                    auto previous = env_.find(name);
                    if (previous == env_.end() || previous->second.isArray) {
                        env_.erase(name);
                        continue;
                    }
                    value.text = previous->second.text + value.text;
                    value.fragments += previous->second.fragments;
                    value.transforms += previous->second.transforms;
                    value.viaVariables = true;  // the chain runs through $name
                    if (value.text.size() > MAX_VALUE_LENGTH) {
                        env_.erase(name);
                        continue;
                    }
                }

                record(varStart, pos_ - varStart, name, value);
                env_[name] = std::move(value);
            } else {
                env_.erase(name);  // now holds something we cannot track
            }

            if (pos_ == loopStart) ++pos_;
            continue;
        }

        // Inline expression: eval("ba" . "se64_decode") and friends
        if (c == '"' || c == '\'') {
            const size_t exprStart = pos_;
            auto parsed = parseExpression(0);
            if (parsed) record(exprStart, pos_ - exprStart, {}, *parsed);
            if (pos_ == loopStart) ++pos_;
            continue;
        }

        // Skip whole identifiers/numbers so a bareword is not rescanned char by char
        if (isIdentChar(c)) {
            while (pos_ < src_.size() && isIdentChar(src_[pos_])) ++pos_;
            continue;
        }

        ++pos_;
    }

    return std::move(findings_);
}

}  // namespace

bool isSensitiveIdentifier(std::string_view name) {
    const std::string lowered = toLower(name);
    return sensitiveNames().find(lowered) != sensitiveNames().end();
}

bool isDynamicallyCalled(std::string_view content, std::string_view variable) {
    if (variable.empty()) return false;

    const std::string needle = "$" + std::string(variable);

    size_t pos = 0;
    while ((pos = content.find(needle, pos)) != std::string_view::npos) {
        const size_t nameEnd = pos + needle.size();

        // Must be the whole variable name, not a prefix of a longer one
        if (nameEnd < content.size() && isIdentChar(content[nameEnd])) {
            pos = nameEnd;
            continue;
        }

        // `new $var()` is dynamic instantiation - every CMS factory does it
        bool isInstantiation = false;
        if (pos >= 4) {
            size_t before = pos;
            while (before > 0 && (content[before - 1] == ' ' || content[before - 1] == '\t')) {
                --before;
            }
            isInstantiation = before >= 3 && content.substr(before - 3, 3) == "new" &&
                              (before == 3 || !isIdentChar(content[before - 4]));
        }

        // $var(  or  ${$var}(  or  $$var(
        size_t after = nameEnd;
        while (after < content.size() &&
               (content[after] == ' ' || content[after] == '\t' ||
                content[after] == '\r' || content[after] == '\n')) {
            ++after;
        }
        if (!isInstantiation && after < content.size() && content[after] == '(') return true;

        // Passed where a callable is expected: $$var, ${$var}, call_user_func($var, ...)
        if (pos > 0 && (content[pos - 1] == '$' || content[pos - 1] == '{')) return true;

        pos = nameEnd;
    }

    return false;
}

namespace {

// OBF024 and OBF025 are separate rules over the same analysis, so the folder ran
// twice on every file. Keep the last result and hand it to the second caller.
//
// Identity is checked by comparing the bytes, not by hashing them: a scanner reads
// one file after another, so the same buffer address comes back constantly for
// different files, and returning another file's findings would be a wrong answer
// rather than a slow one. memcmp against a kept copy is exact and runs at memory
// speed - an earlier version verified with a byte-at-a-time FNV hash, which cost
// most of what the memoisation saved.
struct FoldCache {
    std::string content;
    bool valid = false;
    std::vector<AssembledString> result;

    bool holds(std::string_view candidate) const {
        return valid && content.size() == candidate.size() &&
               std::memcmp(content.data(), candidate.data(), candidate.size()) == 0;
    }
};

}  // namespace

std::vector<AssembledString> findAssembledStrings(std::string_view content) {
    static thread_local FoldCache cache;
    if (cache.holds(content)) {
        return cache.result;
    }

    Folder folder(content);
    auto result = folder.run();

    cache.content.assign(content.data(), content.size());
    cache.result = result;
    cache.valid = true;
    return result;
}

}  // namespace lyxbosa::analysis
