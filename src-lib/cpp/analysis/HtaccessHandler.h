#pragma once

#include <cstdint>
#include <optional>
#include <string_view>

// What an .htaccess directive makes the web server execute.
//
// BD019 and BD020 match a handler directive's line with a pattern; the questions the pattern
// cannot answer - which file names the directive reaches, and whether the handler it names runs
// them as code - are answered here, from the directive's own arguments and the file around it.
// The engine's context filter is the only caller, and it asks only of a file named `.htaccess`.
//
// The directive grammar and every handler name below are the Apache HTTP Server's, LiteSpeed's
// and cPanel's; the rule's header comment in rules/backdoor.cpp cites each source.
namespace lyxbosa::analysis::htaccess {

// What running a file as a script means for a name with this extension. Ordered: a directive
// that reaches several names is as bad as the worst of them.
enum class ExtensionClass : uint8_t {
    Script,     // a server-side script already: .php and its relatives, CGI, ASP, JSP, SSI
    Document,   // .html and .htm, which hosting providers document parsing as PHP
    Data,       // everything else, including no extension and `.htaccess` itself
};

// What a handler or media-type argument runs.
enum class HandlerKind : uint8_t {
    None,       // not a script handler, or one that shows source rather than running it
    Php,        // mod_php, suPHP, LSPHP, cPanel's ea-php and alt-php names, x-mapp-php
    PhpFpm,     // a `proxy:` handler whose backend is FastCGI
    Cgi,        // cgi-script or fcgid-script: runs the file itself, and only under ExecCGI
};

// Case-insensitive, with or without the leading dot, quotes stripped: mod_mime's own reading.
ExtensionClass classifyExtension(std::string_view extension);

HandlerKind classifyHandler(std::string_view token);

// Whether a final path component names the per-directory configuration file Apache opens.
// Folded, and trailing dots and spaces dropped - see the rule's header for why.
bool isAccessFileName(std::string_view finalComponent);

// The widest class of file name the handler directive whose line starts at `offset` makes the
// server execute as a script, or nothing when it executes nothing: a handler that is not a
// script handler, `SetHandler None`, a CGI handler in a file that does not enable ExecCGI, or
// an AddType/AddHandler with no extension. `content` is the whole file.
std::optional<ExtensionClass> executedClass(std::string_view content, size_t offset);

}  // namespace lyxbosa::analysis::htaccess
