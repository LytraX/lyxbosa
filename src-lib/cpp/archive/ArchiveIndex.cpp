#include "ArchiveIndex.h"

#include "core/FileWalker.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <map>
#include <span>

namespace lyxbosa::archive {

namespace {

std::string_view finalComponentOf(std::string_view name) {
    const size_t slash = name.find_last_of('/');
    return slash == std::string_view::npos ? name : name.substr(slash + 1);
}

// Read as FileWalker::hasNoExtension() reads a name, so a leading dot starts no extension:
// `.png` is a name without one, not a PNG.
std::string_view extensionOf(std::string_view name) {
    const std::string_view base = finalComponentOf(name);
    if (FileWalker::hasNoExtension(base)) {
        return {};
    }
    const size_t dot = base.find_last_of('.');
    return base.substr(dot + 1);
}

bool equalsIgnoreCase(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(a[i])) !=
            std::tolower(static_cast<unsigned char>(b[i]))) {
            return false;
        }
    }
    return true;
}

bool extensionIn(std::string_view name, std::span<const std::string_view> set) {
    const std::string_view ext = extensionOf(name);
    if (ext.empty()) return false;
    for (std::string_view candidate : set) {
        if (equalsIgnoreCase(ext, candidate)) return true;
    }
    return false;
}

// Server-side code. The same breadth as the loose-file include list: a scanner
// that trusts extensions has already lost, but inside an archive the extension
// is all there is until the member is inflated, and inflating everything is the
// cost this list exists to avoid.
constexpr std::string_view kScriptExtensions[] = {
    "php", "php3", "php4", "php5", "php7", "php8", "phps", "pht", "phtm", "phtml",
    "phar", "inc", "tpl", "ctp", "module", "install", "engine", "theme", "profile",
    "pl", "pm", "cgi", "py", "rb", "lua", "sh", "bash", "ksh", "zsh",
    "jsp", "jspx", "asp", "aspx", "ashx", "asmx", "cfm", "ps1", "suspected",
};

constexpr std::string_view kMarkupExtensions[] = {
    "js", "mjs", "cjs", "jsx", "ts", "vue", "html", "htm", "xhtml", "shtml",
    "css", "svg",
};

constexpr std::string_view kMediaExtensions[] = {
    "jpg", "jpeg", "jpe", "jfif", "png", "gif", "bmp", "webp", "avif", "ico",
    "tif", "tiff", "psd", "tga", "jp2", "jpx",
    "mp4", "m4v", "avi", "mpg", "mpeg", "mov", "wmv", "mkv", "webm", "flv",
    "mp3", "wav", "ogg", "ogv", "m4a", "wma", "flac",
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
    "ttf", "otf", "eot", "woff", "woff2",
};

// Directories that are writable by the application on every platform this
// scanner has met: WordPress wp-content/uploads, OpenCart image/catalog,
// Magento pub/media and var, PrestaShop img. A script in one of these is not
// where code belongs.
constexpr std::string_view kHotSegments[] = {
    "uploads", "upload", "files", "media", "images", "image", "img", "assets",
    "cache", "tmp", "temp", "var", "userfiles", "attachments", "thumbs",
    "gallery", "avatars", "backup", "backups",
};

// Credential files identified by their full path. A bare basename is not a
// marker: matching "settings.php" anywhere hits wp-admin/network/settings.php,
// a WordPress core admin page, and reports six credential files in an archive
// that has one.
constexpr std::string_view kQualifiedCredentials[] = {
    "sites/default/settings.php",
    "app/etc/env.php",
    "app/etc/local.xml",
    "config/settings.inc.php",
    "app/config/parameters.php",
    "includes/configure.php",
};

// These genuinely live at the root of the site, so proximity to the archive root
// is what qualifies them.
constexpr std::string_view kRootCredentials[] = {
    "wp-config.php", "configuration.php", ".env",
};
constexpr size_t kRootCredentialDepth = 2;

struct PlatformMarker {
    std::string_view marker;
    std::string_view platform;
};

// Distribution files, not config files. Config files do not exist in a stock
// distribution - they are written at install, and wp-config-sample.php ships
// instead - so a marker set built from them found nothing on stock WordPress and
// Joomla and called a stock Magento 2 tree "Joomla".
constexpr PlatformMarker kPlatformMarkers[] = {
    {"wp-includes/version.php", "WordPress"},
    {"wp-login.php", "WordPress"},
    {"libraries/src/Factory.php", "Joomla"},
    {"administrator/manifests/files/joomla.xml", "Joomla"},
    {"bin/magento", "Magento 2"},
    {"app/etc/di.xml", "Magento 2"},
    {"app/Mage.php", "Magento 1"},
    {"classes/PrestaShopAutoload.php", "PrestaShop"},
    {"config/defines.inc.php", "PrestaShop"},
    {"system/startup.php", "OpenCart"},
    {"catalog/controller/common/home.php", "OpenCart"},
    {"core/lib/Drupal.php", "Drupal 8+"},
    {"includes/bootstrap.inc", "Drupal 7"},
    {"concrete/dispatcher.php", "Concrete"},
    {"vendor/typo3/", "TYPO3"},
};

// True when `name` is `suffix`, or ends with "/" + `suffix`. Anchoring on the
// separator is what keeps "wp-login.php" from matching "not-wp-login.php".
bool endsWithSegment(std::string_view name, std::string_view suffix) {
    if (name.size() < suffix.size()) return false;
    if (name.compare(name.size() - suffix.size(), suffix.size(), suffix) != 0) {
        return false;
    }
    return name.size() == suffix.size() || name[name.size() - suffix.size() - 1] == '/';
}

bool containsDirectory(std::string_view name, std::string_view dirPrefix) {
    const size_t at = name.find(dirPrefix);
    if (at == std::string_view::npos) return false;
    return at == 0 || name[at - 1] == '/';
}

size_t depthOf(std::string_view name) {
    return static_cast<size_t>(std::count(name.begin(), name.end(), '/'));
}

bool isSqlDump(std::string_view name) {
    return name.ends_with(".sql") || name.ends_with(".sql.gz") ||
           name.ends_with(".dump") || name.ends_with(".sql.bz2") ||
           name.ends_with(".sql.zip");
}

}  // namespace

std::string normalizeMemberName(std::string_view raw) {
    std::string out;
    out.reserve(raw.size());
    for (char c : raw) {
        out += (c == '\\') ? '/' : c;
    }

    size_t start = 0;
    while (start + 1 < out.size() && out[start] == '.' && out[start + 1] == '/') {
        start += 2;
    }
    while (start < out.size() && out[start] == '/') {
        ++start;
    }

    return out.substr(start);
}

std::string_view memberFilterName(std::string_view stored) {
    size_t start = 0;
    while (true) {
        if (stored.substr(start).starts_with("./")) {
            start += 2;
        } else if (start < stored.size() && stored[start] == '/') {
            ++start;
        } else {
            break;
        }
    }
    return stored.substr(start);
}

bool namesUseOnlyBackslashes(const std::vector<Entry>& entries) {
    // No forward slash but a directory entry's trailing one leaves a backslash as the only
    // separator any name can hold, which is the whole definition. An archive whose names hold
    // no separator at all passes too, and reading it split on both changes nothing.
    for (const auto& entry : entries) {
        std::string_view name = entry.name;
        if (!name.empty() && name.back() == '/') {
            name.remove_suffix(1);   // a directory entry's marker, not a separator
        }
        if (name.find('/') != std::string_view::npos) {
            return false;
        }
    }
    return true;
}

bool isContainerMetadata(std::string_view name) {
    if (name.starts_with("__MACOSX/") || name.find("/__MACOSX/") != std::string_view::npos) {
        return true;
    }

    const std::string_view base = finalComponentOf(name);
    return base.starts_with("._") || base == ".DS_Store" || base == "Thumbs.db";
}

bool isScriptName(std::string_view name) {
    if (extensionIn(name, kScriptExtensions)) return true;

    // No extension at all: webshells routinely have none, and so do the CGI
    // scripts that live in a real cgi-bin. Read as `!ext` reads a file's name, so a member
    // named `.DS_Store` or `._shell` is extension-less exactly as the file of that name is.
    // An empty final component has none either - the whole name of a member stored as `\`
    // or as nothing, which the extractors that write one to disk write as a file without one.
    return FileWalker::hasNoExtension(finalComponentOf(name));
}

bool isMarkupName(std::string_view name) {
    return extensionIn(name, kMarkupExtensions);
}

bool isMediaName(std::string_view name) {
    return extensionIn(name, kMediaExtensions);
}

Bucket classifyMember(std::string_view name) {
    if (isScriptName(name)) {
        size_t from = 0;
        while (from < name.size()) {
            const size_t slash = name.find('/', from);
            if (slash == std::string_view::npos) break;
            const std::string_view segment = name.substr(from, slash - from);
            for (std::string_view hot : kHotSegments) {
                if (equalsIgnoreCase(segment, hot)) {
                    return Bucket::HotScript;
                }
            }
            from = slash + 1;
        }
        return Bucket::Script;
    }

    return isMarkupName(name) ? Bucket::Markup : Bucket::Other;
}

void IndexSummary::observe(std::string_view rawName) {
    const std::string name = normalizeMemberName(rawName);
    if (name.empty() || name.back() == '/') {
        return;   // a directory entry describes no content
    }
    if (isContainerMetadata(name)) {
        // A zip written on a Mac carries a "._x.php" for every x.php. Counting
        // them would double the PHP tally that decides whether this is a site
        // backup, from files that hold no PHP at all.
        //
        // A name test, and not a byte test, for two reasons. There are no bytes here: this
        // tally is taken from the index before any member is read - a zip's whole index
        // first, a tar's header in front of its bytes - and a member the policy leaves shut
        // is never read at all. And a name test here cannot be turned against the finding.
        // Leaving a name out can only withhold, and every reading below is a name as well, so
        // whoever writes the archive withholds ARC001 and ARC002 by renaming `wp-config.php`
        // or `wp-login.php` to anything, with or without this line. A metadata-looking name
        // planted beside a site's own files withholds nothing, because each of those files is
        // still counted, and adds nothing, because it is left out.
        return;
    }

    ++entries;

    if (name.ends_with(".php") || name.ends_with(".phtml") || name.ends_with(".inc")) {
        ++phpEntries;
    }

    if (isSqlDump(name)) {
        ++sqlDumps;
    }

    bool credential = false;
    for (std::string_view marker : kQualifiedCredentials) {
        if (endsWithSegment(name, marker)) {
            credential = true;
            break;
        }
    }
    if (!credential && depthOf(name) <= kRootCredentialDepth) {
        for (std::string_view marker : kRootCredentials) {
            if (endsWithSegment(name, marker)) {
                credential = true;
                break;
            }
        }
    }
    // The cap bounds what the report quotes, not what is detected: one hit is
    // already enough to make the archive a critical exposure.
    if (credential && credentials.size() < kMaxCredentialsListed) {
        credentials.push_back(name);
    }

    for (const auto& marker : kPlatformMarkers) {
        const bool hit = marker.marker.back() == '/'
            ? containsDirectory(name, marker.marker)
            : endsWithSegment(name, marker.marker);
        if (hit) {
            platformHits.emplace_back(marker.platform);
        }
    }
}

std::string IndexSummary::platform() const {
    if (platformHits.empty()) {
        return {};
    }

    // Most markers wins. A single shared filename cannot outvote a distribution
    // that put two of its own in the archive.
    std::map<std::string, size_t> tally;
    for (const auto& hit : platformHits) {
        ++tally[hit];
    }

    const auto best = std::max_element(
        tally.begin(), tally.end(),
        [](const auto& a, const auto& b) { return a.second < b.second; });
    return best->first;
}

}  // namespace lyxbosa::archive
