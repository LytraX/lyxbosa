#include "ZipReader.h"

#include <algorithm>
#include <zip.h>

namespace lyxbosa::archive {

ZipReader::~ZipReader() {
    if (archive_) {
        zip_discard(archive_);   // read-only, so nothing is ever written back
    }
}

std::unique_ptr<ZipReader> ZipReader::openFile(const std::filesystem::path& path) {
#ifdef _WIN32
    // The wide path, handed to libzip as a wide path. zip_open() on Windows reads its narrow
    // argument as UTF-8 - lib/zip_source_file_win32_utf8.c - and it was being given
    // path::string(), which is the ANSI code page: so an archive whose own name held any
    // character past ASCII could not be opened even when the conversion succeeded, and
    // path::string() threw when it did not. A Greek-named backup on a Greek host was
    // reported unreadable and nothing inside it was scanned. Converting to UTF-8 for libzip
    // to convert back would also work, and would lose an unpaired surrogate on the way.
    zip_error_t error;
    zip_error_init(&error);
    zip_source_t* source = zip_source_win32w_create(path.c_str(), 0, ZIP_LENGTH_TO_END, &error);
    if (!source) {
        zip_error_fini(&error);
        return nullptr;
    }
    zip* za = zip_open_from_source(source, ZIP_RDONLY, &error);
    if (!za) {
        zip_source_free(source);
        zip_error_fini(&error);
        return nullptr;
    }
    zip_error_fini(&error);
#else
    int err = 0;
    zip* za = zip_open(path.c_str(), ZIP_RDONLY, &err);
    if (!za) {
        return nullptr;
    }
#endif

    std::unique_ptr<ZipReader> reader(new ZipReader());
    reader->archive_ = za;
    reader->loadIndex();
    return reader;
}

std::unique_ptr<ZipReader> ZipReader::openBuffer(std::string_view bytes) {
    zip_error_t error;
    zip_error_init(&error);

    // freep = 0: the buffer belongs to the caller. Nothing is copied, which is
    // the point - a nested archive is already sitting in a bounded buffer.
    zip_source_t* source = zip_source_buffer_create(bytes.data(), bytes.size(), 0, &error);
    if (!source) {
        zip_error_fini(&error);
        return nullptr;
    }

    zip* za = zip_open_from_source(source, ZIP_RDONLY, &error);
    if (!za) {
        zip_source_free(source);
        zip_error_fini(&error);
        return nullptr;
    }
    zip_error_fini(&error);

    std::unique_ptr<ZipReader> reader(new ZipReader());
    reader->archive_ = za;
    reader->loadIndex();
    return reader;
}

void ZipReader::loadIndex() {
    const zip_int64_t count = zip_get_num_entries(archive_, 0);
    if (count <= 0) {
        return;
    }

    auto total = static_cast<size_t>(count);
    if (total > kMaxEntries) {
        total = kMaxEntries;
        indexTruncated_ = true;
    }

    entries_.reserve(total);
    indices_.reserve(total);

    for (size_t i = 0; i < total; ++i) {
        zip_stat_t st;
        zip_stat_init(&st);
        if (zip_stat_index(archive_, static_cast<zip_uint64_t>(i), 0, &st) != 0) {
            indexTruncated_ = true;
            continue;
        }

        Entry entry;
        entry.name = st.name ? st.name : "";
        entry.size = (st.valid & ZIP_STAT_SIZE) ? st.size : 0;
        entry.compressedSize = (st.valid & ZIP_STAT_COMP_SIZE) ? st.comp_size : 0;
        entry.directory = !entry.name.empty() && entry.name.back() == '/';

        // The host byte of "version made by", per entry: one archive can hold entries two
        // writers added. An entry whose attributes cannot be read keeps the backslash as a
        // character, which is the reading that raises FN002 rather than the one that hides it.
        zip_uint8_t host = 0;
        zip_uint32_t attributes = 0;
        if (zip_file_get_external_attributes(archive_, static_cast<zip_uint64_t>(i), 0, &host,
                                             &attributes) == 0) {
            entry.backslashIsSeparator = host == ZIP_OPSYS_DOS ||
                                         host == ZIP_OPSYS_WINDOWS_NTFS ||
                                         host == ZIP_OPSYS_VFAT;
        }

        entries_.push_back(std::move(entry));
        indices_.push_back(static_cast<uint64_t>(i));
    }
}

bool ZipReader::read(size_t index, std::string& out, uint64_t maxBytes) {
    out.clear();
    if (index >= indices_.size()) {
        return false;
    }

    zip_file_t* file = zip_fopen_index(archive_, indices_[index], 0);
    if (!file) {
        return false;   // encrypted, or a member the index lied about
    }

    // The declared size is a claim, not a fact, so the read is bounded by the
    // caller's cap rather than by what the header says. 42.zip is 42 KB of
    // headers claiming 4.5 PB of content.
    const uint64_t limit = maxBytes > 0 ? maxBytes : entries_[index].size;
    out.reserve(static_cast<size_t>(std::min<uint64_t>(limit, entries_[index].size)));

    char buffer[64 * 1024];
    uint64_t total = 0;
    bool ok = true;

    while (total < limit) {
        const zip_uint64_t want = std::min<uint64_t>(sizeof(buffer), limit - total);
        const zip_int64_t got = zip_fread(file, buffer, want);
        if (got < 0) {
            ok = false;
            break;
        }
        if (got == 0) {
            break;   // end of member
        }
        out.append(buffer, static_cast<size_t>(got));
        total += static_cast<uint64_t>(got);
    }

    zip_fclose(file);
    if (!ok) {
        out.clear();
    }
    return ok;
}

}  // namespace lyxbosa::archive
