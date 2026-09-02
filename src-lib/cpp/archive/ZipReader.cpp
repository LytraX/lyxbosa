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
    int err = 0;
    zip* za = zip_open(path.string().c_str(), ZIP_RDONLY, &err);
    if (!za) {
        return nullptr;
    }

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
