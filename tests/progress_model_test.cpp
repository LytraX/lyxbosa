#include <gtest/gtest.h>

#include "infrastructure/ProgressModel.h"

using namespace lyxbosa;
using namespace std::chrono_literals;

namespace {

// A fixed origin so every test drives time explicitly rather than sleeping.
constexpr ProgressModel::TimePoint kOrigin{};

ProgressModel::TimePoint at(std::chrono::milliseconds offset) {
    return kOrigin + offset;
}

ScanProgress scanned(size_t files, size_t total, uint64_t bytes = 0) {
    ScanProgress p;
    p.filesScanned = files;
    p.totalFiles = total;
    p.bytesScanned = bytes;
    p.phase = total > 0 ? ScanPhase::Scanning : ScanPhase::Discovering;
    return p;
}

// A scan whose total size is known, which is what makes the ETA size-aware.
ScanProgress sized(size_t files, size_t totalFiles, uint64_t bytes, uint64_t totalBytes) {
    ScanProgress p = scanned(files, totalFiles, bytes);
    p.totalBytes = totalBytes;
    return p;
}

}  // namespace

TEST(ProgressModelTest, PercentIsZeroWhileTotalIsUnknown) {
    ProgressModel model(kOrigin);
    model.update(scanned(500, 0), at(1s));

    EXPECT_FALSE(model.totalKnown());
    EXPECT_EQ(model.percent(), 0);
    EXPECT_DOUBLE_EQ(model.fraction(), 0.0);
}

TEST(ProgressModelTest, PercentTracksTheTotalOnceKnown) {
    ProgressModel model(kOrigin);
    model.update(scanned(250, 1000), at(1s));

    EXPECT_TRUE(model.totalKnown());
    EXPECT_EQ(model.percent(), 25);
}

TEST(ProgressModelTest, PercentIsClampedWhenScannedExceedsTotal) {
    // The concurrent count can lag behind the scan on a tree that is growing.
    ProgressModel model(kOrigin);
    model.update(scanned(1500, 1000), at(1s));

    EXPECT_EQ(model.percent(), 100);
    EXPECT_DOUBLE_EQ(model.fraction(), 1.0);
}

TEST(ProgressModelTest, EmptyScanDoesNotDivideByZero) {
    ProgressModel model(kOrigin);
    model.update(scanned(0, 0), at(1s));

    EXPECT_EQ(model.percent(), 0);
    EXPECT_FALSE(model.eta().has_value());
    EXPECT_DOUBLE_EQ(model.filesPerSecond(), 0.0);
}

TEST(ProgressModelTest, NoEtaWhileTotalIsUnknown) {
    ProgressModel model(kOrigin);
    model.update(scanned(100, 0), at(1s));

    EXPECT_FALSE(model.eta().has_value());
}

TEST(ProgressModelTest, EtaReflectsASteadyRate) {
    ProgressModel model(kOrigin);

    // 100 files/second for four seconds, sampled every half second.
    for (int i = 1; i <= 8; ++i) {
        const auto ms = std::chrono::milliseconds(i * 500);
        model.update(scanned(static_cast<size_t>(i * 50), 1000), at(ms));
    }

    ASSERT_TRUE(model.eta().has_value());
    // 600 files left at ~100/s. Allow slack for the smoothing.
    EXPECT_GE(model.eta()->count(), 4);
    EXPECT_LE(model.eta()->count(), 8);
    EXPECT_NEAR(model.filesPerSecond(), 100.0, 20.0);
}

TEST(ProgressModelTest, EtaIsZeroWhenEverythingIsScanned) {
    ProgressModel model(kOrigin);
    model.update(scanned(1000, 1000), at(2s));

    ASSERT_TRUE(model.eta().has_value());
    EXPECT_EQ(model.eta()->count(), 0);
}

TEST(ProgressModelTest, NoEtaOnceFinished) {
    ProgressModel model(kOrigin);
    auto p = scanned(400, 1000);
    p.phase = ScanPhase::Finished;
    model.update(p, at(2s));

    EXPECT_FALSE(model.eta().has_value());
}

TEST(ProgressModelTest, FallsBackToTheOverallAverageBeforeTheFirstSample) {
    ProgressModel model(kOrigin);
    // Inside the sampling window, so no smoothed rate exists yet.
    model.update(scanned(50, 1000), at(100ms));

    EXPECT_NEAR(model.filesPerSecond(), 500.0, 1.0);
}

TEST(ProgressModelTest, TracksElapsedAndThroughput) {
    ProgressModel model(kOrigin);
    for (int i = 1; i <= 4; ++i) {
        model.update(scanned(static_cast<size_t>(i * 100), 1000,
                             static_cast<uint64_t>(i) * 1024 * 1024),
                     at(std::chrono::milliseconds(i * 1000)));
    }

    EXPECT_EQ(model.elapsed().count(), 4000);
    EXPECT_GT(model.bytesPerSecond(), 0.0);
}

TEST(FormatDurationTest, PicksAReadableUnit) {
    EXPECT_EQ(formatDuration(std::chrono::seconds{0}), "0s");
    EXPECT_EQ(formatDuration(std::chrono::seconds{45}), "45s");
    EXPECT_EQ(formatDuration(std::chrono::seconds{134}), "2m 14s");
    EXPECT_EQ(formatDuration(std::chrono::seconds{3900}), "1h 05m");
    EXPECT_EQ(formatDuration(std::chrono::seconds{-5}), "0s");
}

TEST(FormatBytesTest, PicksAReadableUnit) {
    EXPECT_EQ(formatBytes(512), "512 B");
    EXPECT_EQ(formatBytes(1024), "1.0 KB");
    EXPECT_EQ(formatBytes(1536), "1.5 KB");
    EXPECT_EQ(formatBytes(5ULL * 1024 * 1024), "5.0 MB");
    EXPECT_EQ(formatBytes(3ULL * 1024 * 1024 * 1024), "3.0 GB");
}

// ---------------------------------------------------------------------------
// Size-aware progress
//
// The bug these cover: a tree of 100 one-line stubs followed by one 40 MB file
// is 99% done by file count after a second, so the ETA collapses to almost
// nothing and then explodes when the big file starts. Weighting by work keeps
// both the bar and the estimate honest.
// ---------------------------------------------------------------------------

TEST(ProgressModelTest, PercentIsWeightedByBytesNotFileCount) {
    ProgressModel model(kOrigin);

    // 100 tiny files done out of 101; the last one is 40 MB.
    constexpr uint64_t kBig = 40ull * 1024 * 1024;
    model.update(sized(100, 101, 100 * 200, 100 * 200 + kBig), at(1s));

    // By file count this would read 99%.
    EXPECT_LT(model.percent(), 10)
        << "the remaining 40 MB is almost all of the work";
}

TEST(ProgressModelTest, EtaDoesNotCollapseBeforeALargeFile) {
    ProgressModel model(kOrigin);

    constexpr uint64_t kTiny = 200;
    constexpr uint64_t kBig = 40ull * 1024 * 1024;
    const uint64_t totalBytes = 100 * kTiny + kBig;

    // Steady progress through the stubs.
    model.update(sized(50, 101, 50 * kTiny, totalBytes), at(500ms));
    model.update(sized(100, 101, 100 * kTiny, totalBytes), at(1s));

    const auto before = model.eta();
    ASSERT_TRUE(before.has_value());

    // The big file is still entirely ahead, so the estimate must reflect it
    // rather than reporting "almost done".
    EXPECT_GT(before->count(), 1)
        << "ETA ignored 40 MB of remaining work";
}

TEST(ProgressModelTest, EtaTracksThroughputThroughAMixedTree) {
    ProgressModel model(kOrigin);

    // 10 MB total, arriving at a steady 1 MB/s. Whatever the file sizes, the
    // estimate should converge on the time the remaining bytes will take.
    constexpr uint64_t kMB = 1024 * 1024;
    model.update(sized(1, 10, 1 * kMB, 10 * kMB), at(1s));
    model.update(sized(2, 10, 2 * kMB, 10 * kMB), at(2s));
    model.update(sized(3, 10, 3 * kMB, 10 * kMB), at(3s));

    const auto eta = model.eta();
    ASSERT_TRUE(eta.has_value());
    // 7 MB left at ~1 MB/s. Allow for the exponential smoothing warming up.
    EXPECT_GE(eta->count(), 4);
    EXPECT_LE(eta->count(), 10);
}

TEST(ProgressModelTest, PerFileOverheadDominatesForTinyFiles) {
    ProgressModel model(kOrigin);

    // 4,000 files averaging 25 bytes: the bytes are noise, the per-file cost is
    // the whole job. Half done by count must read as roughly half done.
    model.update(sized(2000, 4000, 2000 * 25, 4000 * 25), at(1s));

    EXPECT_GE(model.percent(), 45);
    EXPECT_LE(model.percent(), 55);
}

TEST(ProgressModelTest, FallsBackToFileCountWhenSizesAreUnknown) {
    ProgressModel model(kOrigin);

    // --no-precount, or a walker that could not stat: totalBytes stays 0 and the
    // model must still behave, weighting every file equally.
    model.update(scanned(250, 1000), at(1s));
    EXPECT_EQ(model.percent(), 25);
}
