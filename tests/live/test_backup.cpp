// Configuration backup (read-only): GET monitor/system/config/backup?scope=global, into memory only.
//
// The backup is the device's whole configuration, secrets included. These tests never write it to
// disk, print it or log it (assertions report sizes and booleans, never content), and overwrite every
// buffer that held it before releasing it.
#include <gtest/gtest.h>
#include <forti_api/monitor.hpp>

#include <string>
#include <string_view>

using namespace fortiapi;

namespace {

    // The first line of every FortiOS configuration file.
    constexpr std::string_view config_header = "#config-version=";

    Query global() { return Query().set("scope", "global"); }

    class Scrubbed {
        std::string& text;

    public:
        explicit Scrubbed(std::string& text) : text(text) {}
        Scrubbed(const Scrubbed&) = delete;
        Scrubbed& operator=(const Scrubbed&) = delete;
        ~Scrubbed() { detail::wipe(text); }
    };

}  // namespace

TEST(ConfigBackup, DownloadsTheGlobalConfigurationIntoMemory) {
    auto backup = Monitor::download("system/config/backup", global());
    Scrubbed scrub{backup.body};
    RecordProperty("content_type", backup.content_type);
    EXPECT_GE(backup.http_status, 200);
    EXPECT_LT(backup.http_status, 300);
    ASSERT_GT(backup.bytes, 0u);
    EXPECT_EQ(backup.bytes, backup.body.size());
    EXPECT_TRUE(backup.body.starts_with(config_header));
}

TEST(ConfigBackup, StopsAtTheConfiguredLimit) {
    DownloadOptions options;
    options.max_bytes = 1024;   // any real configuration is larger
    EXPECT_THROW(Monitor::download("system/config/backup", global(), options), SizeLimitError);
}

TEST(ConfigBackup, StreamsToASinkWithoutBuffering) {
    std::size_t received = 0;
    std::string head;   // only the first bytes, to check the header line
    Scrubbed scrub{head};
    DownloadOptions options;
    options.sink = [&](std::string_view chunk) {
        received += chunk.size();
        if (head.size() < config_header.size()) head.append(chunk.substr(0, config_header.size() - head.size()));
    };
    auto backup = Monitor::download("system/config/backup", global(), options);
    EXPECT_TRUE(backup.body.empty());
    EXPECT_GT(received, 0u);
    EXPECT_EQ(backup.bytes, received);
    EXPECT_TRUE(head == config_header);
}
