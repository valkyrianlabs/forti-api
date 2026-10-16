// probe_tls against `openssl s_server` on 127.0.0.1 (no network beyond loopback), with a throwaway
// self-signed certificate for localhost / 127.0.0.1: an untrusted certificate is shown, never used;
// the same certificate pinned as the CA bundle is trusted; a pinned certificate for another name is
// not; and no TLS server is a TransportError. Skipped when there is no openssl command.
#include <gtest/gtest.h>
#include <forti_api/tls.hpp>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <thread>

using namespace fortiapi;
namespace fs = std::filesystem;

namespace {

    std::string openssl_program() {
        for (const char* candidate: {"/usr/bin/openssl", "/opt/homebrew/bin/openssl", "/usr/local/bin/openssl"})
            if (::access(candidate, X_OK) == 0) return candidate;
        return "";
    }

    int run(const std::vector<std::string>& args) {
        pid_t pid = ::fork();
        if (pid == 0) {
            std::vector<char*> argv;
            for (const auto& arg: args) argv.push_back(const_cast<char*>(arg.c_str()));
            argv.push_back(nullptr);
            if (!std::getenv("FORTI_API_TEST_VERBOSE")) {
                std::FILE* null = std::fopen("/dev/null", "w");
                if (null) {
                    ::dup2(::fileno(null), 1);
                    ::dup2(::fileno(null), 2);
                }
            }
            ::execv(argv[0], argv.data());
            ::_exit(127);
        }
        int status = 0;
        ::waitpid(pid, &status, 0);
        return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    }

    unsigned short free_port() {
        int fd = ::socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        socklen_t length = sizeof address;
        if (::bind(fd, reinterpret_cast<sockaddr*>(&address), length) != 0 ||
            ::getsockname(fd, reinterpret_cast<sockaddr*>(&address), &length) != 0)
            throw std::runtime_error("cannot find a free port");
        ::close(fd);
        return ntohs(address.sin_port);
    }

    bool accepting(unsigned short port) {
        int fd = ::socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        address.sin_port = htons(port);
        bool ok = ::connect(fd, reinterpret_cast<sockaddr*>(&address), sizeof address) == 0;
        ::close(fd);
        return ok;
    }

    std::string slurp(const fs::path& path) {
        std::ifstream in(path);
        std::ostringstream text;
        text << in.rdbuf();
        return text.str();
    }

    // A TLS server with a self-signed certificate for localhost and 127.0.0.1.
    class TlsServer {
        pid_t pid_ = -1;

    public:
        fs::path dir, cert;
        unsigned short port = 0;

        explicit TlsServer(const std::string& openssl) {
            dir = fs::temp_directory_path() / std::format("forti-api-tls-{}", ::getpid());
            fs::create_directories(dir);
            cert = dir / "cert.pem";
            if (run({openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=localhost",
                     "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1", "-keyout", (dir / "key.pem").string(),
                     "-out", cert.string()}) != 0)
                throw std::runtime_error("openssl req failed");
            port = free_port();
            pid_ = ::fork();
            if (pid_ == 0) {
                std::FILE* null = std::fopen("/dev/null", "w+");
                if (null) {
                    ::dup2(::fileno(null), 0);
                    ::dup2(::fileno(null), 1);
                    ::dup2(::fileno(null), 2);
                }
                std::string accept = std::to_string(port);   // LibreSSL's s_server takes a port only
                std::string key = (dir / "key.pem").string(), certificate = cert.string();
                ::execl(openssl.c_str(), openssl.c_str(), "s_server", "-www", "-accept", accept.c_str(), "-cert",
                        certificate.c_str(), "-key", key.c_str(), static_cast<char*>(nullptr));
                ::_exit(127);
            }
            for (int i = 0; i < 100 && !accepting(port); ++i) std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }

        ~TlsServer() {
            if (pid_ > 0) {
                ::kill(pid_, SIGTERM);
                ::waitpid(pid_, nullptr, 0);
            }
            std::error_code error;
            fs::remove_all(dir, error);
        }
    };

    Config config_for(unsigned short port) {
        Config config;
        config.host = "localhost";
        config.resolve_ip = "127.0.0.1";   // localhost may resolve to ::1 first (Linux), and s_server listens on both
        config.port = port;
        config.connect_timeout = std::chrono::milliseconds(3000);
        config.api_key = "never-sent";
        return config;
    }

}  // namespace

TEST(Tls, ProbeShowsAnUntrustedCertificateAndTrustsItOncePinned) {
    std::string openssl = openssl_program();
    if (openssl.empty()) GTEST_SKIP() << "no openssl command";
    TlsServer server(openssl);
    ASSERT_TRUE(accepting(server.port)) << "s_server did not start";

    // Not in the system trust store: shown, not trusted.
    TlsProbe untrusted = probe_tls(config_for(server.port));
    EXPECT_FALSE(untrusted.trusted);
    EXPECT_NE(untrusted.verify_code, 0);
    EXPECT_FALSE(untrusted.verify_error.empty());
    ASSERT_EQ(untrusted.chain.size(), 1u);
    auto normalize = [](std::string pem) {
        std::erase(pem, '\r');
        std::erase(pem, '\n');
        return pem;
    };
    EXPECT_EQ(normalize(untrusted.chain[0]), normalize(slurp(server.cert)));
    EXPECT_EQ(untrusted.local_ip, "127.0.0.1");
    EXPECT_EQ(untrusted.peer_ip, "127.0.0.1");

    // The presented certificate pinned as the CA bundle: trusted, for the names it carries.
    fs::path pinned = server.dir / "pinned.pem";
    std::ofstream(pinned) << untrusted.chain[0];
    Config config = config_for(server.port);
    config.ca_bundle = pinned.string();
    TlsProbe trusted = probe_tls(config);
    EXPECT_TRUE(trusted.trusted) << trusted.verify_error;
    EXPECT_EQ(trusted.verify_code, 0);
    EXPECT_EQ(trusted.chain.size(), 1u);

    // The same pin for a name the certificate does not carry: not trusted.
    config.host = "fortigate.test";
    config.resolve_ip = "127.0.0.1";
    TlsProbe other = probe_tls(config);
    EXPECT_FALSE(other.trusted);
    EXPECT_EQ(other.chain.size(), 1u);
}

TEST(Tls, ProbeWithoutATlsServerIsATransportError) {
    Config config = config_for(free_port());
    config.connect_timeout = std::chrono::milliseconds(1000);
    try {
        (void) probe_tls(config);
        FAIL() << "expected TransportError";
    } catch (const TransportError& error) {
        EXPECT_TRUE(error.before_send());
        EXPECT_EQ(error.code(), CURLE_COULDNT_CONNECT);
    }
}
