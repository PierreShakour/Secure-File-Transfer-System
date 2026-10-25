#include "ConfigManager.h"

#include <charconv>
#include <cctype>
#include <fstream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <string_view>

namespace {
    class ConfigParser {
    public:
        explicit ConfigParser(std::string_view input) : input_(input) {}

        ClientConfig parse() {
            ClientConfig config{};
            bool hasServer = false;
            bool hasFiles = false;

            expect('{');
            if (!consume('}')) {
                do {
                    const std::string key = parseString();
                    expect(':');
                    if (key == "server" && !hasServer) {
                        parseServer(config);
                        hasServer = true;
                    }
                    else if (key == "files" && !hasFiles) {
                        config.files = parseFiles();
                        hasFiles = true;
                    }
                    else {
                        fail("unknown or duplicate top-level field: " + key);
                    }
                } while (consume(','));
                expect('}');
            }
            skipWhitespace();
            if (pos_ != input_.size()) fail("trailing characters");
            if (!hasServer || !hasFiles) fail("missing server or files field");
            if (config.clientName.empty() || config.clientName.size() > 100)
                fail("client name must contain 1 to 100 characters");
            if (config.ip.empty()) fail("server IP must not be empty");
            return config;
        }

    private:
        std::string_view input_;
        std::size_t pos_ = 0;

        [[noreturn]] void fail(const std::string& message) const {
            throw std::runtime_error("Invalid transfer.json at byte " +
                std::to_string(pos_) + ": " + message);
        }

        void skipWhitespace() {
            while (pos_ < input_.size() &&
                (input_[pos_] == ' ' || input_[pos_] == '\t' ||
                    input_[pos_] == '\n' || input_[pos_] == '\r')) ++pos_;
        }

        bool consume(char ch) {
            skipWhitespace();
            if (pos_ < input_.size() && input_[pos_] == ch) {
                ++pos_;
                return true;
            }
            return false;
        }

        void expect(char ch) {
            if (!consume(ch)) fail(std::string("expected '") + ch + "'");
        }

        unsigned hexDigit() {
            if (pos_ >= input_.size()) fail("incomplete Unicode escape");
            const char ch = input_[pos_++];
            if (ch >= '0' && ch <= '9') return ch - '0';
            if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
            if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
            fail("invalid Unicode escape");
        }

        unsigned unicodeUnit() {
            unsigned value = 0;
            for (int i = 0; i < 4; ++i) value = (value << 4) | hexDigit();
            return value;
        }

        static void appendUtf8(std::string& result, unsigned codepoint) {
            if (codepoint <= 0x7F) {
                result += static_cast<char>(codepoint);
            }
            else if (codepoint <= 0x7FF) {
                result += static_cast<char>(0xC0 | (codepoint >> 6));
                result += static_cast<char>(0x80 | (codepoint & 0x3F));
            }
            else if (codepoint <= 0xFFFF) {
                result += static_cast<char>(0xE0 | (codepoint >> 12));
                result += static_cast<char>(0x80 | ((codepoint >> 6) & 0x3F));
                result += static_cast<char>(0x80 | (codepoint & 0x3F));
            }
            else {
                result += static_cast<char>(0xF0 | (codepoint >> 18));
                result += static_cast<char>(0x80 | ((codepoint >> 12) & 0x3F));
                result += static_cast<char>(0x80 | ((codepoint >> 6) & 0x3F));
                result += static_cast<char>(0x80 | (codepoint & 0x3F));
            }
        }

        std::string parseString() {
            expect('"');
            std::string result;
            bool closed = false;
            while (pos_ < input_.size()) {
                const unsigned char ch = static_cast<unsigned char>(input_[pos_++]);
                if (ch == '"') { closed = true; break; }
                if (ch < 0x20) fail("unescaped control character");
                if (ch != '\\') { result += static_cast<char>(ch); continue; }
                if (pos_ == input_.size()) fail("incomplete string escape");
                switch (input_[pos_++]) {
                case '"': result += '"'; break;
                case '\\': result += '\\'; break;
                case '/': result += '/'; break;
                case 'b': result += '\b'; break;
                case 'f': result += '\f'; break;
                case 'n': result += '\n'; break;
                case 'r': result += '\r'; break;
                case 't': result += '\t'; break;
                case 'u': {
                    unsigned cp = unicodeUnit();
                    if (cp >= 0xD800 && cp <= 0xDBFF) {
                        if (pos_ + 2 > input_.size() || input_[pos_] != '\\' ||
                            input_[pos_ + 1] != 'u') fail("missing low surrogate");
                        pos_ += 2;
                        const unsigned low = unicodeUnit();
                        if (low < 0xDC00 || low > 0xDFFF) fail("invalid low surrogate");
                        cp = 0x10000 + ((cp - 0xD800) << 10) + (low - 0xDC00);
                    }
                    else if (cp >= 0xDC00 && cp <= 0xDFFF) {
                        fail("unexpected low surrogate");
                    }
                    appendUtf8(result, cp);
                    break;
                }
                default: fail("invalid string escape");
                }
            }
            if (!closed) fail("unterminated string");
            return result;
        }

        int parsePort() {
            skipWhitespace();
            const std::size_t start = pos_;
            if (pos_ == input_.size() || input_[pos_] < '0' || input_[pos_] > '9')
                fail("port must be an integer");
            if (input_[pos_] == '0') ++pos_;
            else while (pos_ < input_.size() && input_[pos_] >= '0' &&
                input_[pos_] <= '9') ++pos_;
            int port = 0;
            const auto result = std::from_chars(input_.data() + start,
                input_.data() + pos_, port);
            if (result.ec != std::errc{} || port < 1 || port > 65535)
                fail("port must be between 1 and 65535");
            return port;
        }

        std::vector<std::string> parseFiles() {
            std::vector<std::string> files;
            expect('[');
            if (!consume(']')) {
                do {
                    std::string filename = parseString();
                    if (filename.empty()) fail("file path must not be empty");
                    files.push_back(std::move(filename));
                } while (consume(','));
                expect(']');
            }
            return files;
        }

        void parseServer(ClientConfig& config) {
            bool hasIp = false, hasPort = false, hasClient = false;
            expect('{');
            if (!consume('}')) {
                do {
                    const std::string key = parseString();
                    expect(':');
                    if (key == "ip" && !hasIp) {
                        config.ip = parseString();
                        hasIp = true;
                    }
                    else if (key == "port" && !hasPort) {
                        config.port = parsePort();
                        hasPort = true;
                    }
                    else if (key == "client" && !hasClient) {
                        config.clientName = parseString();
                        hasClient = true;
                    }
                    else {
                        fail("unknown or duplicate server field: " + key);
                    }
                } while (consume(','));
                expect('}');
            }
            if (!hasIp || !hasPort || !hasClient)
                fail("server must contain ip, port, and client");
        }
    };

} // namespace

ClientConfig ConfigManager::loadConfig(const std::string& filePath) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file) throw std::runtime_error("Cannot open configuration file: " + filePath);

    // The configuration is small; cap input size to avoid unbounded allocations.
    std::string data;
    data.reserve(4096);
    char buffer[4096];
    while (file.read(buffer, sizeof(buffer)) || file.gcount() > 0) {
        if (data.size() + static_cast<std::size_t>(file.gcount()) > 1024 * 1024)
            throw std::runtime_error("Configuration file is too large");
        data.append(buffer, static_cast<std::size_t>(file.gcount()));
    }
    if (file.bad()) throw std::runtime_error("Error reading configuration file");
    return ConfigParser(data).parse();
}
