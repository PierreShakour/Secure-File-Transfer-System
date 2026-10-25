#pragma once

#include <vector>
#include <string>
#include <cstdint>
#include <string>
#include <utility>
#include <tuple>

class FileManager
{
public:
    static std::vector<uint8_t> readFile(const std::string& path);
    static void saveClientInfo(const std::string& name, const std::vector<uint8_t>& clientId, const std::string& privateKeyBase64);
    static std::tuple<std::string, std::vector<uint8_t>, std::string> loadClientInfo();
};
