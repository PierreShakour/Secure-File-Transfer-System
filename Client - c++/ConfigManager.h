#pragma once

#include <string>
#include <vector>

struct ClientConfig
{
    std::string ip;
    int port;
    std::string clientName;
    std::vector<std::string> files;
};

class ConfigManager
{
public:
    static ClientConfig loadConfig(const std::string& filePath);
};