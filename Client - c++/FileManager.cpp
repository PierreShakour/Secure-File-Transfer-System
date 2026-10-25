#include "FileManager.h"
#include <fstream>
#include <stdexcept>
#include <limits>
#include <cstdint>
#include <iomanip>

std::vector<uint8_t> FileManager::readFile(const std::string& path) {
	std::ifstream file(path, std::ios::binary); // try to open the file in binary mode
    if (!file) {
        throw std::runtime_error("Failed to open file: " + path);
    }

	file.seekg(0, std::ios::end); // move the read position to the end of the file
	auto size = file.tellg(); // get the current position, which is the size of the file
    if (size == std::streampos(-1)) {
        throw std::runtime_error("Failed to determine file size: " + path);
    }
	file.seekg(0, std::ios::beg); // move the read position back to the beginning of the file
    if (!file) {
        throw std::runtime_error("Failed to seek file: " + path);
    }

	// Check if the file size exceeds the maximum value for std::streamsize and std::size_t
    if (size > std::numeric_limits<std::streamsize>::max() ||
        static_cast<std::uintmax_t>(static_cast<std::streamoff>(size)) >
        std::numeric_limits<std::size_t>::max()) {
        throw std::runtime_error("File is too large: " + path);
    }

	std::vector<uint8_t> data(static_cast<size_t>(size)); // allocate a vector to hold the file data
    if (!data.empty()) {
		file.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(data.size())); // read the file data into the vector
        if (!file) {
            throw std::runtime_error("Failed to read file: " + path);
        }
    }
	return data; // return the vector containing the file data
}

void FileManager::saveClientInfo(const std::string& name, const std::vector<uint8_t>& clientId, const std::string& privateKeyBase64) {

    if(clientId.size() != 16) {
        throw std::invalid_argument("Client ID must be 16 bytes");
    }

    if (privateKeyBase64.empty()) {
        throw std::invalid_argument("Private key cannot be empty");
    }

    std::ofstream file("me.info");

    if (!file) {
        throw std::runtime_error("Cannot create me.info");
    }

    file << name << '\n';

    for (uint8_t byte : clientId) {
        file << std::hex
            << std::setw(2)
            << std::setfill('0')
            << static_cast<int>(byte);
    }

    file << '\n';
    file << privateKeyBase64 << '\n';
}

std::tuple<std::string, std::vector<uint8_t>, std::string> FileManager::loadClientInfo() {
    std::ifstream file("me.info");

    if (!file) {
        throw std::runtime_error("Cannot open me.info");
    }

    std::string name;
    std::string idHex;

    std::getline(file, name);
    std::getline(file, idHex);

    std::string privateKeyBase64;
    std::getline(file, privateKeyBase64);

    if (privateKeyBase64.empty()) {
        throw std::runtime_error("Missing private key in me.info");
    }

    if (name.empty() || idHex.size() != 32) {
        throw std::runtime_error("Invalid me.info format");
    }

    std::vector<uint8_t> clientId;

    for (size_t i = 0; i < idHex.size(); i += 2) {
        std::string hexByte = idHex.substr(i, 2);
        size_t parsed = 0;
        unsigned long value = std::stoul(hexByte, &parsed, 16);

        if (parsed != 2 || value > 255) {
            throw std::runtime_error("Invalid client ID");
        }

        clientId.push_back(static_cast<uint8_t>(value));
    }

    return { name, clientId, privateKeyBase64 };
}