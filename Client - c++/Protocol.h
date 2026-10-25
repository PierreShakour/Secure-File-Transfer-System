#pragma once

#include <cstdint>
#include <vector>
#include <string>

struct ResponseHeader
{
    uint8_t version;
    uint16_t code;
    uint32_t payloadSize;
};

struct AesResponsePayload {
    std::vector<uint8_t> clientId;
    std::vector<uint8_t> encryptedAesKey;
};

struct FileCrcResponse {
    std::vector<uint8_t> clientId;
    uint32_t encryptedSize;
    std::string fileName;
    uint32_t crc;
};

class Protocol
{
public:
    static constexpr uint8_t VERSION = 3;

    // Request codes
    static constexpr uint16_t REGISTER = 825;
    static constexpr uint16_t SEND_PUBLIC_KEY = 826;
    static constexpr uint16_t RECONNECT = 827;
    static constexpr uint16_t SEND_FILE = 828;

    static constexpr uint16_t VALID_CRC = 900;
    static constexpr uint16_t INVALID_CRC_RESEND = 901;
    static constexpr uint16_t INVALID_CRC_DONE = 902;

    static constexpr size_t CLIENT_ID_SIZE = 16;
    static constexpr size_t REQUEST_HEADER_SIZE = 23;
    static constexpr size_t NAME_SIZE = 255;

    // Response codes
    static constexpr uint16_t REGISTRATION_SUCCESS = 1600;
    static constexpr uint16_t REGISTRATION_FAILED = 1601;
    static constexpr uint16_t SEND_AES = 1602;
    static constexpr uint16_t FILE_RECEIVED_WITH_CRC = 1603;
    static constexpr uint16_t MESSAGE_RECEIVED = 1604;
    static constexpr uint16_t RECONNECT_SUCCESS = 1605;
    static constexpr uint16_t RECONNECT_FAILED = 1606;
    static constexpr uint16_t SERVER_ERROR = 1607;

    static constexpr size_t PUBLIC_KEY_SIZE = 160;
    static constexpr size_t PUBLIC_KEY_REQUEST_PAYLOAD_SIZE = NAME_SIZE + PUBLIC_KEY_SIZE;
    static constexpr size_t ENCRYPTED_AES_KEY_SIZE = 128;

	static std::vector<uint8_t> createRequest(const std::vector<uint8_t>& clientId, uint16_t requestCode, uint32_t payloadSize);
    static std::vector<uint8_t> createRegistrationPayload(const std::string& name);

    static constexpr size_t RESPONSE_HEADER_SIZE = 7;

    static ResponseHeader parseResponseHeader(const std::vector<uint8_t>& data);

	static std::vector<uint8_t> createPublicKeyPayload(const std::string& name, const std::vector<uint8_t>& publicKey);

    static AesResponsePayload parseAesResponsePayload(const std::vector<uint8_t>& payload);

    static std::vector<uint8_t> createFilePayload(const std::string& fileName, const std::vector<uint8_t>& encryptedData, uint32_t totalEncryptedSize, uint32_t originalFileSize, uint16_t packetNumber, uint16_t totalPackets);

    static FileCrcResponse parseFileCrcResponse(const std::vector<uint8_t>& payload);

    static std::vector<uint8_t> createCrcPayload(const std::string& fileName);
};