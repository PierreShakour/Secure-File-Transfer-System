#include "Protocol.h"
#include <stdexcept>
#include <iostream>
#include <string>
#include <algorithm>

std::vector<uint8_t> Protocol::createRequest(const std::vector<uint8_t>& clientId, uint16_t requestCode, uint32_t payloadSize)
{
    if (clientId.size() != CLIENT_ID_SIZE)
        throw std::invalid_argument("Client ID must be " +  std::to_string(CLIENT_ID_SIZE) + " bytes long.");

    std::vector<uint8_t> request;

    // Client ID - 16 bytes
    request.insert(request.end(), clientId.begin(), clientId.end());

    // Version - 1 byte
    request.push_back(VERSION);

    // Request code - 2 bytes, little-endian
    request.push_back(static_cast<uint8_t>(requestCode & 0xFF));
    request.push_back(static_cast<uint8_t>((requestCode >> 8) & 0xFF));

    // Payload size - 4 bytes, little-endian
    request.push_back(static_cast<uint8_t>(payloadSize & 0xFF));
    request.push_back(static_cast<uint8_t>((payloadSize >> 8) & 0xFF));
    request.push_back(static_cast<uint8_t>((payloadSize >> 16) & 0xFF));
    request.push_back(static_cast<uint8_t>((payloadSize >> 24) & 0xFF));

    return request;
}

std::vector<uint8_t> Protocol::createRegistrationPayload(const std::string& name) {
	// the name must be 255 characters or less including the null terminator, so we check for 254 characters or less
    if (name.size() > NAME_SIZE - 1) {
		throw std::invalid_argument("Name must be 254 characters or less.");
    }
    std::vector<uint8_t> registrationName(NAME_SIZE, 0);
    std::copy(name.begin(), name.end(), registrationName.begin());
    return registrationName;
}

ResponseHeader Protocol::parseResponseHeader(const std::vector<uint8_t>& data) {
    if (data.size() != RESPONSE_HEADER_SIZE)
    {
        throw std::invalid_argument("Invalid response header size");
    }
    uint16_t code =
        data[1] |
        (static_cast<uint16_t>(data[2]) << 8);
    uint32_t payloadSize =
        static_cast<uint32_t>(data[3]) |
        (static_cast<uint32_t>(data[4]) << 8) |
        (static_cast<uint32_t>(data[5]) << 16) |
        (static_cast<uint32_t>(data[6]) << 24);
    ResponseHeader header;
    header.version = data[0];
    header.code = code;
    header.payloadSize = payloadSize;
    return header;
}


std::vector<uint8_t> Protocol::createPublicKeyPayload(const std::string& name, const std::vector<uint8_t>& publicKey){
	if (publicKey.size() != PUBLIC_KEY_SIZE) {
		throw std::invalid_argument("Public key must be " + std::to_string(PUBLIC_KEY_SIZE) + " bytes long.");
	}
    std::vector<uint8_t> namePayload = createRegistrationPayload(name);
	std::vector<uint8_t> result(PUBLIC_KEY_REQUEST_PAYLOAD_SIZE);
	std::copy(namePayload.begin(), namePayload.end(), result.begin());
	std::copy(publicKey.begin(), publicKey.end(), result.begin() + namePayload.size());
	return result;
}


AesResponsePayload Protocol::parseAesResponsePayload(const std::vector<uint8_t>& payload) {
    if (payload.size() != CLIENT_ID_SIZE + ENCRYPTED_AES_KEY_SIZE) {
		throw std::invalid_argument("Invalid AES response payload size");
    }
    AesResponsePayload aesPayload;
	aesPayload.clientId = std::vector<uint8_t>(payload.begin(), payload.begin() + CLIENT_ID_SIZE); // the first 16 bytes are the client ID
	aesPayload.encryptedAesKey = std::vector<uint8_t>(payload.begin() + CLIENT_ID_SIZE, payload.end()); // the next 128 bytes are the encrypted AES key
    return aesPayload;
}

std::vector<uint8_t> Protocol::createFilePayload(const std::string& fileName, const std::vector<uint8_t>& encryptedData, uint32_t totalEncryptedSize, uint32_t originalFileSize, uint16_t packetNumber, uint16_t totalPackets) {
    if (fileName.empty() || fileName.size() >= NAME_SIZE) {
        throw std::invalid_argument("Invalid file name");
    }
    if (packetNumber < 1 || totalPackets < 1 || packetNumber > totalPackets) {
		throw std::invalid_argument("Invalid packet number or total packets");
	}
	std::vector<uint8_t> fileNameField(NAME_SIZE, 0); // Fill the file name field with null bytes
	std::copy(fileName.begin(), fileName.end(), fileNameField.begin()); // Copy the file name into the field
    
    if (encryptedData.size() > UINT32_MAX) {
        throw std::invalid_argument("Encrypted file is too large");
    }

	uint32_t contentSize = totalEncryptedSize; // The total size of the encrypted file

	std::vector<uint8_t> payload; // Reserve space for the payload
	// Append the content size (4 bytes, little-endian)
    for (int i = 0; i < 32; i += 8) {
        payload.push_back(static_cast<uint8_t>((contentSize >> i) & 0xFF));
    }
	// Append the original file size (4 bytes, little-endian)
    for (int i = 0; i < 32; i += 8) {
        payload.push_back(static_cast<uint8_t>((originalFileSize >> i) & 0xFF));
    }
	// Append the packet number (2 bytes, little-endian)
    for (int i = 0; i < 16; i += 8) {
        payload.push_back(static_cast<uint8_t>((packetNumber >> i) & 0xFF));
    }
	// Append the total packets (2 bytes, little-endian)
    for (int i = 0; i < 16; i += 8) {
        payload.push_back(static_cast<uint8_t>((totalPackets >> i) & 0xFF));
    }
	// Append the file name field (255 bytes)
    payload.insert(payload.end(), fileNameField.begin(), fileNameField.end());
	// Append the encrypted data
    payload.insert(payload.end(), encryptedData.begin(), encryptedData.end());
    return payload;
}

FileCrcResponse Protocol::parseFileCrcResponse(const std::vector<uint8_t>& payload) {
	if (payload.size() != CLIENT_ID_SIZE + 4 + NAME_SIZE + 4) {
		throw std::invalid_argument("Invalid file CRC response payload size");
	}
	FileCrcResponse crcResponse;
	crcResponse.clientId = std::vector<uint8_t>(payload.begin(), payload.begin() + CLIENT_ID_SIZE); // the first 16 bytes are the client ID
	crcResponse.encryptedSize =
		static_cast<uint32_t>(payload[CLIENT_ID_SIZE]) |
		(static_cast<uint32_t>(payload[CLIENT_ID_SIZE + 1]) << 8) |
		(static_cast<uint32_t>(payload[CLIENT_ID_SIZE + 2]) << 16) |
		(static_cast<uint32_t>(payload[CLIENT_ID_SIZE + 3]) << 24); // the next 4 bytes are the encrypted size
    auto nameStart = payload.begin() + CLIENT_ID_SIZE + 4;
    auto nameEnd = nameStart + NAME_SIZE;

    auto nullPos = std::find(nameStart, nameEnd, 0);

    if (nullPos == nameEnd) {
        throw std::invalid_argument("File name is not null-terminated");
    }

    crcResponse.fileName = std::string(nameStart, nullPos);
	crcResponse.crc =
		static_cast<uint32_t>(payload[CLIENT_ID_SIZE + 4 + NAME_SIZE]) |
		(static_cast<uint32_t>(payload[CLIENT_ID_SIZE + 4 + NAME_SIZE + 1]) << 8) |
		(static_cast<uint32_t>(payload[CLIENT_ID_SIZE + 4 + NAME_SIZE + 2]) << 16) |
		(static_cast<uint32_t>(payload[CLIENT_ID_SIZE + 4 + NAME_SIZE + 3]) << 24); // the last 4 bytes are the CRC
	return crcResponse;
}

std::vector<uint8_t> Protocol::createCrcPayload(const std::string& fileName) {
	if (fileName.empty() || fileName.size() >= NAME_SIZE) {
		throw std::invalid_argument("Invalid file name");
	}
	std::vector<uint8_t> nameField(NAME_SIZE, 0); // Fill the file name field with null bytes
    std::copy(fileName.begin(), fileName.end(), nameField.begin()); // Copy the file name into the field
    return nameField;
}