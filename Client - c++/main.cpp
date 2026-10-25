#include "Network.h"
#include "Protocol.h"
#include "Crypto.h"
#include "FileManager.h"
#include "ConfigManager.h"
#include <iostream>
#include <iomanip>
#include <filesystem>
#include <algorithm>

unsigned long memcrc(char* b, size_t n);

void uploadFile(const std::string& filePath, const std::vector<uint8_t>& aesKey, const std::vector<uint8_t>& receivedClientId, Network& network, Crypto& crypto) {
    std::string fileName =
        std::filesystem::path(filePath).filename().string();

    std::cout << "Uploading: " << fileName << std::endl;

    std::vector<uint8_t> originalFileData =
        FileManager::readFile(filePath);

    std::vector<uint8_t> encryptedFileData =
        crypto.encryptFile(originalFileData, aesKey);

    if (originalFileData.size() > UINT32_MAX ||
        encryptedFileData.size() > UINT32_MAX)
    {
        throw std::runtime_error("File exceeds protocol size limit");
    }

    // Calculate the number of packets needed to send the file
    constexpr size_t MAX_CHUNK_SIZE = 4096;

    size_t totalPackets =
        (encryptedFileData.size() + MAX_CHUNK_SIZE - 1)
        / MAX_CHUNK_SIZE;

    if (totalPackets > UINT16_MAX)
    {
        throw std::runtime_error("File requires too many packets");
    }


    constexpr int MAX_ATTEMPTS = 3;

    for (int attempt = 1; attempt <= MAX_ATTEMPTS; ++attempt)
    {
        std::cout << "Sending file, attempt "
            << attempt << "/" << MAX_ATTEMPTS << std::endl;

        for (size_t packet = 0; packet < totalPackets; ++packet)
        {
            size_t offset = packet * MAX_CHUNK_SIZE;

            size_t chunkSize = (std::min)(
                MAX_CHUNK_SIZE,
                encryptedFileData.size() - offset
                );

            std::vector<uint8_t> chunk(
                encryptedFileData.begin() + offset,
                encryptedFileData.begin() + offset + chunkSize
            );

            std::vector<uint8_t> filePayload =
                Protocol::createFilePayload(
                    fileName,
                    chunk,
                    static_cast<uint32_t>(encryptedFileData.size()),
                    static_cast<uint32_t>(originalFileData.size()),
                    static_cast<uint16_t>(packet + 1),
                    static_cast<uint16_t>(totalPackets)
                );

            std::vector<uint8_t> fileRequest =
                Protocol::createRequest(
                    receivedClientId,
                    Protocol::SEND_FILE,
                    static_cast<uint32_t>(filePayload.size())
                );

            network.sendAll(fileRequest);
            network.sendAll(filePayload);

        }


        std::cout << "Encrypted file sent!" << std::endl;


        std::vector<uint8_t> crcHeaderData =
            network.recvExact(Protocol::RESPONSE_HEADER_SIZE);

        ResponseHeader crcHeader =
            Protocol::parseResponseHeader(crcHeaderData);


        if (crcHeader.version != Protocol::VERSION)
        {
            throw std::runtime_error("Unsupported server version");
        }

        if (crcHeader.code == Protocol::SERVER_ERROR)
        {
            if (crcHeader.payloadSize > 1024 * 1024)
            {
                throw std::runtime_error("Server error payload too large");
            }

            network.recvExact(crcHeader.payloadSize);

            std::cout << "Server error during file upload (attempt "
                << attempt << "/" << MAX_ATTEMPTS << ")"
                << std::endl;

            if (attempt == MAX_ATTEMPTS)
            {
                throw std::runtime_error(
                    "Fatal: File upload failed after 3 attempts"
                );
            }

            continue;
        }

        if (crcHeader.code != Protocol::FILE_RECEIVED_WITH_CRC ||
            crcHeader.payloadSize != 279) {
            throw std::runtime_error("Invalid CRC response");
        }

        std::vector<uint8_t> crcPayloadData =
            network.recvExact(crcHeader.payloadSize);

        FileCrcResponse crcResponse =
            Protocol::parseFileCrcResponse(crcPayloadData);

        if (crcResponse.clientId != receivedClientId ||
            crcResponse.fileName != fileName ||
            crcResponse.encryptedSize != encryptedFileData.size()) {
            throw std::runtime_error("CRC response does not match the sent file");
        }

        uint32_t localCrc = static_cast<uint32_t>(
            memcrc(
                reinterpret_cast<char*>(originalFileData.data()),
                originalFileData.size()
            )
            );


        if (localCrc == crcResponse.crc) {
            std::cout << "CRC MATCH!" << std::endl;

            std::vector<uint8_t> crcPayload =
                Protocol::createCrcPayload(fileName);

            std::vector<uint8_t> crcRequest =
                Protocol::createRequest(
                    receivedClientId,
                    Protocol::VALID_CRC,
                    static_cast<uint32_t>(crcPayload.size())
                );

            network.sendAll(crcRequest);
            network.sendAll(crcPayload);

        }
        else {
            std::cout << "CRC MISMATCH! Attempt "
                << attempt << "/" << MAX_ATTEMPTS << std::endl;

            uint16_t requestCode =
                (attempt < MAX_ATTEMPTS)
                ? Protocol::INVALID_CRC_RESEND
                : Protocol::INVALID_CRC_DONE;

            std::vector<uint8_t> crcPayload =
                Protocol::createCrcPayload(fileName);

            std::vector<uint8_t> crcRequest =
                Protocol::createRequest(
                    receivedClientId,
                    requestCode,
                    static_cast<uint32_t>(crcPayload.size())
                );

            network.sendAll(crcRequest);
            network.sendAll(crcPayload);

            if (requestCode == Protocol::INVALID_CRC_RESEND)
            {
                continue;
            }
        }
        std::vector<uint8_t> ackHeaderData =
            network.recvExact(Protocol::RESPONSE_HEADER_SIZE);

        ResponseHeader ackHeader =
            Protocol::parseResponseHeader(ackHeaderData);

        if (ackHeader.version != Protocol::VERSION)
        {
            throw std::runtime_error("Unsupported server version");
        }

        if (ackHeader.code == Protocol::SERVER_ERROR)
        {
            if (ackHeader.payloadSize > 1024 * 1024)
            {
                throw std::runtime_error("Server error payload too large");
            }

            network.recvExact(ackHeader.payloadSize);

            std::cout << "Server error during acknowledgment (attempt "
                << attempt << "/" << MAX_ATTEMPTS << ")"
                << std::endl;

            if (attempt == MAX_ATTEMPTS)
            {
                throw std::runtime_error(
                    "Fatal: File transfer failed after 3 attempts"
                );
            }

            continue;
        }

        if (ackHeader.code != Protocol::MESSAGE_RECEIVED ||
            ackHeader.payloadSize != Protocol::CLIENT_ID_SIZE) {
            throw std::runtime_error("Invalid CRC acknowledgment");
        }

        std::vector<uint8_t> ackClientId =
            network.recvExact(ackHeader.payloadSize);

        if (ackClientId != receivedClientId) {
            throw std::runtime_error("Acknowledgment client ID mismatch");
        }

        if (localCrc == crcResponse.crc)
        {
            std::cout << "File transfer completed successfully!" << std::endl;
        }
        else
        {
            throw std::runtime_error("File transfer failed after 3 attempts.");
        }
        break;
    }
}

bool reconnectClient(std::string& name, std::vector<uint8_t>& receivedClientId, std::vector<uint8_t>& aesKey, std::vector<uint8_t>& publicKey, Network& network, Crypto& crypto) {
    constexpr int MAX_ATTEMPTS = 3;
    auto [savedName, savedId, savedPrivateKey] =
        FileManager::loadClientInfo();

    name = savedName;
    crypto.loadPrivateKey("priv.key");
    publicKey = crypto.getPublicKey();

    std::vector<uint8_t> reconnectPayload =
        Protocol::createRegistrationPayload(name);

    std::vector<uint8_t> reconnectRequest =
        Protocol::createRequest(
            savedId,
            Protocol::RECONNECT,
            static_cast<uint32_t>(reconnectPayload.size())
        );

    for (int attempt = 1; attempt <= MAX_ATTEMPTS; ++attempt)
    {
        network.sendAll(reconnectRequest);
        network.sendAll(reconnectPayload);

        std::vector<uint8_t> reconnectHeaderData =
            network.recvExact(Protocol::RESPONSE_HEADER_SIZE);

        ResponseHeader reconnectResponse =
            Protocol::parseResponseHeader(reconnectHeaderData);

        if (reconnectResponse.version != Protocol::VERSION)
        {
            throw std::runtime_error("Unsupported server version");
        }

        // Reconnection failed: fall back to registration.
        if (reconnectResponse.code == Protocol::RECONNECT_FAILED)
        {
            if (reconnectResponse.payloadSize > 1024 * 1024)
            {
                throw std::runtime_error("Response payload too large");
            }

            network.recvExact(reconnectResponse.payloadSize);

            throw std::runtime_error("Fatal: Reconnection failed");
        }

        // Reconnection succeeded.
        if (reconnectResponse.code == Protocol::RECONNECT_SUCCESS)
        {
            if (reconnectResponse.payloadSize !=
                Protocol::CLIENT_ID_SIZE + Protocol::ENCRYPTED_AES_KEY_SIZE)
            {
                throw std::runtime_error("Invalid reconnection response size");
            }

            std::vector<uint8_t> reconnectAesPayload =
                network.recvExact(reconnectResponse.payloadSize);

            AesResponsePayload reconnectAesResponse =
                Protocol::parseAesResponsePayload(reconnectAesPayload);

            if (reconnectAesResponse.clientId != savedId)
            {
                throw std::runtime_error("Reconnection client ID mismatch");
            }

            receivedClientId = savedId;

            aesKey = crypto.decryptAesKey(
                reconnectAesResponse.encryptedAesKey
            );

            std::cout << "Reconnected successfully!" << std::endl;
            return false;
        }

        // Only retry general server errors.
        if (reconnectResponse.code != Protocol::SERVER_ERROR)
        {
            throw std::runtime_error("Unexpected reconnection response");
        }

        if (reconnectResponse.payloadSize > 1024 * 1024)
        {
            throw std::runtime_error("Server error payload too large");
        }

        network.recvExact(reconnectResponse.payloadSize);

        std::cout << "Server error during reconnection (attempt "
            << attempt << "/" << MAX_ATTEMPTS << ")"
            << std::endl;

        if (attempt == MAX_ATTEMPTS)
        {
            throw std::runtime_error(
                "Fatal: Reconnection failed after 3 attempts"
            );
        }
    }

    throw std::runtime_error("Reconnection attempts exhausted");
}


void registerClient(const std::string& name, std::vector<uint8_t>& receivedClientId, std::vector<uint8_t>& aesKey, const std::vector<uint8_t>& publicKey, Network& network, Crypto& crypto) {
    constexpr int MAX_ATTEMPTS = 3;

    std::vector<uint8_t> vec(16, 0);
    std::vector<uint8_t> payload =
        Protocol::createRegistrationPayload(name);

    std::vector<uint8_t> request =
        Protocol::createRequest(
            vec,
            Protocol::REGISTER,
            static_cast<uint32_t>(payload.size())
        );

    for (int attempt = 1; attempt <= MAX_ATTEMPTS; ++attempt)
    {
        network.sendAll(request);
        network.sendAll(payload);

        std::vector<uint8_t> responseData =
            network.recvExact(Protocol::RESPONSE_HEADER_SIZE);

        ResponseHeader response =
            Protocol::parseResponseHeader(responseData);

        if (response.version != Protocol::VERSION)
        {
            throw std::runtime_error("Unsupported server version");
        }

        if (response.code == Protocol::REGISTRATION_SUCCESS)
        {
            if (response.payloadSize != Protocol::CLIENT_ID_SIZE)
            {
                throw std::runtime_error("Invalid registration response size");
            }

            receivedClientId = network.recvExact(response.payloadSize);

            std::cout << "Registration successful!" << std::endl;
            break;
        }

        if (response.code != Protocol::REGISTRATION_FAILED &&
            response.code != Protocol::SERVER_ERROR)
        {
            throw std::runtime_error(
                "Unexpected response during registration"
            );
        }

        // Server returned an error.
        if (response.payloadSize > 1024 * 1024)
        {
            throw std::runtime_error("Server error payload is too large");
        }

        network.recvExact(response.payloadSize);

        std::cout << "Server responded with an error. Code: "
            << response.code
            << " (attempt " << attempt << "/" << MAX_ATTEMPTS << ")"
            << std::endl;

        if (attempt == MAX_ATTEMPTS)
        {
            throw std::runtime_error(
                "Fatal: Registration failed after 3 attempts"
            );
        }
    }

    std::cout << "Client ID: ";

    for (uint8_t byte : receivedClientId)
    {
        std::cout << std::hex
            << std::setw(2)
            << std::setfill('0')
            << static_cast<int>(byte);
    }

    std::cout << std::dec << std::endl;

    std::vector<uint8_t> payLoad =
        Protocol::createPublicKeyPayload(name, publicKey);

    std::vector<uint8_t> req =
        Protocol::createRequest(receivedClientId, Protocol::SEND_PUBLIC_KEY, Protocol::PUBLIC_KEY_REQUEST_PAYLOAD_SIZE);
    for (int attempt = 1; attempt <= MAX_ATTEMPTS; ++attempt)
    {
        network.sendAll(req);
        network.sendAll(payLoad);

        std::vector<uint8_t> aesHeaderData =
            network.recvExact(Protocol::RESPONSE_HEADER_SIZE);

        ResponseHeader aesHeader =
            Protocol::parseResponseHeader(aesHeaderData);

        if (aesHeader.version != Protocol::VERSION)
        {
            throw std::runtime_error("Unsupported server version");
        }

        if (aesHeader.code == Protocol::SEND_AES)
        {
            if (aesHeader.payloadSize !=
                Protocol::CLIENT_ID_SIZE + Protocol::ENCRYPTED_AES_KEY_SIZE)
            {
                throw std::runtime_error("Invalid AES response size");
            }

            std::vector<uint8_t> aesPayloadData =
                network.recvExact(aesHeader.payloadSize);

            AesResponsePayload aesResponse =
                Protocol::parseAesResponsePayload(aesPayloadData);

            if (aesResponse.clientId != receivedClientId)
            {
                throw std::runtime_error("Client ID mismatch");
            }

            aesKey = crypto.decryptAesKey(
                aesResponse.encryptedAesKey
            );

            std::cout << "AES key received successfully!" << std::endl;
            break;
        }

        if (aesHeader.code != Protocol::SERVER_ERROR)
        {
            throw std::runtime_error(
                "Unexpected response during public-key exchange"
            );
        }

        // Consume the error response payload.
        if (aesHeader.payloadSize > 1024 * 1024)
        {
            throw std::runtime_error("Server error payload is too large");
        }

        network.recvExact(aesHeader.payloadSize);

        std::cout << "Server responded with an error. Code: "
            << aesHeader.code
            << " (attempt " << attempt << "/" << MAX_ATTEMPTS << ")"
            << std::endl;

        if (attempt == MAX_ATTEMPTS)
        {
            throw std::runtime_error(
                "Fatal: Public-key exchange failed after 3 attempts"
            );
        }
    }

    std::cout << "AES key size: " << aesKey.size() << std::endl;
    FileManager::saveClientInfo(name, receivedClientId, crypto.getPrivateKeyBase64());
    crypto.savePrivateKey("priv.key");
}


int main()
{
    try
    {
        ClientConfig config = ConfigManager::loadConfig("transfer.json");
        std::string name = config.clientName;
        Crypto crypto;
        std::vector<uint8_t> publicKey = crypto.getPublicKey();
        Network network;

        network.connectToServer(config.ip, config.port);

        std::cout << "Connected successfully!" << std::endl;

        std::vector<uint8_t> receivedClientId;
        std::vector<uint8_t> aesKey;

        bool needsRegistration = !std::filesystem::exists("me.info");
        if (!needsRegistration)
        {
			needsRegistration = reconnectClient(name, receivedClientId, aesKey, publicKey, network, crypto);
        }
        if (needsRegistration)
        {
            registerClient(name, receivedClientId, aesKey, publicKey, network, crypto);
        }
        
        for (const std::string& filePath : config.files)
        {
            uploadFile(filePath, aesKey, receivedClientId, network, crypto);
        }
    }
    catch (const std::exception& e)
    {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}