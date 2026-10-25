#pragma once

#include <cryptopp/rsa.h>
#include <vector>
#include <string>
#include <stdexcept>

class Crypto
{
public:
    Crypto();
    std::vector<uint8_t> getPublicKey() const;
    std::vector<uint8_t> decryptAesKey(const std::vector<uint8_t>& encryptedAesKey);
    std::vector<uint8_t> encryptFile(const std::vector<uint8_t>& fileData, const std::vector<uint8_t>& aesKey);
    void savePrivateKey(const std::string& filePath) const;
    void loadPrivateKey(const std::string& filePath);
    std::string getPrivateKeyBase64() const;

private:
    CryptoPP::RSA::PrivateKey privateKey;
    CryptoPP::RSA::PublicKey publicKey;
};
