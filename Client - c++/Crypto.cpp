#include "Crypto.h"
#include <cryptopp/osrng.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/files.h>
#include <cryptopp/base64.h>
#include <cryptopp/queue.h>

Crypto::Crypto()
{
    CryptoPP::AutoSeededRandomPool rng;

    privateKey.GenerateRandomWithKeySize(rng, 1024);

    publicKey.AssignFrom(privateKey);
}

std::vector<uint8_t> Crypto::getPublicKey() const
{
    CryptoPP::ByteQueue queue;
    publicKey.Save(queue);
    
    std::vector<uint8_t> result(queue.CurrentSize());
    queue.Get(result.data(), result.size());

    return result;
}

std::vector<uint8_t> Crypto::decryptAesKey(const std::vector<uint8_t>& encryptedAesKey) {
    CryptoPP::RSAES_OAEP_SHA_Decryptor decryptor(privateKey);
	CryptoPP::AutoSeededRandomPool rng;

    if (encryptedAesKey.size() != decryptor.FixedCiphertextLength()) {
        throw std::invalid_argument("Invalid encrypted AES key size");
    }

    std::vector<uint8_t> decryptedAesKey(decryptor.MaxPlaintextLength(encryptedAesKey.size()));

    CryptoPP::DecodingResult result = decryptor.Decrypt(
        rng,
        encryptedAesKey.data(),
        encryptedAesKey.size(),
        decryptedAesKey.data()
    );

    // Verify successful decryption and AES-256 key length
    if (!result.isValidCoding || result.messageLength != 32) {
        throw std::runtime_error("Failed to decrypt AES key");
    }
    // Remove unused bytes from the output buffer
    decryptedAesKey.resize(result.messageLength);

    return decryptedAesKey;
}

std::vector<uint8_t> Crypto::encryptFile(const std::vector<uint8_t>& fileData, const std::vector<uint8_t>& aesKey) {
    if (aesKey.size() != CryptoPP::AES::MAX_KEYLENGTH) {
        throw std::invalid_argument("AES key must be 32 bytes for AES-256");
    }

    // The assignment requires a zero IV (16 bytes)
    CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE] = { 0 };

    // Initialize AES-256-CBC encryption
    CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption encryptor(
        aesKey.data(),
        aesKey.size(),
        iv
    );

    // Allocate enough space for ciphertext and PKCS#7 padding
    std::vector<uint8_t> encryptedData(
        fileData.size() + CryptoPP::AES::BLOCKSIZE
    );

    // Encrypt the file data
    CryptoPP::ArraySink sink(
        encryptedData.data(),
        encryptedData.size()
    );

    CryptoPP::ArraySource source(
        fileData.data(),
        fileData.size(),
        true,
        new CryptoPP::StreamTransformationFilter(
            encryptor,
            new CryptoPP::Redirector(sink)
        )
    );

    // Resize to the actual encrypted data length
    encryptedData.resize(sink.TotalPutLength());

    return encryptedData;
}

void Crypto::savePrivateKey(const std::string& filePath) const
{
    CryptoPP::FileSink file(filePath.c_str());
    privateKey.Save(file);
    file.MessageEnd();
}

void Crypto::loadPrivateKey(const std::string& filePath)
{
    CryptoPP::FileSource file(filePath.c_str(), true);
    privateKey.Load(file);

    publicKey.AssignFrom(privateKey);
}

std::string Crypto::getPrivateKeyBase64() const
{
    CryptoPP::ByteQueue queue;
    privateKey.Save(queue);

    std::string encodedKey;

    CryptoPP::Base64Encoder encoder(
        new CryptoPP::StringSink(encodedKey),
        false
    );

    queue.CopyTo(encoder);
    encoder.MessageEnd();

    return encodedKey;
}