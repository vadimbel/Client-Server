#include "RSAkeys.h"
#include <string>
#include <sstream>
#include <iomanip>
#include "network_utils.h"

/**
 * This function generates a pair of RSA keys and return them
 */
std::pair<CryptoPP::RSA::PrivateKey, CryptoPP::RSA::PublicKey> generateKeys() {
    // provides a cryptographic random number generator
    CryptoPP::AutoSeededRandomPool rng;

    // Generate RSA keys
    CryptoPP::InvertibleRSAFunction parameters;
    parameters.GenerateRandomWithKeySize(rng, 1024); // Key len = 1024 bits

    CryptoPP::RSA::PrivateKey privateKey(parameters);
    CryptoPP::RSA::PublicKey publicKey(parameters);

    return { privateKey, publicKey };
}

/**
 * This function creates me.info file with data provided as parametes. 
 *
 * @param userName : The user's name to be saved in the file.
 * @param uuid : A unique identifier for the user, typically a UUID string.
 * @param privateKey : The RSA private key of the user, to be stored securely.
 *
 */
void createMeInfoFile(const std::string& userName, const std::string& uuid, const CryptoPP::RSA::PrivateKey& privateKey) {
    // filename
    std::string filePath = "me.info";

    // Open a file stream for writing
    std::ofstream fileStream(filePath);

    if (!fileStream.is_open()) {
        std::cerr << "Failed to open file for writing: " << filePath << std::endl;
        return;
    }

    // Write the userName and uuid to the file
    fileStream << userName << std::endl;
    fileStream << uuid << std::endl;

    // Convert the private key to DER string format
    std::string derFormattedKey = keyToDERString(privateKey);

    // Encode the DER formatted key in Base64
    std::string encodedPrivateKey = encode(derFormattedKey);

    // Write the Base64 encoded key to the file
    fileStream << encodedPrivateKey << std::endl;

    fileStream.close();
}

/**
 * This function creates priv.key file with data provided as parametes.
 *
 * @param privateKey : private RSA key that will be written in 64base format
 *
 */
void createPrivKeyFile(const CryptoPP::RSA::PrivateKey& privateKey) {
    // Step 1: Convert the private key to DER format
    std::string derFormattedPrivateKey = keyToDERString(privateKey);

    // Step 2: Encode the DER formatted private key in Base64
    std::string base64EncodedPrivateKey = encode(derFormattedPrivateKey);

    // Step 3: Write the Base64 encoded private key to "priv.key"
    std::ofstream outFile("priv.key");
    if (!outFile.is_open()) {
        std::cerr << "Failed to open 'priv.key' for writing." << std::endl;
        return;
    }

    outFile << base64EncodedPrivateKey;
    outFile.close();
}

/**
 * This function reads the private RSA key stored in 'priv.key' file.
 *
 * @param filename : filename will be readed
 *
 * return private RSA key in der format
 */
CryptoPP::RSA::PrivateKey readPrivateKeyFromFile(const std::string& filename) {
    // Step 1: Read the Base64 encoded private key from "priv.key"
    std::ifstream inFile(filename);
    if (!inFile.is_open()) {
        throw std::runtime_error("Failed to open '" + filename + "' for reading.");
    }

    std::string base64EncodedPrivateKey((std::istreambuf_iterator<char>(inFile)),
        std::istreambuf_iterator<char>());
    inFile.close();

    // Step 2: Decode the Base64 encoded string
    std::string derFormattedPrivateKey;
    CryptoPP::StringSource ss(base64EncodedPrivateKey, true /* pumpAll */,
        new CryptoPP::Base64Decoder(
            new CryptoPP::StringSink(derFormattedPrivateKey)
        )
    );

    // Step 3: Convert the DER formatted private key to CryptoPP::RSA::PrivateKey
    CryptoPP::RSA::PrivateKey privateKey;
    CryptoPP::StringSource privateKeySource(derFormattedPrivateKey, true /* pumpAll */);
    privateKey.BERDecode(privateKeySource);

    return privateKey;
}


std::string encode(const std::string& str) {
    // convertion from der string to 64 base format
    std::string encoded;
    CryptoPP::StringSource ss(str, true,
        new CryptoPP::Base64Encoder(
            new CryptoPP::StringSink(encoded)
        ) // Base64Encoder
    ); // StringSource

    return encoded;
}

std::string decode(const std::string& base64String) {
    std::string decoded;
    CryptoPP::StringSource ss(base64String, true,
        new CryptoPP::Base64Decoder(
            new CryptoPP::StringSink(decoded)
        ) // Base64Decoder
    ); // StringSource

    return decoded;
}

template<typename KeyType>
std::string keyToDERString(const KeyType& key) {
    // receive private/public RSA key and return it as der string format
    std::string derFormattedKey;
    CryptoPP::StringSink stringSink(derFormattedKey);
    key.DEREncode(stringSink);
    stringSink.MessageEnd();

    return derFormattedKey;
}

// Explicit template instantiation for the types you use
template std::string keyToDERString<CryptoPP::RSA::PrivateKey>(const CryptoPP::RSA::PrivateKey& key);
template std::string keyToDERString<CryptoPP::RSA::PublicKey>(const CryptoPP::RSA::PublicKey& key);


std::vector<unsigned char> DecryptAESKeyWithRSAPrivateKey(
    const CryptoPP::RSA::PrivateKey& privateKey,
    const std::vector<unsigned char>& encryptedAESKey) {

    std::string privDER = keyToDERString(privateKey);
    std::string priv64base = encode(privDER);

    CryptoPP::AutoSeededRandomPool rng;
    std::string decryptedText;

    try {
        // Create a decryptor object using the RSA private key with RSAES_OAEP_SHA
        CryptoPP::RSAES_OAEP_SHA_Decryptor decryptor(privateKey);

        // Decrypt the encrypted AES key
        CryptoPP::StringSource ss(encryptedAESKey.data(), encryptedAESKey.size(), true,
            new CryptoPP::PK_DecryptorFilter(rng, decryptor,
                new CryptoPP::StringSink(decryptedText) // The decrypted text is appended here
            ) // PK_DecryptorFilter
        ); // StringSource
    }
    catch (const CryptoPP::Exception& e) {
        std::cerr << "Decryption failed: " << e.what() << std::endl;
        // Handle the error appropriately
    }

    // Convert decryptedText (std::string) back to std::vector<unsigned char>
    std::vector<unsigned char> decryptedAESKey(decryptedText.begin(), decryptedText.end());
    return decryptedAESKey;
}

