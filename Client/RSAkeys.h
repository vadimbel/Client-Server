#include "files.h"
#include <iostream>
#include <fstream>
#include <osrng.h>
#include <rsa.h>
#include <base64.h>
#include <filters.h>
#include <secblock.h>
#include <hex.h>


std::pair<CryptoPP::RSA::PrivateKey, CryptoPP::RSA::PublicKey> generateKeys();
void createMeInfoFile(const std::string& userName, const std::string& uuid, const CryptoPP::RSA::PrivateKey& privateKey);
void createPrivKeyFile(const CryptoPP::RSA::PrivateKey& privateKey);
CryptoPP::RSA::PrivateKey readPrivateKeyFromFile(const std::string& filename);
std::string encode(const std::string& str);
std::string decode(const std::string& base64String);
template<typename KeyType>
std::string keyToDERString(const KeyType& key);
std::vector<unsigned char> DecryptAESKeyWithRSAPrivateKey(const CryptoPP::RSA::PrivateKey& privateKey, const std::vector<unsigned char>& encryptedAESKey);
