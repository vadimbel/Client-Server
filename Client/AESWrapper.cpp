#include "AESWrapper.h"
#include <modes.h>
#include <aes.h>
#include <filters.h>
#include <stdexcept>
#include <immintrin.h>	// _rdrand32_step


/**
 * Generates a cryptographic random AES key.
 *
 * @param buffer Pointer to the buffer where the key will be stored.
 * @param length The length of the buffer, should be equal to the AES key length.
 * @return Pointer to the buffer now containing the AES key.
 * @details Utilizes hardware random number generation to fill the buffer with random data.
 */
unsigned char* AESWrapper::GenerateKey(unsigned char* buffer, unsigned int length)
{
	for (size_t i = 0; i < length; i += sizeof(unsigned int))
		_rdrand32_step(reinterpret_cast<unsigned int*>(&buffer[i]));
	return buffer;
}

/**
 * Default constructor that generates a new AES key.
 *
 * @details Generates a default 16-byte AES key.
 */
AESWrapper::AESWrapper()
{
	GenerateKey(_key, DEFAULT_KEYLENGTH);
}

/**
 * Constructor that initializes the AESWrapper with a provided key.
 *
 * @param key Pointer to the array containing the AES key.
 * @param length Length of the AES key array, which must be 16 bytes.
 * @throws std::length_error If the provided key length is not 16 bytes.
 */
AESWrapper::AESWrapper(const unsigned char* key, unsigned int length)
{
	if (length != DEFAULT_KEYLENGTH)
		throw std::length_error("key length must be 16 bytes");
	memcpy_s(_key, DEFAULT_KEYLENGTH, key, length);
}

/**
 * Destructor for AESWrapper.
 *
 * @details Currently does not perform any specific action.
 */
AESWrapper::~AESWrapper()
{
}

/**
 * Retrieves the AES key used in the wrapper.
 *
 * @return Pointer to the internal AES key array.
 */
const unsigned char* AESWrapper::getKey() const
{
	return _key;
}

 /**
  * Encrypts plaintext using AES in CBC mode.
  *
  * @param plain Pointer to the plaintext buffer.
  * @param length Length of the plaintext buffer.
  * @return Encrypted data as a string.
  * @details Uses CryptoPP's AES encryption, with a zero-initialized IV for simplicity.
  */
std::string AESWrapper::encrypt(const char* plain, unsigned int length)
{
	CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE] = { 0 };	// for practical use iv should never be a fixed value!

	CryptoPP::AES::Encryption aesEncryption(_key, DEFAULT_KEYLENGTH);
	CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, iv);

	std::string cipher;
	CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink(cipher));
	stfEncryptor.Put(reinterpret_cast<const CryptoPP::byte*>(plain), length);
	stfEncryptor.MessageEnd();

	return cipher;
}

/**
 * Decrypts encrypted data using AES in CBC mode.
 *
 * @param cipher Pointer to the cipher buffer.
 * @param length Length of the cipher buffer.
 * @return Decrypted data as a string.
 * @details Uses CryptoPP's AES decryption, with a zero-initialized IV for simplicity.
 */
std::string AESWrapper::decrypt(const char* cipher, unsigned int length)
{
	CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE] = { 0 };	// for practical use iv should never be a fixed value!

	CryptoPP::AES::Decryption aesDecryption(_key, DEFAULT_KEYLENGTH);
	CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, iv);

	std::string decrypted;
	CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink(decrypted));
	stfDecryptor.Put(reinterpret_cast<const CryptoPP::byte*>(cipher), length);
	stfDecryptor.MessageEnd();

	return decrypted;
}

