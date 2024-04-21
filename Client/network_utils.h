#ifndef NETWORK_UTILS_H
#define NETWORK_UTILS_H

#include "utils.h"
#include "headerProtocol.h"
#include "payload.h"
#include "RSAkeys.h"
#include <boost/asio.hpp>

using boost::asio::ip::tcp;

int connectToServer(std::unordered_map<std::string, std::string> data, std::string& errors);

int dataTransferResponse(boost::asio::ip::tcp::socket& s, HeaderProtocol& header);

// CRC
int sendCRCHeaderPayload(boost::asio::ip::tcp::socket& s, HeaderProtocol& header, const Payload& payload);
int receiveCRCresponse(boost::asio::ip::tcp::socket& s, HeaderProtocol& header);

// encrypted file
int sendEncryptedFileContentHeaderPayload(boost::asio::ip::tcp::socket& s, HeaderProtocol& header, const Payload& payload);
int encryptedFileContentResponse(boost::asio::ip::tcp::socket& s, HeaderProtocol& header, uint32_t& serverCRC);

// public RSA key
int sendPublicKeyHeaderPayload(boost::asio::ip::tcp::socket& s, HeaderProtocol& header, const Payload& payload);
int publicRSAKeyResponse(boost::asio::ip::tcp::socket& s, HeaderProtocol& header, std::vector<unsigned char>& encryptedAESkey);

// registration
int sendRegistrationHeaderPayload(boost::asio::ip::tcp::socket& s, HeaderProtocol& header, const Payload& payload);
int registrationResponse(boost::asio::ip::tcp::socket& s, HeaderProtocol& header);

// helpers
int sendHeaderToServer(boost::asio::ip::tcp::socket& s, const HeaderProtocol& header);
std::tuple<uint8_t, uint16_t, uint32_t, std::string> receiveHeader(boost::asio::ip::tcp::socket& socket);
std::string bytesToHexString(const std::vector<unsigned char>& uuidBytes);
unsigned int setRequestCode(std::string action);
uint32_t toLittleEndian32(uint32_t value);
uint16_t toLittleEndian16(uint16_t value);
bool isLittleEndian();
void checkAndHandleError(const boost::system::error_code& ec);
std::string toHexString(const std::vector<uint8_t>& data);
std::array<uint8_t, 16> hexStringToByteArray(const std::string& hex);
std::string aesKeyToHexString(const std::vector<unsigned char>& aesKey);

#endif // NETWORK_UTILS_H

