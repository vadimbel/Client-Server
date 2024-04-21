#ifndef DATA_H
#define DATA_H

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <filesystem>
#include <algorithm>
#include <unordered_map>
#include <cstdint>
#include <array>
#include <stdexcept>

namespace appdata {
    const char* const meInfo = "me.info";
    const char* const transferInfo = "transfer.info";
    const unsigned int LINES = 3;
    const unsigned int clientVersion = 3;
    const unsigned int maxRetry = 3;
    const std::string REGISTRATION = "registration";
    const std::string RECONNECT = "reconnect";
    const std::string undefined = "UNDEFINED";
    const std::string serverErrorMessage = "server responded with an error";
    const std::string privKey = "priv.key";
    const unsigned int clientIDBytesSize = 16;
    const unsigned int versionBytesSize = 1;
    const unsigned int statusCodeBytesSize = 2;
    const unsigned int payloadSizeBytesSize = 4;
    const uint32_t maxContentPerPacket = 4000000000;
    // request codes
    const unsigned int registrationCode = 1025;
    const unsigned int sendPublicKeyCode = 1026;
    const unsigned int reconectCode = 1027;
    const unsigned int sendFileCode = 1028;
    const unsigned int validCRCcode = 1029;
    const unsigned int invalidCRCcode = 1030;
    const unsigned int errorCRCcode = 1031;
    // response codes
    const unsigned int registrationSuccess = 1600;
    const unsigned int registrationFail = 1601;
    const unsigned int receivedPublicKeySendAES = 1602;
    const unsigned int fileReceivedCRCsuccess = 1603;
    const unsigned int receivedMsgValid = 1604;
    const unsigned int acceptReconnectSendAES = 1605;
    const unsigned int reconnectDenied = 1606;
    const unsigned int basicFAIL = 1607;

    const unsigned int RANGE = 255;
    const unsigned int ERR = 200;
    const unsigned int SUCCESS = 201;
    const unsigned int UNDEFINED = 0;
    const unsigned int STOP = 1;
}

std::unordered_map<std::string, std::string> openFile();
std::pair<std::string, std::string> extractAddressAndPort(const std::string& ipAddress);
std::string readFileContent(const std::string& filePath);
bool isAllAscii(const std::string& str);
bool isValidIpAddressAndPort(const std::string& ipAddress);

#endif // DATA_H