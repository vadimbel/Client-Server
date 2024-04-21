#include "headerProtocol.h"
#include <algorithm>

/**
* This class is the header part of the reqeust will be sent from client to server
*/

HeaderProtocol::HeaderProtocol(uint8_t version, uint16_t code, uint32_t payloadSize)
    : clientID({0}), version(version), code(code), payloadSize(payloadSize) {}

// getters
std::array<uint8_t, 16> HeaderProtocol::getClientID() const {
    return clientID;
}

uint8_t HeaderProtocol::getVersion() const {
    return version;
}

uint16_t HeaderProtocol::getCode() const {
    return code;
}

uint32_t HeaderProtocol::getPayloadSize() const {
    return payloadSize;
}

// Setters
void HeaderProtocol::setClientID(const std::array<uint8_t, 16>& id) {
    clientID = id;
}

void HeaderProtocol::setVersion(uint8_t ver) {
    version = ver;
}

void HeaderProtocol::setCode(uint16_t c) {
    code = c;
}

void HeaderProtocol::setPayloadSize(uint32_t size) {
    payloadSize = size;
}

bool HeaderProtocol::compareClientID(const std::vector<unsigned char>& otherID) const {
    // Check if the sizes match
    if (otherID.size() != clientID.size())
        return false;

    // Compare contents
    return std::equal(clientID.begin(), clientID.end(), otherID.begin());
}
