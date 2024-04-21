#ifndef HEADERPROTOCOL_H
#define HEADERPROTOCOL_H

#include <cstdint>
#include <array>
#include <vector>

/* 
 This class represents the header part of the protocol that will be sent in each reqeust from client to server
*/

class HeaderProtocol {
private:
    std::array<uint8_t, 16> clientID; // 16 bytes for clientID, unsigned
    uint8_t version;                  // 1 byte for version, unsigned
    uint16_t code;                    // 2 bytes for code, unsigned
    uint32_t payloadSize;             // 4 bytes for payloadSize, unsigned

public:
    HeaderProtocol(uint8_t version, uint16_t code, uint32_t payloadSize);

    
    // Getters and Setters declarations
    std::array<uint8_t, 16> getClientID() const;
    uint8_t getVersion() const;
    uint16_t getCode() const;
    uint32_t getPayloadSize() const;

    void setClientID(const std::array<uint8_t, 16>& id);
    void setVersion(uint8_t ver);
    void setCode(uint16_t c);
    void setPayloadSize(uint32_t size);

    bool compareClientID(const std::vector<unsigned char>& otherID) const;
};


#endif // HEADERPROTOCOL_H
