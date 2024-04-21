#ifndef SENDENCRYPTEDFILECONTENT_H
#define SENDENCRYPTEDFILECONTENT_H

#include "Payload.h" // Include the Payload interface
#include <string>
#include <vector>
#include <cstdint> // For fixed-width integer types

class SendEncryptedFileContent : public Payload {
private:
    uint32_t contentSize;
    uint32_t originalFileSize;
    uint16_t packetNumber;
    uint16_t totalPackets;
    std::vector<uint8_t> messageContent;
    std::string fileName;

public:
    // Constructor with initialization parameters
    SendEncryptedFileContent(uint32_t contentSizeParam, uint32_t originalFileSizeParam,
        uint16_t packetNumberParam, uint16_t totalPacketsParam, const std::vector<uint8_t>& messageContentParam, const std::string& fileNameParam);

    // Getters
    uint32_t getContentSize() const;
    uint32_t getOriginalFileSize() const;
    uint16_t getPacketNumber() const;
    uint16_t getTotalPackets() const;
    std::string getFileName() const;
    const std::vector<uint8_t>& getMessageContent() const;
};

#endif // SENDENCRYPTEDFILECONTENT_H

