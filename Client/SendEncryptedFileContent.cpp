#include "SendEncryptedFileContent.h"
#include <fstream>
#include <iostream>

/**
    This class represent the the encrypted file protocol request, inherit from payload base class interface
*/


SendEncryptedFileContent::SendEncryptedFileContent(uint32_t contentSizeParam, uint32_t originalFileSizeParam, uint16_t packetNumberParam,
    uint16_t totalPacketsParam, const std::vector<uint8_t>& messageContentParam, const std::string& fileNameParam) :
    contentSize(contentSizeParam),
    originalFileSize(originalFileSizeParam),
    packetNumber(packetNumberParam),
    totalPackets(totalPacketsParam),
    messageContent(messageContentParam),
    fileName(fileNameParam) {}


uint32_t SendEncryptedFileContent::getContentSize() const {
    return contentSize;
}

uint32_t SendEncryptedFileContent::getOriginalFileSize() const {
    return originalFileSize;
}

uint16_t SendEncryptedFileContent::getPacketNumber() const {
    return packetNumber;
}

uint16_t SendEncryptedFileContent::getTotalPackets() const {
    return totalPackets;
}

std::string SendEncryptedFileContent::getFileName() const {
    return std::string(fileName);
}

const std::vector<uint8_t>& SendEncryptedFileContent::getMessageContent() const {
    return messageContent;
}
