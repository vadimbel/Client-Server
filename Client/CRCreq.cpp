#include "CRCreq.h"
#include "utils.h"

/**
    This class represent the CRC protocol request, inherit from payload base class interface
*/

CrcReq::CrcReq(const std::string& name) {
    if (!isValidByteSize(name)) {
        throw std::runtime_error("ERROR: class attribute.");
    }
    this->fileName = name;
}

std::string CrcReq::getFileName() const {
    return fileName;
}

bool CrcReq::isValidByteSize(const std::string& str) {
    return str.size() < appdata::RANGE;
}
