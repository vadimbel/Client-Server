#ifndef CRCREQ_H
#define CRCREQ_H

#include <string>
#include <stdexcept> // For std::runtime_error
#include "payload.h"

class CrcReq : public Payload {
private:
    std::string fileName; // Name of the person

public:
    explicit CrcReq(const std::string& name); // Constructor with name

    // Getter and Setter
    std::string getFileName() const;

    // Utility function to check string byte size
    static bool isValidByteSize(const std::string& str);
};

#endif // CRCREQ_H