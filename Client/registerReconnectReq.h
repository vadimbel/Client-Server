#ifndef REGISTERRECONNECTREQ_H
#define REGISTERRECONNECTREQ_H

#include <string>
#include <stdexcept> // For std::runtime_error
#include "payload.h"

class RegisterReconnectReq : public Payload {
private:
    std::string name; // Name of the person

public:
    explicit RegisterReconnectReq(const std::string& name); // Constructor with name

    // Getter
    std::string getName() const;

    // Utility function to check string byte size
    static bool isValidByteSize(const std::string& str);
};


#endif // REGISTERRECONNECTREQ_H