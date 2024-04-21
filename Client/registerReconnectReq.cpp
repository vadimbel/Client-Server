#include "registerReconnectReq.h"
#include "utils.h"

/**
* This class rrepresents the registration/reconnect protocol requests
*/

RegisterReconnectReq::RegisterReconnectReq(const std::string& name) {
    if (!isValidByteSize(name)) {
        throw std::runtime_error("ERROR: class attribute.");
    }
    this->name = name;
}

std::string RegisterReconnectReq::getName() const {
    return name;
}

bool RegisterReconnectReq::isValidByteSize(const std::string& str) {
    return str.size() < appdata::RANGE;
}
