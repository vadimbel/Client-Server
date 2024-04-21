#include "SendPublicKeyReq.h"
#include "utils.h"

/**
    This class represent the the public RSA key protocol request, inherit from payload base class interface
*/

SendPublicKeyReq::SendPublicKeyReq(const std::string& name, const std::string& publicKey) {
    //if (!isValidByteSize(name)) {
        //throw std::runtime_error("ERROR: class attribute.");
    //}
    this->name = name;
    this->publicKey = publicKey;
}

std::string SendPublicKeyReq::getName() const {
    return name;
}

std::string SendPublicKeyReq::getPublicKey() const {
    return publicKey;
}


//bool SendPublicKeyReq::isValidByteSize(const std::string& str) {
    //return str.size() < appdata::RANGE;
//}
