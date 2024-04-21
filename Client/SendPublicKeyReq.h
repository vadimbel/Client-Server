#ifndef SENDPUBLICKEYREQ_H
#define SENDPUBLICKEYREQ_H

#include <string>
#include <stdexcept> // For std::runtime_error
#include "payload.h"

class SendPublicKeyReq : public Payload {
private:
	std::string name;
	std::string publicKey;

public:
	explicit SendPublicKeyReq(const std::string& name, const std::string& publicKey); // Constructor

	// Getter
	std::string getName() const;
	std::string getPublicKey() const;
};

#endif // SENDPUBLICKEYREQ_H