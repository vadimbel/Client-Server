// Payload.h
#ifndef PAYLOAD_H
#define PAYLOAD_H

// interface class for different types of payloads in the protocol

class Payload {
public:
    virtual ~Payload() = default; // Virtual destructor for polymorphic delete
};

#endif // PAYLOAD_H

