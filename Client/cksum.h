#ifndef CHECKSUM_UTIL_H
#define CHECKSUM_UTIL_H

#include <string>

uint32_t calculate_checksum(const std::vector<unsigned char>& binaryContent);

#endif // CHECKSUM_UTIL_H

