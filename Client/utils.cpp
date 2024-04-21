#include "utils.h"

/**
 * Opens and reads information from 'me.info' and 'transfer.info' configuration files.
 *
 * The function attempts to open and parse both files to determine the application's next action based on the available data.
 * It handles 'me.info' for user and private key information and 'transfer.info' for connection and file transfer details.
 *
 * @return A map containing relevant configuration details and the next action for the application.
 * If both files are opened successfully, it indicates a reconnect scenario.
 * If only 'transfer.info' is successfully opened, it indicates a registration scenario.
 * Any other option is invalid, return an empty map indicating an error.
 */
std::unordered_map<std::string, std::string> openFile() {
    std::ifstream file;
    std::stringstream buffer;
    std::unordered_map<std::string, std::string> data;
    std::unordered_map<std::string, std::string> meInfoDataMap;
    std::unordered_map<std::string, std::string> transferInfoDataMap;
    std::vector<std::string> meInfoContent;
    std::vector<std::string> transferInfoContent;

    bool meInfo = false;        // boolean represent if 'me.info' file opened successfully
    bool transferInfo = false;  // boolean represent if 'transfer.info' file opened successfully

    // try open 'transferInfo'
    file.open(appdata::transferInfo);
    // 'transferInfo' opened succesfully
    if (file) {
        // mark that 'transferInfo' file succesfully opened, then read and store file content
        transferInfo = true;

        // Temporary variables to hold file content
        std::string ipAddress, username, filePath, line;

        // Line 1: IP address with port
        if (std::getline(file, ipAddress)) {

            if (!isValidIpAddressAndPort(ipAddress)) {
                std::cerr << "Error - transfer.info: invalid IP address format." << std::endl;
                return data; // Return empty or error-indicated data
            }

            auto [address, port] = extractAddressAndPort(ipAddress);

            // Store address and port in transferInfoDataMap
            transferInfoDataMap["address"] = address;
            transferInfoDataMap["port"] = port;
        }

        // Line 2: Username (read up to 100 characters, must be ascii)
        if (std::getline(file, line)) {
            if (line.length() > 100) {
                std::cerr << "Error - transfer.info: Username exceeds 100 characters limit." << std::endl;
                return data; // Return empty or error-indicated data
            }

            if (!isAllAscii(line)) {
                std::cerr << "Error - transfer.info: Username must be ascii." << std::endl;
                return data; // Return empty or error-indicated data
            }

            std::string userName = line.substr(0, 100);  // Ensuring up to 100 characters
            transferInfoDataMap["username"] = userName;
        }

        if (file.fail() && !file.eof()) {
            file.clear(); // Clear fail state
            file.ignore(std::numeric_limits<std::streamsize>::max(), '\n'); // Skip to the end of the line
        }

        // Rest of the file: File path
        while (std::getline(file, line)) {
            filePath += line + "\n"; // Reconstruct lines if there are line breaks
        }
        if (!filePath.empty() && filePath.back() == '\n') {
            filePath.pop_back(); // Remove the last newline character
        }
        transferInfoDataMap["filePath"] = filePath;
        // close opened file
        file.close();
    }

    // clear objects, then try open 'meInfo'
    buffer.str("");
    buffer.clear();
    file.clear();
    file.open(appdata::meInfo);

    // 'meInfo' opened succesfully
    if (file) {
        std::string line;
        meInfo = true;          // mark that me.info file opened

        // Line 1: Username (read up to 100 characters, must be ascii)
        if (std::getline(file, line)) {
            if (line.length() > 100) {
                std::cerr << "Error - me.info: Username exceeds 100 characters limit." << std::endl;
                return data; // Return empty or error-indicated data
            }

            if (!isAllAscii(line)) {
                std::cerr << "Error - me.info: Username must be ascii." << std::endl;
                return data; // Return empty or error-indicated data
            }

            std::string userName = line.substr(0, 100);  // Ensuring up to 100 characters
            meInfoDataMap["userName"] = userName;
        }

        // Line 2: Hex string (16 bytes)
        char hexStringBuffer[33]; // 32 characters + null terminator for 16 bytes
        file.read(hexStringBuffer, 32);
        hexStringBuffer[32] = '\0'; // Ensure null termination

        // clientID must contain only ascii values
        if (!isAllAscii(hexStringBuffer)) {
            std::cerr << "Error - me.info: invalid clientID." << std::endl;
            return data; // Return empty or error-indicated data
        }
        
        meInfoDataMap["clientID"] = std::string(hexStringBuffer);

        // Consume any remaining part of the line if it exists
        file.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

        // Rest of the file
        std::stringstream buffer;
        buffer << file.rdbuf();
        std::string restOfFile = buffer.str();

        if (!isAllAscii(restOfFile)) {
            std::cerr << "Error - me.info: key must be 64base format." << std::endl;
            return data; // Return empty or error-indicated data
        }

        meInfoDataMap["privateRSAkey"] = restOfFile;

        file.close();
    }

    // if 'transferInfo' and 'meInfo' opened succsesfully = recconect
    if (meInfo and transferInfo) {
        // if both files exist, username must match
        if (meInfoDataMap["userName"] != transferInfoDataMap["username"])
            return data;

        // Copy data from meInfoDataMap into data
        for (const auto& pair : meInfoDataMap) {
            data[pair.first] = pair.second;
        }
        // Copy data from transferInfoDataMap into data
        for (const auto& pair : transferInfoDataMap) {
            data[pair.first] = pair.second;
        }
        // set reconnect action to data
        data["action"] = appdata::RECONNECT;
        return data;
    }
    // if 'transferInfo' opened and 'meInfo' did not then action = registration , copy all 'transferInfo' data into 'data' and return
    else if (transferInfo and !meInfo) {
        // Copy data from transferInfoDataMap into data
        for (const auto& pair : transferInfoDataMap) {
            data[pair.first] = pair.second;
        }
        // set reconnect action to data
        data["action"] = appdata::REGISTRATION;
        return data;
    }
    // any other situation is invalid -> return empty 'data'
    else {
        std::cout << "error" << std::endl;
        return data;
    }
}

/**
 * Reads the entire content of a file into a string.
 *
 * @param filePath The path to the file that needs to be read.
 * @return A string containing the contents of the file.
 * @throws std::runtime_error If the file cannot be opened.
 */
std::string readFileContent(const std::string& filePath) {
    std::ifstream fileStream(filePath);
    if (!fileStream.is_open()) {
        throw std::runtime_error("Failed to open file: " + filePath);
    }

    std::stringstream buffer;
    buffer << fileStream.rdbuf();
    return buffer.str();
}

/**
 * Extracts the address and port from a string formatted as "address:port".
 *
 * @param ipAddress The string containing the IP address and port.
 * @return A pair containing the address and the port. If the format is incorrect, both values in the pair will be empty strings.
 */
std::pair<std::string, std::string> extractAddressAndPort(const std::string& ipAddress) {
    auto colonPos = ipAddress.find_last_of(':');
    if (colonPos != std::string::npos && colonPos + 1 < ipAddress.length()) {
        std::string address = ipAddress.substr(0, colonPos);
        std::string port = ipAddress.substr(colonPos + 1);
        return { address, port };
    }
    return { "", "" }; // Return empty strings if format is incorrect
}

/**
 * Checks if all characters in a string are ASCII.
 * ASCII characters are those from character code 0 to 127.
 *
 * @param str The string to be checked for ASCII characters.
 * @return true if all characters are ASCII, false otherwise.
 */
bool isAllAscii(const std::string& str) {
    for (char ch : str) {
        if (static_cast<unsigned char>(ch) > 127) {  // Check if the character is beyond ASCII range
            return false;
        }
    }
    return true;  // All characters were within the ASCII range
}

/**
 * Checks if the given IP address string is valid and the port number is within the acceptable range.
 *
 * @param ipAddress The string containing the IP address and port in the format "x.x.x.x:y".
 * @return True if the format is correct and both IP and port are valid, False otherwise.
 */
bool isValidIpAddressAndPort(const std::string& ipAddress) {
    size_t colonPos = ipAddress.find(':');
    if (colonPos == std::string::npos) {
        return false;  // No colon found, invalid format
    }

    std::string ipPart = ipAddress.substr(0, colonPos);
    std::string portPart = ipAddress.substr(colonPos + 1);

    // Check if port part is numeric and within the valid range
    if (!std::all_of(portPart.begin(), portPart.end(), ::isdigit)) {
        return false;  // Port part is not entirely numeric
    }
    int port = std::stoi(portPart);
    if (port < 1 || port > 65535) {
        return false;  // Port number is out of valid range
    }

    // Split the IP part into its components
    std::stringstream ss(ipPart);
    std::string segment;
    std::vector<std::string> segments;

    while (std::getline(ss, segment, '.')) {
        segments.push_back(segment);
    }

    if (segments.size() != 4) {
        return false;  // IP part does not have exactly four octets
    }

    for (const std::string& str : segments) {
        if (str.empty() || !std::all_of(str.begin(), str.end(), ::isdigit)) {
            return false;  // Segment is not numeric
        }

        int num = std::stoi(str);
        if (num < 0 || num > 255) {
            return false;  // Segment is out of byte range
        }
    }

    return true;  // Passed all checks
}
