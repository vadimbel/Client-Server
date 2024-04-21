#include "network_utils.h"
#include "Base64Wrapper.h"

int main() {

    // read and recieve data from files 
    std::unordered_map<std::string, std::string> data = openFile();
    // if data recieved from files is empty => error
    if (data.empty()) {
        std::cout << "FILES ERROR - usernames, EXIT." << std::endl;
        return -1;
    }

    std::string errors = "";        // string stores errors during client-server connection
    unsigned int retryCount = 0;    // client will try to connect to server up to 3 times
    int res = 0;                    // result of client-server connection

    while (retryCount < appdata::maxRetry) {
        res = connectToServer(data, errors);
        if (res == 0)
            break;
        retryCount++;
    }
    std::cout << "FINAL RES result : " << res << std::endl;
    if (!errors.empty())
        std::cout << "ERRORS : " << std::endl;
        std::cout << errors << std::endl;

    return 0;
}

