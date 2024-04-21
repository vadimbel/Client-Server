#include "network_utils.h"
#include "utils.h"
#include "headerProtocol.h"
#include "registerReconnectReq.h"
#include "sendPublicKeyReq.h"
#include "RSAkeys.h"
#include "AESWrapper.h"
#include "SendEncryptedFileContent.h"
#include "cksum.h"
#include "CRCreq.h"
#include <limits>

/**
 * This is the main function performs the client connection to server.
 */
int connectToServer(std::unordered_map<std::string, std::string> data, std::string& errors) {
	// create copy of the data recieved from files
	std::unordered_map<std::string, std::string> copyData;
	for (const auto& pair : data)
		copyData[pair.first] = pair.second;

	// extract necessary data
	std::string IPaddress = copyData["IPaddress"];		// client IP address
	std::string port = copyData["port"];				// client port
	std::string action = copyData["action"];			// registration / reconnect

	// Create a binary TCP connection
	boost::asio::io_context io_context;
	tcp::resolver resolver(io_context);
	tcp::socket s(io_context);

	try {
		boost::asio::connect(s, resolver.resolve(IPaddress, port));
		// convert 'action' (registration/reconnect) into request code
		unsigned int requestCode = setRequestCode(action);

		uint32_t serverCRC = 0;			// uint32_t for CRC calculation
		int CRCattempts = 0;			// CRC calculations attempts

		// create protocol header (defulat clientID, version, code, payloadSize)
		HeaderProtocol header(appdata::clientVersion, appdata::UNDEFINED, appdata::UNDEFINED);
		// Define a unique_ptr for Payload base class
		std::unique_ptr<Payload> payload;

		// create objects to store RSA keys and encrypted AES key that will be received from server
		std::pair<CryptoPP::RSA::PrivateKey, CryptoPP::RSA::PublicKey> keys;
		CryptoPP::RSA::PrivateKey privateKey;
		CryptoPP::RSA::PublicKey publicKey;
		std::vector<unsigned char> encryptedAESkey;

		// result of reading files must be one of those request codes
		if (requestCode != appdata::registrationCode and requestCode != appdata::reconectCode) {
			errors += "Failure translate request code, EXIT.";
			return 1;		// Return failure
		}

		// main loop performs the client-server connection 
		// client requests will be sent to server until connection is closed (requestCode == appdata::STOP)
		while (requestCode != appdata::STOP) {
			// if registration request
			if (requestCode == appdata::registrationCode) {

				// set header request code for registration request
				header.setCode(appdata::registrationCode);

				// set registration request payload pointer
				payload = std::make_unique<RegisterReconnectReq>(copyData["username"]);

				// transfer registration request data (header & payload) using 'sendRegistrationHeaderPayload', check for data transfer error
				int result = sendRegistrationHeaderPayload(s, header, *payload);
				if (result == 1) {
					errors += appdata::serverErrorMessage + " - registration data transfer.\n";
					return 1;
				}
				
				// receieve response for data transfer from server - inform client if data (header+payload) reached to server
				result = dataTransferResponse(s, header);
				
				if (result == 1) {
					errors += appdata::serverErrorMessage + " - registration data transfer.\n";
					return 1;
				}
				
				// receive response for registration request
				result = registrationResponse(s, header);
				if (result == 1) {
					errors += appdata::serverErrorMessage + " - registration failed, username exist.\n";
					return 1;
				}
				
				requestCode = appdata::sendPublicKeyCode;
			}
			else if (requestCode == appdata::sendPublicKeyCode) {

				// generate RSA keys (using 'generateKeys' from RSAkeys.cpp file)
				keys = generateKeys();
				privateKey = keys.first;
				publicKey = keys.second;

				// get clientID from header object and convert it to hexString for me.info file
				std::array<uint8_t, 16>  clientID = header.getClientID();
				std::vector<unsigned char> uuidBytes(clientID.begin(), clientID.end());
				std::string clientIDHex = bytesToHexString(uuidBytes);

				// create me.info file using 'createMeInfoFile' function from RSAkeys.cpp
				createMeInfoFile(copyData["username"], clientIDHex, privateKey);

				// create priv.key file using 'createPrivKeyFile' function from RSAkeys.cpp
				createPrivKeyFile(privateKey);

				// convert RSA public key to 64base string using functions from RSAkeys.cpp file
				std::string publicKeyDERFormat = keyToDERString(publicKey);		// to DER format
				std::string publicKey64Base = encode(publicKeyDERFormat);		// to 64 base
				
				// set public RSA key request payload pointer (contains fields : username, RSA public key 64base format)
				payload = std::make_unique<SendPublicKeyReq>(copyData["username"], publicKey64Base);

				// set header request code for public RSA key request
				header.setCode(appdata::sendPublicKeyCode);

				// transfer public RSA key request data
				int result = sendPublicKeyHeaderPayload(s, header, *payload);
				if (result == 1) {
					errors += appdata::serverErrorMessage + " - public key data transfer fail.\n";
					return 1;
				}
				// receieve response for data transfer from server - inform client if data (header+payload) reached to server
				result = dataTransferResponse(s, header);
				if (result == 1) {
					errors += appdata::serverErrorMessage + " - public key accept data fail.\n";
					return 1;
				}
				// receieve public RSA key response
				// if client received data sent from server successfully, 'encryptedAESkey' will be updated to the AES key sent from server
				result = publicRSAKeyResponse(s, header, encryptedAESkey);
				if (result == 1) {
					errors += appdata::serverErrorMessage + " - public key response fail.\n";
					return 1;
				}

				requestCode = appdata::sendFileCode;
			}
			else if (requestCode == appdata::sendFileCode) {

				// read file content (file with filepath from transfer.info file) using 'readFileContent' from utils.cpp file
				std::string content = readFileContent(copyData["filePath"]);			// file content before encryption (string format)
				
				// get private RSA key, decrypt (encrypted) aes key received from server using private RSA key
				std::vector<unsigned char> decryptedAESkey = DecryptAESKeyWithRSAPrivateKey(privateKey, encryptedAESkey);
				const unsigned char* aesKey = decryptedAESkey.data();
				
				// encrypt file content using decrypted aes key using AESWrapper.cpp file
				AESWrapper aesWrapper(aesKey, AESWrapper::DEFAULT_KEYLENGTH);	// AESWrapper instance
				std::string encryptedContentBinary = aesWrapper.encrypt(content.c_str(), content.length());	// encrypt file content (binary data)

				// set header request code to encrypted file request
				header.setCode(appdata::sendFileCode);

				// create all attributes needed for send file request (for payload pointer)
				std::string filePath = copyData["filePath"];
				std::string fileName = std::filesystem::path(filePath).filename().string();		// extract file name from filePath

				uint32_t contentSize = static_cast<uint32_t>(encryptedContentBinary.length());		// size of encrypted content
				uint32_t originalFileSize = static_cast<uint32_t>(content.length());			// size of original file content before encryption
				
				// one packet will be able to store up to 'maxContentPerPacket' file size, define total amount of packets need to be passed
				uint16_t totalPackets;
				if (contentSize % appdata::maxContentPerPacket == 0)
					totalPackets = contentSize / appdata::maxContentPerPacket;
				else
					totalPackets = (contentSize / appdata::maxContentPerPacket) + 1;

				// loop that sends all chucks of file content
				for (uint16_t packetNumber = 0; packetNumber < totalPackets; packetNumber++) {
					// Calculate start and end indices for the part of the encrypted content to be sent in this packet
					size_t start = packetNumber * appdata::maxContentPerPacket;
					size_t end = std::min(start + appdata::maxContentPerPacket, static_cast<size_t>(contentSize));

					// Extract part of the encrypted content string
					std::string partOfEncryptedContent = encryptedContentBinary.substr(start, end - start);
					
					// Convert string to vector<uint8_t>
					std::vector<uint8_t> messageContent(partOfEncryptedContent.begin(), partOfEncryptedContent.end());

					// set reqeust payload pointer with 'partOfEncryptedContent' for this packet
					payload = std::make_unique<SendEncryptedFileContent>(contentSize, originalFileSize, packetNumber, totalPackets,
						messageContent, filePath);

					// transfer packet of encrypted file request data (header, payload)
					int result = sendEncryptedFileContentHeaderPayload(s, header, *payload);
					if (result == 1) {
						errors += appdata::serverErrorMessage + " - file packet lost.\n";
						return 1;
					}
					// receive response from server if all file content transfered succesfully
					result = dataTransferResponse(s, header);
					if (result == 1) {
						errors += appdata::serverErrorMessage + " - loss file content while transfer.\n";
						return 1;
					}
				}
				// receieve encrypted file response (server CRC calculation will be received in this part)
				int result = encryptedFileContentResponse(s, header, serverCRC);
				if (result == 1) {
					errors += appdata::serverErrorMessage + " - server CRC calculation fail.\n";
					return 1;
				}

				// calculate client CRC : convert file content from string to binary format, then calculate client CRC
				std::vector<unsigned char> binaryContent(content.begin(), content.end());
				uint32_t clientCRC = calculate_checksum(binaryContent);		// using function from cksum.cpp

				// send valid CRC to server
				if (serverCRC == clientCRC) {
					// set header valid CRC code
					header.setCode(appdata::validCRCcode);

					// set payload pointer for valid CRC request
					payload = std::make_unique<CrcReq>(filePath);

					// send request data (header & payload)
					result = sendCRCHeaderPayload(s, header, *payload);
					if (result == 1) {
						errors += appdata::serverErrorMessage + " - failed transfer CRC data.\n";
						return 1;
					}
					// receive response from server
					result = receiveCRCresponse(s, header);
					if (result == 1) {
						errors += appdata::serverErrorMessage + " - failed receive CRC answer.\n";
						return 1;
					}

					s.close();
					return 0;
				}
				else if (serverCRC != clientCRC and CRCattempts < appdata::maxRetry) {
					// CRC did not mathced, perform 'sendFile' request again up to 3 times
					errors += appdata::serverErrorMessage + " - CRC missmatch.\n";

					// set header invalid CRC code
					header.setCode(appdata::invalidCRCcode);

					// set payload pointer for invalid CRC request
					payload = std::make_unique<CrcReq>(filePath);

					result = sendCRCHeaderPayload(s, header, *payload);
					if (result == 1) {
						errors += appdata::serverErrorMessage + " - failed transfer CRC data.\n";
						return 1;
					}

					CRCattempts++;				// increase CRC calculation attemps and send again
					requestCode = appdata::sendFileCode;
				}
				else {
					errors += appdata::serverErrorMessage + " - ABORT.\n";

					// set header 4th invalid CRC request
					header.setCode(appdata::errorCRCcode);

					// set payload pointer for invalid CRC request
					payload = std::make_unique<CrcReq>(filePath);

					result = sendCRCHeaderPayload(s, header, *payload);
					if (result == 1) {
						errors += appdata::serverErrorMessage + " - failed transfer CRC data.\n";
						return 1;
					}

					s.close();
					return 0;
				}
			}
			else if (requestCode == appdata::reconectCode) {

				// set header request code for reconnect request
				header.setCode(appdata::reconectCode);

				// set header 'clientID' attribute to be the clientID was read from 'me.info' file
				std::string clientID = copyData["clientID"];
				std::array<uint8_t, 16> clientIDArray = hexStringToByteArray(clientID);
				header.setClientID(clientIDArray);

				// set reconnect request payload pointer 
				payload = std::make_unique<RegisterReconnectReq>(copyData["username"]);

				
				// transfer reconnect (same as registration) request data (header & payload), check for data transfer error
				int result = sendRegistrationHeaderPayload(s, header, *payload);
				if (result == 1) {
					errors += appdata::serverErrorMessage + " - reconnect data transfer.\n";
					return 1;
				}
				
				// receieve reconnect response
				result = dataTransferResponse(s, header);
				if (result == appdata::reconnectDenied) {
					errors += appdata::serverErrorMessage + " - failed reconnect with provided username1.\n";
					requestCode = appdata::registrationCode;	// failed reconnect with provided username - perform registration
				}
				else if (result == 1) {
					errors += appdata::serverErrorMessage + " - failed reconnect with provided username2.\n";
					return 1;
				}
				
				// reconnect request accepted, receive encrypted aes key
				result = publicRSAKeyResponse(s, header, encryptedAESkey);
				if (result == 1) {
					errors += appdata::serverErrorMessage + " - failed receiving AES key.\n";
					return 1;
				}

				privateKey = readPrivateKeyFromFile(appdata::privKey);

				requestCode = appdata::sendFileCode;
			}
			else {
				requestCode = appdata::STOP;
			}
		}
		
		s.close();
		return 0;
	}
	catch (std::exception& e) {
		errors += "Failed connect to server \n";
		std::cout << errors << std::endl;
		s.close();  // Close the socket
		return 1;  // Return failure
	}

	s.close();
	return 0;
}

/**
 * @brief Receives and processes the response header from the server after data has been sent.
 *
 * This function attempts to receive a response from the server to determine the success or
 * failure of a previously sent request. It reads the header to extract the status code and
 * then verifies whether the received clientID matches the expected clientID.
 *
 * @param s: Reference to the socket used for communication with the server.
 * @param header: Reference to the HeaderProtocol object.
 *
 * @return int Returns 0 on success, indicating that the server received and validated the data
 *         successfully. Returns 1 if any error occurs during header reception, reading the payload,
 *         or if the validation of clientID or statusCode indicates a failure.
 */
int dataTransferResponse(boost::asio::ip::tcp::socket& s, HeaderProtocol& header) {
	boost::system::error_code ec;		// handle boost::asio errors

	// get response header using 'receiveHeader' function, unpack the returned tuple
	auto [version, statusCode, payloadSize, errorMsg] = receiveHeader(s);
	// if receiving response header failed
	if (version == appdata::basicFAIL and statusCode == appdata::basicFAIL and payloadSize == appdata::basicFAIL and errorMsg == appdata::undefined) {
		return 1;
	}

	// try reconnect with username that doesnt exist in server DB
	if (statusCode == appdata::reconnectDenied) {
		return appdata::reconnectDenied;
	}

	// statusCode must be appdata::receivedMsgValid
	if (statusCode != appdata::receivedMsgValid) {
		return 1;
	}

	// read clientID based on payload size received in header, then check if match to clinets 'clientID' that sent the request
	std::vector<unsigned char> payloadBuffer(payloadSize);

	boost::asio::read(s, boost::asio::buffer(payloadBuffer), ec);
	if (ec) {
		return 1; // reading payload failed, return failure
	}

	// compare clientID received from server with current client
	if (!header.compareClientID(payloadBuffer)) {
		return 1;
	}

	// if clientID matched and received valid response code
	if (statusCode == appdata::receivedMsgValid) {
		return 0;	// return success
	}
	else {
		return 1;	// else return failure
	}
}

/**
 * Sends a CRC request over a TCP socket, including the header and filename as payload.
 * Ensures payload matches expected type before sending.
 *
 * @param s : TCP socket used for communication.
 * @param header : Header details for the CRC request.
 * @param payload : Payload to be sent; expected to be of type CrcReq.
 *
 * @return Returns 0 on success, 1 on failure (e.g., type mismatch, send error).
 *
 * This function casts the generic Payload to a CrcReq type, retrieves the filename,
 * sets the header's payload size, and sends the data. If any operation fails, such as
 * an incorrect payload type or a send error, the function returns 1.
 */
int sendCRCHeaderPayload(boost::asio::ip::tcp::socket& s, HeaderProtocol& header, const Payload& payload) {
	boost::system::error_code ec;

	// Cast the base Payload pointer to a CrcReq pointer
	const CrcReq* specificPayload = dynamic_cast<const CrcReq*>(&payload);
	if (!specificPayload)
		return 1; // Return failure if casting failed

	// Retrieve filename from the payload
	std::string filename = specificPayload->getFileName();

	// Convert filename to binary data
	std::vector<unsigned char> binaryFilename(filename.begin(), filename.end());

	// Set the payload size in the header according to the binary filename size
	header.setPayloadSize(binaryFilename.size());

	binaryFilename.push_back('\0'); // Append null terminator for binary data

	// Send request header part
	int headerResult = sendHeaderToServer(s, header);
	if (headerResult != 0)
		return 1; // Return failure if sending the header failed

	// Send the binary filename as part of the payload
	boost::asio::write(s, boost::asio::buffer(binaryFilename), ec);
	if (ec)
		return 1; // Return failure if sending the filename failed

	return 0; // Return success
}


/**
 * Receives a CRC response from a TCP socket, including its header and any associated payload.
 *
 * @param s TCP socket used for communication.
 * @param header Header object to be populated with response details.
 *
 * @return Returns 0 on successful receipt and validation of the CRC response, 1 if any errors occur.
 *
 * This function retrieves the response header and validates its components. If the header indicates
 * a failure or if the CRC status code does not match the expected 'receivedMsgValid' code, the function
 * returns 1. It then reads the payload according to the specified size in the header. If reading the payload
 * fails due to an error, the function also returns 1. Success is indicated by returning 0.
 */

int receiveCRCresponse(boost::asio::ip::tcp::socket& s, HeaderProtocol& header) {
	boost::system::error_code ec;

	// get response header using 'receiveHeader' function, unpack the returned tuple
	auto [version, statusCode, payloadSize, errorMsg] = receiveHeader(s);
	// if receiving response header failed
	if (version == appdata::basicFAIL and statusCode == appdata::basicFAIL and payloadSize == appdata::basicFAIL and errorMsg == appdata::undefined)
		return 1;
	// if response returned failure code
	if (statusCode != appdata::receivedMsgValid)
		return 1;

	// read the payload based on the payload size
	std::vector<unsigned char> payloadBuffer(payloadSize);
	boost::asio::read(s, boost::asio::buffer(payloadBuffer), ec);
	if (ec)
		return 1; // Return failure if reading payload failed

	return 0;
}

/**
 * Sends encrypted file content along with metadata such as file size, packet number, and total packets
 * using a TCP socket. It also handles the endianess conversion for numerical data.
 *
 * @param s TCP socket used for the data transmission.
 * @param header HeaderProtocol object that encapsulates details like payload size.
 * @param payload Generic Payload object that should be cast to SendEncryptedFileContent to access file content data.
 *
 * @return Returns 0 if the file content and header are sent successfully, 1 otherwise.
 *
 * This function dynamically casts the passed generic Payload to SendEncryptedFileContent to extract attributes
 * necessary for sending file content. It then calculates the size of the payload, sends the header,
 * and sequentially sends the file content and associated metadata. Errors during any send operation result in a
 * return value of 1, indicating failure.
 */
int sendEncryptedFileContentHeaderPayload(boost::asio::ip::tcp::socket& s, HeaderProtocol& header, const Payload& payload) {
	boost::system::error_code ec;

	// Create SendEncryptedFileContent payload
	const SendEncryptedFileContent* specificPayload = dynamic_cast<const SendEncryptedFileContent*>(&payload);
	if (!specificPayload)
		return 1;

	// Retrieve payload attributes
	uint32_t contentSize = specificPayload->getContentSize();
	uint32_t originalFileSize = specificPayload->getOriginalFileSize();
	uint16_t packetNumber = specificPayload->getPacketNumber();
	uint16_t totalPackets = specificPayload->getTotalPackets();
	std::vector<uint8_t> messageContent = specificPayload->getMessageContent();
	std::string fileName = specificPayload->getFileName();

	// Convert filename to binary data
	std::vector<unsigned char> binaryFileName(fileName.begin(), fileName.end());

	// Calculate total payload size
	header.setPayloadSize(sizeof(contentSize) + sizeof(originalFileSize) + sizeof(packetNumber) + sizeof(totalPackets) +
		messageContent.size() + binaryFileName.size());

	binaryFileName.push_back('\0'); // Append null terminator for binary data

	// Send header data
	int result = sendHeaderToServer(s, header);
	if (result != 0)
		return 1; // Return failure if header could not be sent

	// Prepare buffer for payload data
	std::vector<unsigned char> payloadBuffer;

	// Insert the converted attributes into the buffer
	payloadBuffer.insert(payloadBuffer.end(), reinterpret_cast<unsigned char*>(&contentSize), reinterpret_cast<unsigned char*>(&contentSize) + sizeof(contentSize));
	payloadBuffer.insert(payloadBuffer.end(), reinterpret_cast<unsigned char*>(&originalFileSize), reinterpret_cast<unsigned char*>(&originalFileSize) + sizeof(originalFileSize));
	payloadBuffer.insert(payloadBuffer.end(), reinterpret_cast<unsigned char*>(&packetNumber), reinterpret_cast<unsigned char*>(&packetNumber) + sizeof(packetNumber));
	payloadBuffer.insert(payloadBuffer.end(), reinterpret_cast<unsigned char*>(&totalPackets), reinterpret_cast<unsigned char*>(&totalPackets) + sizeof(totalPackets));
	payloadBuffer.insert(payloadBuffer.end(), messageContent.begin(), messageContent.end());
	payloadBuffer.insert(payloadBuffer.end(), binaryFileName.begin(), binaryFileName.end());

	// Send the payload buffer
	boost::asio::write(s, boost::asio::buffer(payloadBuffer), ec);
	if (ec)
		return 1; // Indicate failure

	return 0;
}


/**
 * Receives a response for an encrypted file content transfer, including the server's calculated CRC,
 * from a TCP socket. This function also extracts and validates the server's response.
 *
 * @param s TCP socket used for the communication.
 * @param header HeaderProtocol object used to handle the response metadata.
 * @param serverCRC Reference to store the CRC received from the server for validation.
 *
 * @return Returns 0 if the response is successfully received and validated, 1 otherwise.
 *
 * This function first retrieves the header of the response to determine the success of the file transfer.
 * It then reads the payload, which includes the clientID, content size, and CRC. The function checks if the
 * response status code matches the expected code for a successful file transfer. If any step fails, such as
 * an error in receiving the header or payload, or if the status code indicates failure, the function returns 1.
 */

int encryptedFileContentResponse(boost::asio::ip::tcp::socket& s, HeaderProtocol& header, uint32_t& serverCRC) {
	boost::system::error_code ec;

	// get response header using 'receiveHeader' function, unpack the returned tuple
	auto [version, statusCode, payloadSize, errorMsg] = receiveHeader(s);
	// if receiving response header failed
	if (version == appdata::basicFAIL and statusCode == appdata::basicFAIL and payloadSize == appdata::basicFAIL and errorMsg == appdata::undefined)
		return 1;
	// if registration returned failure code
	if (statusCode != appdata::fileReceivedCRCsuccess)
		return 1;

	// read the payload based on the payload size
	std::vector<unsigned char> payloadBuffer(payloadSize);
	boost::asio::read(s, boost::asio::buffer(payloadBuffer), ec);
	if (ec)
		return 1; // Return failure if reading payload failed

	// Extract clientID
	std::string clientID(payloadBuffer.begin(), payloadBuffer.begin() + 16);

	// Extract content size
	uint32_t contentSize = *reinterpret_cast<uint32_t*>(&payloadBuffer[16]);

	// Extract CRC
	uint32_t CRC = *reinterpret_cast<uint32_t*>(&payloadBuffer[20]);

	// Extract file name (up to 255 characters, null-terminated)
	std::string fileName(reinterpret_cast<char*>(&payloadBuffer[24]), payloadSize - 24 - 1); // -1 to exclude null terminator

	// save serverCRC calculation
	serverCRC = CRC;

	return 0;
}

/**
 * Sends a public key along with a username over a TCP socket. It first sends a header followed by the actual payload.
 *
 * @param s Reference to the TCP socket used for the communication.
 * @param header Reference to the HeaderProtocol object, which needs to have its payload size set based on the data being sent.
 * @param payload Reference to the Payload object, which should be of type SendPublicKeyReq.
 *
 * @return Returns 0 on successful data transfer, 1 on failure.
 *
 * This function attempts to send a username and a public RSA key to a client. It first validates and casts the generic
 * Payload to a SendPublicKeyReq. After setting the appropriate payload size in the header, it sends the header and then
 * the payload data. The username and public key are both terminated with a null character before sending.
 * If any part of the process fails, such as a dynamic cast failure or an error during the send operation, the function
 * returns 1.
 */
int sendPublicKeyHeaderPayload(boost::asio::ip::tcp::socket& s, HeaderProtocol& header, const Payload& payload) {
	boost::system::error_code ec;

	// Create SendPublicKeyReq payload
	const SendPublicKeyReq* specificPayload = dynamic_cast<const SendPublicKeyReq*>(&payload);
	if (!specificPayload)
		return 1;

	// Retrieve payload attributes
	std::string name = specificPayload->getName();
	std::string publicKey = specificPayload->getPublicKey();

	// Convert strings to binary data
	std::vector<unsigned char> binaryName(name.begin(), name.end());
	std::vector<unsigned char> binaryPublicKey(publicKey.begin(), publicKey.end());

	// Set header payloadSize attribute value according to the total size of the binary data
	header.setPayloadSize(binaryName.size() + binaryPublicKey.size());

	// Append null terminators for binary data
	binaryName.push_back('\0');
	binaryPublicKey.push_back('\0');

	// Send request header part
	int headerResult = sendHeaderToServer(s, header);
	if (headerResult != 0)
		return 1; // Return failure if header could not be sent

	// Send payload part of the request (username, public RSA key)
	boost::asio::write(s, boost::asio::buffer(binaryName), ec);
	if (ec)
		return 1; // Return failure if error occurred while sending name

	boost::asio::write(s, boost::asio::buffer(binaryPublicKey), ec);
	if (ec)
		return 1; // Return failure if error occurred while sending public key

	return 0; // Success
}


/**
 * Receives and handles the server response after sending a public RSA key request, extracting the encrypted AES key.
 *
 * @param s Reference to the TCP socket used for communication.
 * @param header Reference to the HeaderProtocol object used to interpret the response header.
 * @param encryptedAESkey Vector to store the received encrypted AES key.
 *
 * @return Returns 0 on successful reception and processing of the encrypted AES key, 1 if any error occurs.
 *
 * This function processes the server's response to a public RSA key request. It first retrieves the response header,
 * validates the status code, and checks for successful AES key transmission. If successful, it reads the payload
 * which includes the client ID and the encrypted AES key. The function then extracts and stores the encrypted AES key
 * into the provided vector. If any part of this process fails, such as an error in reading the response or a status
 * code mismatch, the function returns 1.
 */

int publicRSAKeyResponse(boost::asio::ip::tcp::socket& s, HeaderProtocol& header, std::vector<unsigned char>& encryptedAESkey) {
	boost::system::error_code ec;

	// get response header using 'receiveHeader' function, unpack the returned tuple
	auto [version, statusCode, payloadSize, errorMsg] = receiveHeader(s);
	// if receiving response header failed
	if (version == appdata::basicFAIL and statusCode == appdata::basicFAIL and payloadSize == appdata::basicFAIL and errorMsg == appdata::undefined)
		return 1;

	// response if valid only when : 
	// 1. receive response for public rsa key request when register.
	// 2. receive response for reconnect reqeust
	if (statusCode != appdata::receivedPublicKeySendAES and statusCode != appdata::acceptReconnectSendAES)
		return 1;

	// read the payload based on the payload size
	std::vector<unsigned char> payloadBuffer(payloadSize);
	boost::asio::read(s, boost::asio::buffer(payloadBuffer), ec);
	if (ec)
		return 1; // Return failure if reading payload failed

	// Extract clientID
	std::vector<unsigned char> clientID(payloadBuffer.begin(), payloadBuffer.begin() + 16);
	
	// Extract encrypted AES key
	std::vector<unsigned char> encryptedAESKeyReceived(payloadBuffer.begin() + 16, payloadBuffer.end());

	// Copy the received encrypted AES key to the encryptedAESkey parameter
	encryptedAESkey = encryptedAESKeyReceived;

	return 0;
}

/**
 * This function will be used in 'connectToServer' function on registration/reconnect requests (via requestCode == appdata::registrationCode or
 * appdata::reconnect).
 * function will use 'sendHeaderToServer' to transfer the header data according to protocol, then send payload (name).
 * 
 * @param s: The TCP socket connected to the server, used for sending the request and receiving the response.
 * @param header: A reference to a HeaderProtocol object, which will be used to set the registration/reconnect requests.
 * @param payload: A constant reference to a Payload object that will be pointing to specific request object.
 *
 * return 0=success or 1=failure
 */
int sendRegistrationHeaderPayload(boost::asio::ip::tcp::socket& s, HeaderProtocol& header, const Payload& payload) {
	boost::system::error_code ec;

	// Try to cast payload to RegisterReconnectReq type
	const RegisterReconnectReq* specificPayload = dynamic_cast<const RegisterReconnectReq*>(&payload);
	if (!specificPayload) {
		return 1; // Failure due to type mismatch
	}

	// Get payload attributes (name), encode it to bytes
	std::string name = specificPayload->getName();
	std::vector<unsigned char> encodedName(name.begin(), name.end()); // Directly converting string to bytes

	// Calculate payload size as the size of the encoded name
	header.setPayloadSize(static_cast<uint32_t>(encodedName.size()));

	// Send header data to the server
	int headerResult = sendHeaderToServer(s, header);
	if (headerResult != 0) {
		return 1; // Failure in sending header
	}

	// Append null terminator to the encoded name for string termination
	encodedName.push_back('\0');

	// Send the encoded name to the server
	boost::asio::write(s, boost::asio::buffer(encodedName), ec);
	if (ec) {
		return 1; // Failure in sending data
	}

	return 0; // Success
}


/**
 * this function receive the server response for registration request.
 * using 'receiveHeader' for receiving registration response header.
 * receive payload inside the function.
 * 
 * if header and payload received successfully, it updates header object attribute : clientID
 *
 * @param s: The TCP socket connected to the server, used for sending the request and receiving the response.
 * @param header: A reference to a HeaderProtocol object.
 *
 * return 0=success or 1=failure
 */
int registrationResponse(boost::asio::ip::tcp::socket& s, HeaderProtocol& header) {
	boost::system::error_code ec;		// handle boost::asio errors

	// get response header using 'receiveHeader' function, unpack the returned tuple
	auto [version, statusCode, payloadSize, errorMsg] = receiveHeader(s);
	// if receiving response header failed
	if (version == appdata::basicFAIL and statusCode == appdata::basicFAIL and payloadSize == appdata::basicFAIL and errorMsg == appdata::undefined)
		return 1;
	// statusCode must be this value
	if (statusCode != appdata::registrationSuccess)
		return 1;

	// read the payload based on the payload size
	std::vector<unsigned char> payloadBuffer(payloadSize);

	boost::asio::read(s, boost::asio::buffer(payloadBuffer), ec);
	if (ec)
		return 1; // Return failure if reading payload failed

	// copy clientID created in server to client header object
	std::string clientIDStr;
	if (payloadSize == appdata::clientIDBytesSize) {			// chec that UUID with size = 16 bytes

		// set header clientID
		std::array<uint8_t, appdata::clientIDBytesSize> newClientID;
		std::copy(payloadBuffer.begin(), payloadBuffer.end(), newClientID.begin());
		header.setClientID(newClientID);
	}
	else
		return 1; // Return failure

	return 0;
}

/**
 * this function will be used in multiple requests, sending the header data to server according to protocol.
 *
 * @param s: The TCP socket connected to the server, used for sending the request and receiving the response.
 * @param header: A reference to a HeaderProtocol object.
 *
 * return 0=success or 1=failure
 */
int sendHeaderToServer(boost::asio::ip::tcp::socket& s, const HeaderProtocol& header) {
	boost::system::error_code ec;

	// Convert header attributes to little endian
	uint16_t codeLE = toLittleEndian16(header.getCode());
	uint32_t payloadSizeLE = toLittleEndian32(header.getPayloadSize());

	// Prepare version and clientID
	uint8_t version = header.getVersion();
	auto clientID = header.getClientID();

	// Prepare the buffer for header data
	std::vector<unsigned char> headerBuffer;

	// Calculate the size of the buffer including code, version, clientID, and payload size
	const std::size_t headerBufferSize = sizeof(codeLE) + sizeof(version) + clientID.size() + sizeof(payloadSizeLE);
	headerBuffer.reserve(headerBufferSize);

	// Insert the code, version, clientID, and payload size into the buffer
	headerBuffer.insert(headerBuffer.end(), reinterpret_cast<unsigned char*>(&codeLE), reinterpret_cast<unsigned char*>(&codeLE) + sizeof(codeLE));
	headerBuffer.push_back(version);
	headerBuffer.insert(headerBuffer.end(), clientID.begin(), clientID.end());
	headerBuffer.insert(headerBuffer.end(), reinterpret_cast<unsigned char*>(&payloadSizeLE), reinterpret_cast<unsigned char*>(&payloadSizeLE) + sizeof(payloadSizeLE));

	// Send the header buffer
	boost::asio::write(s, boost::asio::buffer(headerBuffer), ec);
	if (ec)
		return 1; // Indicate failure
	
	return 0; // Success
}

/**
 * this function will be used in multiple requests, receive header data from server.
 *
 * @param s The TCP socket connected to the server, used for sending the request and receiving the response.
 */
std::tuple<uint8_t, uint16_t, uint32_t, std::string> receiveHeader(boost::asio::ip::tcp::socket& s) {
	boost::system::error_code ec;

	// Define the header structure : version + status code + payload size
	const size_t headerSize = appdata::versionBytesSize + appdata::statusCodeBytesSize + appdata::payloadSizeBytesSize;
	std::vector<unsigned char> headerBuffer(headerSize);

	// Attempt to read the header
	boost::asio::read(s, boost::asio::buffer(headerBuffer), ec);
	if (ec) {
		// If an error occurs while try to read header, return default values and the error message
		return { appdata::basicFAIL, appdata::basicFAIL, appdata::basicFAIL, appdata::undefined};
	}

	// Extract version, status code, and payload size
	uint8_t version = *reinterpret_cast<uint8_t*>(&headerBuffer[0]);
	uint16_t statusCode = *reinterpret_cast<uint16_t*>(&headerBuffer[1]);
	uint32_t payloadSize = *reinterpret_cast<uint32_t*>(&headerBuffer[3]);

	// If successful, return the extracted values with an empty error message
	return { version, statusCode, payloadSize, "Success receiving header" };
}


/**
 * Converts a vector of uint8_t to a hexadecimal string.
 * @param data The vector of uint8_t containing the binary data.
 * @return A string representing the hexadecimal values of the data.
 */
std::string toHexString(const std::vector<uint8_t>& data) {
	std::stringstream hexStream;
	hexStream << std::hex << std::setfill('0');
	for (auto byte : data) {
		hexStream << std::setw(2) << static_cast<int>(byte);
	}
	return hexStream.str();
}

/**
 * Converts a vector of unsigned char to a hexadecimal string.
 * Each byte in the vector is represented as two hexadecimal digits.
 * @param uuidBytes The vector of unsigned char to be converted.
 * @return A hexadecimal string representation of the input bytes.
 */
std::string bytesToHexString(const std::vector<unsigned char>& uuidBytes) {
	std::ostringstream hexStream;
	hexStream << std::hex << std::setfill('0');
	for (auto byte : uuidBytes) {
		hexStream << std::setw(2) << static_cast<int>(byte);
	}
	return hexStream.str();
}

/**
 * Maps a string representing an action to its corresponding request code.
 * @param action A string key representing the action (e.g., "RECONNECT", "REGISTRATION").
 * @return The request code associated with the action.
 */
unsigned int setRequestCode(std::string action) {
	if (action == appdata::RECONNECT)
		return appdata::reconectCode;
	else if (action == appdata::REGISTRATION)
		return appdata::registrationCode;
	else
		return appdata::UNDEFINED;
}

/**
 * Ensures a 16-bit integer is in little-endian format.
 * If the system is big-endian, it swaps the byte order; otherwise, it returns the value unchanged.
 * @param value The 16-bit integer to convert.
 * @return The 16-bit integer in little-endian byte order.
 */
uint16_t toLittleEndian16(uint16_t value) {
	if (isLittleEndian()) {
		return value;
	}
	else {
		return ((value & 0xFF00) >> 8) |
			((value & 0x00FF) << 8);
	}
}

/**
 * Ensures a 32-bit integer is in little-endian format.
 * If the system is big-endian, it swaps the byte order; otherwise, it returns the value unchanged.
 * @param value The 32-bit integer to convert.
 * @return The 32-bit integer in little-endian byte order.
 */
uint32_t toLittleEndian32(uint32_t value) {
	if (isLittleEndian()) {
		return value;
	}
	else {
		return ((value & 0xFF000000) >> 24) |
			((value & 0x00FF0000) >> 8) |
			((value & 0x0000FF00) << 8) |
			((value & 0x000000FF) << 24);
	}
}

/**
 * Determines if the system is little-endian.
 * @return True if the system is little-endian, false if it is big-endian.
 */
bool isLittleEndian() {
	uint32_t num = 1;
	return *(reinterpret_cast<uint8_t*>(&num)) == 1;
}

/**
 * Checks and handles Boost ASIO error codes.
 * If an error is present, it throws an exception with the error message.
 * @param ec The error code to check.
 */
void checkAndHandleError(const boost::system::error_code& ec) {
	if (ec) {
		throw std::runtime_error("errorMessage : " + ec.message());
	}
}

/**
 * Converts a 32-character hexadecimal string into an array of 16 bytes.
 * Throws an exception if the input string does not conform to the expected length.
 * @param hex The hexadecimal string to convert.
 * @return An array of 16 bytes derived from the hexadecimal string.
 */
std::array<uint8_t, 16> hexStringToByteArray(const std::string& hex) {
	if (hex.length() != 32) { // Ensure the hex string is exactly 32 characters (16 bytes)
		throw std::invalid_argument("Hex string must be exactly 32 characters long.");
	}

	std::array<uint8_t, 16> byteArray{};
	for (size_t i = 0; i < hex.length(); i += 2) {
		// Convert each pair of hex characters to a byte
		std::string byteString = hex.substr(i, 2);
		byteArray[i / 2] = static_cast<uint8_t>(std::stoi(byteString, nullptr, 16));
	}

	return byteArray;
}

/**
 * Converts a vector of unsigned characters (AES key) into a hexadecimal string representation.
 *
 * @param aesKey The vector of unsigned characters representing the AES key.
 * @return Returns a hexadecimal string representation of the AES key.
 *
 * This function iterates through each byte in the provided AES key vector, converting each byte
 * into a two-character hexadecimal string. It uses a stringstream to concatenate these hex values.
 * The resulting string provides a human-readable format of the binary AES key data, often useful
 * for logging, debugging, or displaying the key in a consistent hexadecimal format.
 */

std::string aesKeyToHexString(const std::vector<unsigned char>& aesKey) {
	std::ostringstream hexStream;
	hexStream << std::hex << std::setfill('0');
	for (unsigned char byte : aesKey) {
		hexStream << std::setw(2) << static_cast<int>(byte);
	}
	return hexStream.str();
}
