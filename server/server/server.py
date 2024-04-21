from keys import cksum
from keys import keys_utils
from utils import const, utils
from SQlite import SQlite_utils
import socket
import struct
import uuid
import selectors
from .client_context import ClientContext
import os


selector = selectors.DefaultSelector()  # Create a selector object
contexts = {}                           # Dictionary to store contexts keyed by client identifiers (e.g., socket object)

"""
    This file is the main functionality of the server,
    Contains function for server activation, receive data and  send responses to client.
"""


def accept_connection(server_socket):
    """
    This function is designed to handle the initial connection setup phase for a client attempting to connect to the server.
    It ensures the client connection is non-blocking, allowing the server to handle multiple connections simultaneously
    without waiting for any single operation to complete. A new client context is created for each connection to maintain
    stateful information needed throughout the client's session.
    Parameters:
        server_socket (socket.socket): The server socket that is listening for incoming connections.
    Returns:
        None
    Raises:
        socket.error: If an error occurs while accepting the incoming connection.
    """
    try:
        # Accept incoming client connection
        client_socket, addr = server_socket.accept()
        print("Accepted connection from", addr)
        # Set socket to non-blocking so server will be able to manage multiple connections
        client_socket.setblocking(False)
        # Create and store a new ClientContext for this client
        contexts[client_socket] = ClientContext()
        # Register new socket with the selector, invoke 'handle_client' to handle client connected
        selector.register(client_socket, selectors.EVENT_READ, handle_client)
    except socket.error as e:
        print(f"Error accepting connection: {e}")


def handle_client(client_socket):
    """
        Manages communication with a connected client using a non-blocking socket. This function is invoked by the selector
        whenever the client socket is ready to read. It retrieves the client-specific context, handles the request, and
        manages the connection lifecycle based on the client's actions.

        Parameters:
            client_socket (socket.socket): The client socket associated with the connected client.

        Returns:
            None

        Notes:
            If the result from handling the client's request indicates the connection should be closed, the function
            unregisters the client from the selector, closes the socket, and removes any client-specific context.
            Any exceptions during request handling or socket operations result in the connection being closed and
            unregistered from the selector.
    """
    try:
        client_session = contexts[client_socket]  # Retrieve the context for this client
        data = SQlite_utils.fetch_clients_and_files_full_data()  # Fetch data needed for handling requests
        result = decipher_request(client_socket, data, "OPEN_SOCKET", client_session)
        if result == "CLOSE_SOCKET":
            print("Closing connection")
            selector.unregister(client_socket)
            client_socket.close()
            del contexts[client_socket]  # Clean up the context
    except Exception as e:
        print(f"Error handling client {client_socket}: {e}")
        selector.unregister(client_socket)
        client_socket.close()


def run_server():
    """
        Starts the server, sets up listening on a specified port, and handles incoming connections using a non-blocking
        approach with selectors. The server runs indefinitely, accepting new connections and processing existing ones
        according to events triggered by the selector.

        This function configures the server socket to listen on a dynamically read port, registers the socket with a
        selector to manage asynchronous I/O, and enters an infinite loop to continuously monitor and respond to events
        such as new connections or data ready to be processed.

        Parameters:
            None

        Returns:
            None

        Notes:
            The server uses a selector to efficiently handle multiple client connections concurrently without the need for
            multi-threading or multi-processing. This allows the server to scale to handle many connections with minimal
            resource overhead.
    """
    host = ''
    port = utils.read_port()

    SQlite_utils.open_database()

    # create new socket using IPv4, TCP. will be closed automatically when goes out of scope
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        # binds socket to specific IP address and port
        server_socket.bind((host, int(port)))
        # listen for incoming connections
        server_socket.listen()
        # Set server socket to non-blocking ( calls that cannot be completed immediately will not block and will either
        # return with partial results or raise an exception)
        server_socket.setblocking(False)
        # register server socket with the selector to be monitored. when server socket is ready to read,
        # 'accept_connection' function will be called to accept the connection
        selector.register(server_socket, selectors.EVENT_READ, accept_connection)

        print("Server is listening on", port)
        # This loop keeps the server running indefinitely, continuously checking for and handling incoming events
        while True:
            events = selector.select(timeout=None)  # Block until sockets are ready
            # iterates over collection of events returned key = tuple contains : 1. 'fileobj' (socket object),
            # 2. 'events' (event mask), 3. 'data' (callback function associated with the socket mask = the specific
            # event that are ready
            for key, mask in events:
                # extracts callback function that was registered with this socket
                callback = key.data
                # Call accept_connection or handle_client (function that was registered with this socket)
                callback(key.fileobj)


def decipher_request(client_socket, data, result, client_session):
    """
    This function accepts client request data (header and payload), and sends response for each request, update DB and
    RAM, handle errors.
    :param client_socket: client connection.
    :param data: DB data.
    :param result: result of request.
    :param client_session: data stored in RAM for client connection session.

    """
    # read request data
    request_data = receive_request_header_data(client_socket)
    code, version, clientID, payload_size = request_data    # header data of accepted request

    # if problem occurred while reading header data, set 'req_code' to '' -> socket will be closed
    if len(code) != const.REQ_CODE_LEN:
        req_code = ''
    else:
        # else convert req code format
        req_code = struct.unpack('<H', code)[0]

    # decipher payload according to req code
    match req_code:
        case 1025:
            # receive payload according to registration request (user_name)
            payload_size = struct.unpack('<I', payload_size)[0]  # convert from binary
            user_name = receive_until_delimiter(client_socket)

            # check size of received payload for registration request
            if len(user_name) != payload_size:
                response_header_clientID(client_socket, const.FAIL_CODE, clientID)
                return "CLOSE_SOCKET"       # send fail response and close client socket connection
            # success code to client - header and payload data passed successfully
            else:
                response_header_clientID(client_socket, const.RECEIVED_MSG_VALID, clientID)
            # Check if 'user_name' is in 'data' (DB)
            exist = SQlite_utils.username_exist(data, user_name)
            # If 'user_name' exists in DB -> ERROR : cannot register with existing username.
            if exist:
                # send fail response with default uuid bytes and close connection
                default_uuid_bytes = bytes([0] * 16)  # 16 bytes of zero
                response_header_clientID(client_socket, const.REGISTRATION_FAIL, default_uuid_bytes)
                return "CLOSE_SOCKET"
            # else - username is not in DB -> perform registration and all actions needed
            else:
                uuid_bytes = create_uuid()                           # create uuid
                SQlite_utils.add_client(uuid_bytes, user_name)      # add client to DB with clientID (bytes) and username (string)
                client_session.set_client_id(uuid_bytes)            # add clientID and username to RAM for session
                client_session.set_user_name(user_name)
                response_header_clientID(client_socket, const.REGISTRATION_SUCCESS, uuid_bytes)  # send valid response
                return ""
        case 1026:
            # receive request payload (username and public RSA key)
            user_name = receive_until_delimiter(client_socket)
            public_rsa_key_base64 = receive_until_delimiter(client_socket)

            # check the size of the received payload according to payload_size (header attribute)
            payload_size_received = len(user_name) + len(public_rsa_key_base64)
            payload_size = struct.unpack('<I', payload_size)[0]  # convert from binary

            # check received payload
            if payload_size_received != payload_size:
                SQlite_utils.remove_client_by_name(user_name)       # remove item 'user_name' from clients table in DB
                response_header_clientID(client_socket, const.FAIL_CODE, clientID)  # fail response
                return "CLOSE_SOCKET"

            # payload received is valid, send valid response to client and perform all actions needed
            else:
                # send valid response to server to inform that data received and validated
                response_header_clientID(client_socket, const.RECEIVED_MSG_VALID, clientID)

                # generate AES key using 'create_aes_key' from 'keys_utils' file
                aes_key = keys_utils.create_aes_key()

                # encrypt with public RSA key received
                encrypted_aes_key = keys_utils.encrypt_aes_key_with_rsa(public_rsa_key_base64, aes_key)

                # update data in RAM, fields : public RSA key, aes_key
                client_session.set_aes_key(aes_key)
                client_session.set_public_key(keys_utils.base64_to_der(public_rsa_key_base64))

                # update client table of item 'username', fields : public RSA key, last seen, encrypted aes_key
                SQlite_utils.update_client_info(user_name, public_rsa_key_base64, encrypted_aes_key)

                # send encrypted AES key to client
                send_encrypted_aes_key(client_socket, clientID,
                                       const.RECEIVED_PUBLICKEY_SEND_CRYPT_AES, encrypted_aes_key)
                return ""
        case 1027:
            # receive payload according to registration request
            payload_size = struct.unpack('<I', payload_size)[0]  # convert from binary
            user_name = receive_until_delimiter(client_socket)

            # check size of received payload for registration request
            if len(user_name) != payload_size:
                response_header_clientID(client_socket, const.FAIL_CODE, clientID)
                return "CLOSE_SOCKET"  # send fail response and close client socket connection
            # check if client id DB
            exist = SQlite_utils.username_exist(data, user_name)
            # if not in DB return failure, restart as new client
            if not exist:
                response_header_clientID(client_socket, const.RECONNECT_REQUEST_DENIED, clientID)
                return ""
            else:
                # send accept reconnect response
                response_header_clientID(client_socket, const.RECEIVED_MSG_VALID, clientID)

                # update data in DB ('lastSeen' field)
                SQlite_utils.update_last_seen(clientID, user_name)

                # create aes key, save it in RAM for session
                aes_key = keys_utils.create_aes_key()
                client_session.set_aes_key(aes_key)

                # get client public RSA key from DB, save it in RAM for session
                public_key = SQlite_utils.get_public_key_by_client_id(clientID)
                client_session.set_public_key(public_key)

                # convert public key to 64base
                public_key_64base_format = keys_utils.encode_to_base64(public_key)

                # encrypt aes key using public RSA key
                encrypted_aes_key = keys_utils.encrypt_aes_key_with_rsa(public_key_64base_format, aes_key)

                # send to client
                send_encrypted_aes_key(client_socket, clientID,
                                       const.RECEIVED_RECONNECT_REQUEST_SEND_CRYPT_AES, encrypted_aes_key)

                return ""
        case 1028:
            # receive reqeust payload
            (contentSize, originalFileSize, packetNumber, totalPackets, file_content, file_name) = receive_encrypted_file_content_payload(client_socket)
            full_file_content = file_content        # every chunk of file content will be appended to this variable
            packet_count = packetNumber
            total_packets = totalPackets

            # read all packets and store each part of file_content in full_file_content
            while packet_count < total_packets-1:
                (contentSize, originalFileSize, packetNumber, totalPackets, file_content, file_name) = receive_encrypted_file_content_payload(client_socket)
                full_file_content += file_content
                packet_count = packet_count+1

            # check if 'full_file_content' received match the size of 'contentSize'
            if len(full_file_content) != contentSize:
                SQlite_utils.remove_client_by_id(clientID)  # remove item 'user_name' from clients table in DB
                response_header_clientID(client_socket, const.FAIL_CODE, clientID)
                return "CLOSE_SOCKET"
            else:
                SQlite_utils.add_file_to_database(clientID, file_name)
                response_header_clientID(client_socket, const.RECEIVED_MSG_VALID, clientID)

            # get aes key from RAM
            aes_key = client_session.get_aes_key()

            # decrypt file content using aes key
            decrypted_message_content = keys_utils.decrypt_aes_content(full_file_content, aes_key)

            # store decrypted file content and filename in client session
            file_name_extract = os.path.basename(file_name)
            client_session.set_file_name(file_name_extract)
            client_session.set_decrypted_file_content(decrypted_message_content.decode('utf-8'))

            # calculate CRC
            CRC_calc = cksum.calculate_checksum(decrypted_message_content)

            # send CRC to client
            encrypted_file_CRC_response(client_socket, const.RECEIVED_VALID_FILE_CRC, clientID, contentSize, file_name, CRC_calc)
            return ""
        case 1029:
            payload_size = struct.unpack('<I', payload_size)[0] # convert from binary to decimal, little endian
            file_name = receive_until_delimiter(client_socket)  # receive request payload

            # get filename and file content from client session
            file_name_session = client_session.get_file_name()
            file_content_session = client_session.get_decrypted_file_content()

            SQlite_utils.verify_file_entry(clientID, file_name)
            utils.store_file_in_package(file_name_session, file_content_session)
            response_header_clientID(client_socket, const.RECEIVED_MSG_VALID, clientID)  # response to client
            return "CLOSE_SOCKET"
        case 1030:
            payload_size = struct.unpack('<I', payload_size)[0]  # convert from binary to decimal, little endian
            file_name = receive_until_delimiter(client_socket)  # receive request payload
            return ""
        case 1031:
            payload_size = struct.unpack('<I', payload_size)[0]  # convert from binary to decimal, little endian
            file_name = receive_until_delimiter(client_socket)  # receive request payload
            return "CLOSE_SOCKET"
        case _:
            return "CLOSE_SOCKET"


def receive_request_header_data(client_socket):
    """
    This method receives client requests header data and perform validation.
    if data is invalid/corrupted : empty tuple will be returned - indicates error,
    else return data received.
    :param client_socket: client connection.
    :return:
    """
    # receive request code
    code_data = client_socket.recv(const.REQ_CODE_LEN)
    if len(code_data) < const.REQ_CODE_LEN:
        return '', '', '', ''

    # receive header version
    version_data = client_socket.recv(const.VERSION_LEN)
    if len(version_data) < const.VERSION_LEN:
        return '', '', '', ''

    # Receive header clientID
    clientID_data = client_socket.recv(const.CLIENTID_LEN)
    if len(clientID_data) < const.CLIENTID_LEN:
        return '', '', '', ''

    # receive header payload size
    payload_size_data = client_socket.recv(const.PAYLOADSIZE_LEN)
    if len(payload_size_data) < const.PAYLOADSIZE_LEN:
        return '', '', '', ''

    return code_data, version_data, clientID_data, payload_size_data


def response_header_clientID(client_socket, code, uuid_bytes):
    """
    This response contains :
        - header : (server version, response code, payload size).
        - payload : (clientID).
    This is the basic response for data received from client.
    :param client_socket: client socket connection.
    :param code: response code (accept/fail code) will be sent to client.
    :param uuid_bytes: client ID.
    :return: accept/fail code.
    """
    # create header and payload objects for registration success answer to client :

    # Pack header : Format: version (1 byte), status (2 bytes), payload_size (4 bytes)
    header = struct.pack('<BH', const.SERVER_VERSION, code) + struct.pack('<I', len(uuid_bytes))
    # payload is uuid_bytes
    payload = uuid_bytes

    # pack header+payload and sent to client
    registration_success_response = header + payload

    # Send the message
    client_socket.sendall(registration_success_response)


def create_uuid():
    """
    This method creates new clientID and return it bytes format.
    :return: clientID in bytes format.
    """
    new_uuid = uuid.uuid4().hex  # Generate a new UUID and convert to hexadecimal string
    uuid_bytes = bytes.fromhex(new_uuid)  # Convert hex string back to bytes
    return uuid_bytes


def receive_until_delimiter(client_socket, delimiter=b'\0'):
    """
    This method receive client data byte-by-byte until delimiter='\n' is appeared or lost connection
    :param client_socket: socket connection object
    :param delimiter: '\n'
    :return: converted client data utf-8 format
    """
    data = b''
    while True:
        byte = client_socket.recv(1)  # Receive byte by byte
        if byte == delimiter or byte == b'':  # End of message or connection closed
            break
        data += byte

    return data.decode('utf-8')


def send_encrypted_aes_key(client_socket, uuid_bytes, code, encrypted_aes):
    """
    This method send encrypted aes key to client.
    :param client_socket: client connection.
    :param uuid_bytes: clientID in bytes format.
    :param code: response code.
    :param encrypted_aes:
    :return:
    """
    # create header and payload objects for encrypted aes key response

    # Pack header : Format: version (1 byte), status (2 bytes), payload_size (4 bytes)
    payload_size = len(uuid_bytes) + len(encrypted_aes)
    header = struct.pack('<BH', const.SERVER_VERSION, code) + struct.pack('<I', payload_size)

    # payload uuid_bytes, encrypted aes_key
    payload = uuid_bytes + encrypted_aes

    # pack header+payload
    response = header+payload

    # send response
    client_socket.sendall(response)


def receive_encrypted_file_content_payload(client_socket):
    """
    This method receives encrypted file from client and other metadata related to client request.
    :param client_socket: client connection.
    :return:
    """

    # First, receive the fixed-size part of the payload
    # This includes contentSize, originalFileSize, packetNumber, and totalPackets
    fixed_size_format = '<I I H H'  # Format string for struct.unpack
    fixed_size_length = struct.calcsize(fixed_size_format)  # Calculate size of fixed part
    fixed_part = client_socket.recv(fixed_size_length)
    contentSize, originalFileSize, packetNumber, totalPackets = struct.unpack(fixed_size_format, fixed_part)

    # receive file content (binary string data)
    file_content = client_socket.recv(contentSize)
    # receive file name content
    file_name = receive_until_delimiter(client_socket)

    # Return the extracted data
    return contentSize, originalFileSize, packetNumber, totalPackets, file_content, file_name


def encrypted_file_CRC_response(client_socket, code, clientID, encrypted_content_size, file_name, CRC):
    """
    This method sends the response for client encrypted file request, contains all data needed according to protocol.
    :param client_socket: client connection.
    :param code: response code.
    :param clientID: clientID bytes.
    :param encrypted_content_size:
    :param file_name:
    :param CRC:
    :return:
    """
    # Convert encrypted_content_size to bytes for sending
    encrypted_content_size_bytes = struct.pack('<I', encrypted_content_size)
    # Ensure file_name is correctly encoded and null-terminated
    file_name_encoded = file_name.encode('utf-8') + b'\x00'
    # Pack check_sum as a 4-byte unsigned integer in little-endian format
    check_sum_bytes = struct.pack('<I', CRC)
    # Calculate header payload size correctly
    payload_size = len(clientID) + len(encrypted_content_size_bytes) + len(file_name_encoded) + len(check_sum_bytes)
    # Pack the header
    header = struct.pack('<BH', const.SERVER_VERSION, code) + struct.pack('<I', payload_size)
    # Create the payload
    payload = clientID + encrypted_content_size_bytes + check_sum_bytes + file_name_encoded
    # Concatenate header and payload
    response = header + payload
    # Send the response
    client_socket.sendall(response)
