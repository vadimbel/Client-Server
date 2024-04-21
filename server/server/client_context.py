
class ClientContext:
    """
    This class contains all data will be stored during client connection session. will be used when needed during
    responses and requests.
    """
    def __init__(self):
        self._client_id = None
        self._user_name = None
        self._aes_key = None
        self._public_key = None
        self._file_name = None
        self._decrypted_file_content = None

    # Client ID
    def get_client_id(self):
        return self._client_id

    def set_client_id(self, value):
        self._client_id = value

    # User name
    def get_user_name(self):
        return self._user_name

    def set_user_name(self, value):
        self._user_name = value

    # AES key
    def get_aes_key(self):
        return self._aes_key

    def set_aes_key(self, value):
        self._aes_key = value

    # Public key
    def get_public_key(self):
        return self._public_key

    def set_public_key(self, value):
        self._public_key = value

    def get_file_name(self):
        return self._file_name

    def set_file_name(self, value):
        self._file_name = value

    def get_decrypted_file_content(self):
        return self._decrypted_file_content

    def set_decrypted_file_content(self, value):
        self._decrypted_file_content = value




