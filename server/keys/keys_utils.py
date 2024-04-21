import base64
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Util.Padding import unpad
from Crypto.PublicKey import RSA


"""
This file contains functions related to RSA keys action will be performed during client-server connection.
"""


def encode_to_base64(binary_data):
    """
    Encodes binary data to a Base64 string.

    :param binary_data: Binary data as bytes.
    :return: Base64 encoded string.
    """
    # Encode the binary data to Base64
    base64_encoded = base64.b64encode(binary_data)
    # Convert bytes to string for easier use in Python
    return base64_encoded.decode('utf-8')


def base64_to_der(base64_string):
    """
    Convert a base64-encoded string to DER format (binary data).
    Parameters:
    base64_string (str): The base64-encoded string.
    Returns:
    bytes: The original binary data in DER format.
    """
    der_bytes = base64.b64decode(base64_string)
    return der_bytes


def create_aes_key():
    """
    Creates new aes key.
    :return:
    """
    # Generate a 256-bit (32 bytes) AES key
    aes_key = get_random_bytes(32)
    return aes_key


def encrypt_aes_key_with_rsa(public_key_base64, aes_key):
    """
    This method receives public RSA key and aes key, performs encryption of aes key using public RSA key.
    :param public_key_base64:
    :param aes_key:
    :return:
    """
    # Decode the RSA public key from base64
    public_key_der = base64_to_der(public_key_base64)
    # Load the RSA public key
    rsa_public_key = RSA.import_key(public_key_der)

    # Initialize the PKCS1_OAEP cipher with the RSA public key
    cipher = PKCS1_OAEP.new(rsa_public_key)

    # Encrypt the AES key
    encrypted_aes_key = cipher.encrypt(aes_key)
    return encrypted_aes_key


def decrypt_aes_content(encrypted_content: bytes, aes_key: bytes) -> bytes:
    """
    This function receives binary data and decrypt it using binary aes key. Will be used for receiving encrypted file
    content and decrypt the file content using aes key.
    :param encrypted_content:
    :param aes_key:
    :return: decrypted file content in binary format
    """
    # Assuming the IV was a block of zeros during encryption
    iv = b'\x00' * AES.block_size
    # iv = {0}, aes is 32 bytes
    try:
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        decrypted_bytes = unpad(cipher.decrypt(encrypted_content), AES.block_size)
        return decrypted_bytes
    except (ValueError, KeyError) as e:
        print(f"Decryption failed: {e}")
        return b''

