from utils import const
import tempfile
import os


"""
    This file contains function that will be used across the project
"""


def store_file_in_package(file_name, file_content):
    """
    Stores the decrypted file content into a specified package directory, creating the directory if it doesn't exist.

    Parameters:
        file_name (str): The name of the file to store.
        file_content (str): The content of the file to store, expected to be a UTF-8 string.

    Returns:
        bool: True if the file was successfully written, False otherwise.
    """
    package_directory = "files"  # Define the directory name for packages

    # Ensure the package directory exists
    if not os.path.exists(package_directory):
        os.makedirs(package_directory)

    # Construct the full path where the file will be stored
    file_path = os.path.join(package_directory, file_name)

    try:
        # Write the decrypted file content to the file
        with open(file_path, 'w', encoding='utf-8') as file:
            file.write(file_content)
        return True
    except Exception as e:
        print(f"Failed to store file '{file_name}': {str(e)}")
        return False



def read_port():
    """
    This method try to open file to receive port number that will be used for server connection.
    :return: file port number / default port number.
    """
    try:
        with open(const.FILE_NAME, 'r') as file:
            return file.read()
    except FileNotFoundError:
        print("WARNING: Port fail.")
        return const.DEFAULT_PORT


def write_decrypted_content_to_file(decrypted_content: bytes) -> str:
    """
    Writes decrypted content to a temporary file and returns the file path.

    :param decrypted_content: The decrypted content as a bytes object.
    :return: The path to the temporary file.
    """
    # Create a temporary file and write the decrypted content to it
    temp_file = tempfile.NamedTemporaryFile(delete=False)
    temp_file_path = temp_file.name
    temp_file.write(decrypted_content)
    temp_file.close()

    return temp_file_path
