from utils import const
from sqlite3 import Error
from datetime import datetime
import sqlite3
from typing import Optional
import os
from keys import keys_utils


"""
    This file contains multiple functions related to DB handling,
    will be used across different client-server requests/responses.
"""


def update_last_seen(client_id, username):
    """
    Updates the 'LastSeen' field for a specific client in the 'clients' table.

    Parameters:
        client_id (bytes): The client's unique ID as a byte string.
        username (str): The client's username.

    Returns:
        bool: True if the update was successful, False otherwise.
    """
    # Connect to the SQLite database
    conn = sqlite3.connect(const.DB_NAME)
    cursor = conn.cursor()

    try:
        # Prepare the current time in ISO 8601 format
        last_seen = datetime.now().isoformat()

        # Update the LastSeen field where the ID and Name match the given parameters
        cursor.execute("""
            UPDATE clients
            SET LastSeen = ?
            WHERE ID = ? AND Name = ?
        """, (last_seen, client_id, username))

        # Check if any row was actually updated
        if cursor.rowcount > 0:
            conn.commit()
            return True
        else:
            print(f"No record found for user '{username}' with provided client ID.")
            return False

    except sqlite3.Error as e:
        print(f"An error occurred: {e}")
        return False

    finally:
        # Close the database connection
        conn.close()


def remove_client_by_id(client_id):
    """
    Removes a client record from the 'clients' table in the SQLite database based on the provided client ID.
    Parameters:
        client_id (bytes): The client ID of the client to remove, in byte form.
    Returns:
        bool: True if the operation was successful and at least one row was affected, False otherwise.
    """
    try:
        # Connect to the SQLite database
        conn = sqlite3.connect(const.DB_NAME)
        # Create a cursor object
        cursor = conn.cursor()

        # Execute the SQL command to delete the client
        cursor.execute("DELETE FROM clients WHERE ID = ?", (client_id,))

        # Check if any row was affected
        if cursor.rowcount > 0:
            # Commit the changes if rows are affected
            conn.commit()
            return True
        else:
            return False

    except sqlite3.Error as e:
        # Print an error message if an exception occurs
        print(f"An error occurred while removing the client: {e}")
        return False

    finally:
        # Close the database connection
        conn.close()


def remove_client_by_name(user_name):
    """
    Removes a client record from the 'clients' table in the SQLite database based on the provided user name.
    Parameters:
        user_name (str): The username of the client to remove.
    Returns:
        bool: True if the operation was successful and at least one row was affected, False otherwise.
    """
    try:
        # Connect to the SQLite database
        conn = sqlite3.connect(const.DB_NAME)
        # Create a cursor object
        cursor = conn.cursor()

        # Execute the SQL command to delete the client
        cursor.execute("DELETE FROM clients WHERE Name = ?", (user_name,))

        # Check if any row was affected
        if cursor.rowcount > 0:
            # Commit the changes if rows are affected
            conn.commit()
            return True
        else:
            return False

    except sqlite3.Error as e:
        # Print an error message if an exception occurs
        print(f"An error occurred while removing the client: {e}")
        return False

    finally:
        # Close the database connection
        conn.close()


def get_public_key_by_client_id(client_id: bytes) -> Optional[bytes]:
    """
    Retrieves the public key for a given client ID from the database.

    :param client_id: The client ID to search for.
    :return: Public key as bytes if found, None otherwise.
    """
    # Connect to the SQLite database
    conn = sqlite3.connect(const.DB_NAME)
    cursor = conn.cursor()

    try:
        # Prepare the SELECT query
        query = "SELECT PublicKey FROM clients WHERE ID = ?"
        cursor.execute(query, (client_id,))

        # Fetch the result
        result = cursor.fetchone()
        if result:
            return result[0]  # Return the public key if found
        else:
            return None  # Client or public key not found
    finally:
        # Ensure the connection is closed
        conn.close()


def verify_file_entry(client_id, file_path):
    """
    This method validates the existence of a file entry in DB and updates verification status.
    :param client_id: clientID bytes.
    :param file_path: full path of file.
    :return:
    """
    # Extract the filename from the full file path
    file_name = os.path.basename(file_path)

    # Connect to the SQLite database
    conn = sqlite3.connect(const.DB_NAME)
    cursor = conn.cursor()

    try:
        # Check if there is an entry for this clientID with the given file name and path
        cursor.execute("SELECT FileID FROM files WHERE ID = ? AND FileName = ? AND PathName = ?",
                       (client_id, file_name, file_path))
        data = cursor.fetchone()

        if data:
            # Entry exists, update Verified field to true
            cursor.execute("UPDATE files SET Verified = 1 WHERE ID = ? AND FileName = ? AND PathName = ?",
                           (client_id, file_name, file_path))
            conn.commit()
        else:
            print("No matching file entry found to verify.")

    except sqlite3.Error as e:
        print(f"An error occurred: {e}")
    finally:
        # Close the connection
        conn.close()


def add_file_to_database(client_id, file_path):
    # Extract the filename from the full file path
    file_name = os.path.basename(file_path)

    # Connect to the SQLite database
    conn = sqlite3.connect(const.DB_NAME)
    cursor = conn.cursor()

    try:
        # Insert a new file entry
        cursor.execute("INSERT INTO files (ID, FileName, PathName, Verified) VALUES (?, ?, ?, ?)",
                       (client_id, file_name, file_path, 0))

        # Commit the changes and log success
        conn.commit()
    except sqlite3.Error as e:
        print(f"An error occurred: {e}")
    finally:
        # Close the connection
        conn.close()


def get_aes_key_by_client_id(client_id: bytes) -> Optional[bytes]:
    """
    Retrieves the AES key for a given client ID from the database.

    :param client_id: The client ID to search for.
    :return: AES key as bytes if found, None otherwise.
    """
    # Connect to the SQLite database
    conn = sqlite3.connect(const.DB_NAME)
    cursor = conn.cursor()

    try:
        # Prepare the SELECT query
        query = "SELECT AESKey FROM clients WHERE ID = ?"
        cursor.execute(query, (client_id,))

        # Fetch the result
        result = cursor.fetchone()
        if result:
            return result[0]  # Return the AES key if found
        else:
            return None  # Client or AES key not found
    finally:
        # Ensure the connection is closed
        conn.close()


def get_client_id_by_username(user_name):
    # Connect to the SQLite database
    conn = sqlite3.connect(const.DB_NAME)
    cursor = conn.cursor()

    try:
        # Prepare a SELECT statement to fetch clientID
        query = "SELECT ID FROM clients WHERE Name = ?"
        cursor.execute(query, (user_name,))

        # Fetch the result
        result = cursor.fetchone()
        if result:
            return result[0]  # Return the clientID
        else:
            print("No client found with the username:", user_name)
            return None
    except sqlite3.Error as error:
        print("Failed to read data from sqlite table", error)
        return None
    finally:
        # Closing the connection
        if conn:
            conn.close()


def update_client_info(user_name, public_key, aes_key):

    # Decode the base64 encoded string to bytes (binary format)
    public_key_bytes = keys_utils.base64_to_der(public_key)

    # Get the current time in ISO 8601 format
    last_seen = datetime.now().isoformat()

    try:
        # Connect to the SQLite database
        conn = sqlite3.connect(const.DB_NAME)
        cursor = conn.cursor()

        # SQL statement to update client information
        sql = ''' UPDATE clients
                  SET PublicKey = ?, LastSeen = ?, AESKey = ?
                  WHERE Name = ?'''

        # Execute the SQL statement
        cursor.execute(sql, (public_key_bytes, last_seen, aes_key, user_name))

        # Commit the changes
        conn.commit()

    except sqlite3.Error as error:
        print("Failed to update client info due to ", error)
    finally:
        if conn:
            # Close the database connection
            conn.close()


def add_client(uuid_bytes, user_name):
    """
    Add a new client to the database using the given username and UUID bytes.
    The UUID bytes are converted to a hexadecimal string before being inserted.

    Parameters:
    uuid_bytes (bytes): The UUID of the client, in bytes.
    user_name (str): The name of the user.
    """
    # Open a connection to the SQLite database
    conn = None
    try:
        conn = sqlite3.connect(const.DB_NAME)
        cursor = conn.cursor()

        # Prepare the insert statement. ID as hex string (converted from bytes)
        query = '''INSERT INTO clients (ID, Name, PublicKey, LastSeen, AESKey)
                   VALUES (?, ?, NULL, NULL, NULL);'''
        parameters = (uuid_bytes, user_name)  # ID is now a hex string

        # Execute the insert operation
        cursor.execute(query, parameters)
        conn.commit()
    except sqlite3.IntegrityError as e:
        print("Client with the same name or UUID already exists.", e)
    except Error as e:
        print(f"An error occurred: {e}")
    finally:
        if conn:
            conn.close()


def username_exist(data, user_name):
    """
        Check if a user with the specified name exists in the data.

        Parameters:
        user_name (str): The name of the user to check.
        data (list): The list of dictionaries containing user data.

        Returns:
        bool: True if the user exists, False otherwise.
        """
    for client in data:
        if client['name'] == user_name:
            return True

    return False


def fetch_clients_and_files_full_data():
    conn = sqlite3.connect(const.DB_NAME)
    cursor = conn.cursor()

    # SQL query to fetch all relevant data
    query = '''
    SELECT c.Name, c.PublicKey, c.LastSeen, c.AESKey, f.FileName, f.PathName, f.Verified
    FROM clients c
    LEFT JOIN files f ON c.ID = f.ID
    ORDER BY c.Name, f.FileName
    '''

    cursor.execute(query)
    rows = cursor.fetchall()
    conn.close()

    data = {}
    for row in rows:
        name, public_key, last_seen, aes_key, file_name, path_name, verified = row

        # Create client entry if not exists
        if name not in data:
            data[name] = {
                'name': name,
                'publicKey': public_key,
                'lastSeen': last_seen,
                'AESKey': aes_key,
                'files': {}
            }

        # Add file entry if file information is present
        if file_name:
            file_entry = {
                'filename': file_name,
                'pathname': path_name,
                'verified': bool(verified)  # Convert to boolean for clarity
            }
            # Add file entry to the files dictionary under the client
            data[name]['files'][file_name] = file_entry

    return list(data.values())


def open_database():
    """
    This method create DB is not exists.
    :return:
    """
    # Connect to SQLite database (or create it if it doesn't exist)
    conn = sqlite3.connect(const.DB_NAME)
    # Create a cursor object using the cursor() method
    cursor = conn.cursor()

    # Create table 'clients'
    cursor.execute('''CREATE TABLE IF NOT EXISTS clients (
                        ID BLOB UNIQUE CHECK(length(ID) = 16),     -- length has to be 16 bytes
                        Name TEXT PRIMARY KEY CHECK(length(Name) <= 254),  -- up to 255 char (include null terminator)
                        PublicKey BLOB, 
                        LastSeen TEXT,                                  -- use ISO 8601 format 
                        AESKey BLOB CHECK(length(AESKey) == 128)         -- up to 128 bit = 32 bytes
                    );''')


    cursor.execute('''CREATE TABLE IF NOT EXISTS files (
                        FileID INTEGER PRIMARY KEY AUTOINCREMENT,
                        ID BLOB,                               -- foreign key to 'client' table
                        FileName TEXT CHECK(length(FileName) <= 254),   -- up to 255 char (include null terminator)
                        PathName TEXT CHECK(length(PathName) <= 254),   -- up to 255 char (include null terminator)
                        Verified INTEGER CHECK(Verified IN (0, 1)),
                        FOREIGN KEY(ID) REFERENCES clients(ID)
                    );''')

    # Commit the changes and close the connection
    conn.commit()
    conn.close()