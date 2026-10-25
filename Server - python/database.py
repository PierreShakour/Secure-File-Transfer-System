import sqlite3

DATABASE_NAME = "defensive.db"


# Initialize the database with the required tables.
def initialize_database():
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS clients (
            ID BLOB PRIMARY KEY,
            Name TEXT UNIQUE,
            PublicKey BLOB,
            LastSeen TEXT,
            AESKey BLOB
        );
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS files (
            ID BLOB,
            FileName TEXT,
            PathName TEXT,
            Verified INTEGER
        );
    ''')

    conn.commit()
    conn.close()


# Save a new client to the database.
def save_client(client_id, name):
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()

    # Create the clients table
    cursor.execute('''
      INSERT INTO clients (ID, Name) VALUES (?, ?)
    ''', (client_id, name))

    conn.commit()
    conn.close()


# Check if a client exists in the database by name.
def client_exists(name):
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()

    cursor.execute('SELECT 1 FROM clients WHERE Name = ?', (name,))
    exists = cursor.fetchone() is not None

    conn.close()
    return exists


# Save the client's public key and AES key to the database.
def save_client_keys(client_id, public_key, aes_key):
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()

    cursor.execute('''
        UPDATE clients
        SET PublicKey = ?, AESKey = ?
        WHERE ID = ?
    ''', (public_key, aes_key, client_id))

    conn.commit()
    conn.close()


# Update the last seen timestamp for a client in the database.
def update_last_seen(client_id):
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()

    cursor.execute('''
        UPDATE clients
        SET LastSeen = CURRENT_TIMESTAMP
        WHERE ID = ?
    ''', (client_id,))

    conn.commit()
    conn.close()


# Save a file record to the database, ensuring that any existing
# record for the same client and file name is removed first.
def save_file(client_id, file_name, path_name):
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()

    cursor.execute(
        "DELETE FROM files WHERE ID = ? AND FileName = ?",
        (client_id, file_name)
    )

    cursor.execute('''
       INSERT INTO files (ID, FileName, PathName, Verified)
          VALUES (?, ?, ?, 0)
    ''', (client_id, file_name, path_name))

    conn.commit()
    conn.close()


# Verify a file in the database by setting its Verified status to 1.
def verify_file(client_id, file_name):
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()

    cursor.execute('''
        UPDATE files
        SET Verified = 1
        WHERE ID = ? AND FileName = ?
    ''', (client_id, file_name))

    conn.commit()
    conn.close()


# Retrieve a client record from the database by name.
def get_client_by_name(name):
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()

    cursor.execute('''
        SELECT ID, PublicKey, AESKey
        FROM clients
        WHERE Name = ?
    ''', (name,))

    client = cursor.fetchone()

    conn.close()
    return client


if __name__ == "__main__":
    initialize_database()
    print("Database initialized successfully!")
