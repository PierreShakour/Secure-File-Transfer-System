import socket
import uuid
import os
import threading
import sqlite3
from database import (initialize_database, save_client, client_exists,
                      save_client_keys, save_file, update_last_seen,
                      verify_file, get_client_by_name)
from cksum import memcrc
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA1
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from protocol import (
    REQUEST_HEADER_SIZE,
    parse_request_header,
    VERSION,
    build_response_header,
    REGISTRATION_SUCCESS,
    REGISTER,
    CLIENT_ID_SIZE,
    NAME_SIZE,
    PUBLIC_KEY_REQUEST_PAYLOAD_SIZE,
    SEND_PUBLIC_KEY,
    SEND_AES,
    parse_file_payload,
    parse_name,
    parse_public_key_payload,
    SEND_FILE,
    build_file_crc_payload,
    FILE_RECEIVED_WITH_CRC,
    VALID_CRC,
    MESSAGE_RECEIVED,
    REGISTRATION_FAILED,
    RECONNECT,
    RECONNECT_SUCCESS,
    RECONNECT_FAILED,
    INVALID_CRC_DONE,
    INVALID_CRC_RESEND,
    SERVER_ERROR
)
HOST = ""
clients = {}
clients_lock = threading.RLock()


# Receives exactly the specified number of bytes from the socket,
# raising an error if the connection closes prematurely.
def recv_exact(sock, size):
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("Connection closed prematurely by peer")
        data.extend(chunk)
    return bytes(data)


def handle_client(conn, addr):
    with conn:
        conn.settimeout(300)
        print(f"Connected by {addr}")
        failed_transfers = set()
        file_transfers = {}
        try:
            while True:
                header = recv_exact(conn, REQUEST_HEADER_SIZE)

                (client_id, version, code,
                 payload_size) = parse_request_header(header)

                if version != VERSION:
                    raise ValueError(f"Unsupported client version: {version}")

                MAX_REQUEST_PAYLOAD = 1024 * 1024

                if payload_size > MAX_REQUEST_PAYLOAD:
                    raise ValueError("Request payload too large")

                payload = recv_exact(conn, payload_size)
                transfer_id = None
                try:
                    if code == REGISTER:
                        if payload_size != NAME_SIZE:
                            raise ValueError(
                                "Invalid registration payload size")
                        name = parse_name(payload)
                        try:
                            new_client_id = register_client(name)
                            response = build_response_header(
                                REGISTRATION_SUCCESS, CLIENT_ID_SIZE)
                            conn.sendall(response)
                            conn.sendall(new_client_id)
                            print(f"Registered {name}")
                            print(f"Client ID: {new_client_id.hex()}")
                        except ValueError as e:
                            response = build_response_header(
                                REGISTRATION_FAILED, 0)
                            conn.sendall(response)
                            print(f"Registration failed: {e}")

                    elif code == SEND_PUBLIC_KEY:
                        if payload_size != PUBLIC_KEY_REQUEST_PAYLOAD_SIZE:
                            raise ValueError("Invalid public key payload size")
                        name, public_key = parse_public_key_payload(
                            payload)  # parse the public key payload and name
                        # finbd if the name is registered with the client ID
                        registered_name = find_client_by_id(
                            client_id)
                        if registered_name is None:
                            raise ValueError("Client ID not registered")
                        elif registered_name != name:
                            raise ValueError(
                                "Client ID does not match the provided name")
                        else:
                            aes_key = generate_aes_key()
                            encrypted_aes_key = encrypt_aes_key(
                                public_key, aes_key)

                            with clients_lock:
                                save_client_keys(
                                    client_id, public_key, aes_key)
                                clients[name]["public_key"] = public_key
                                clients[name]["aes_key"] = aes_key
                                clients[name]["encrypted_aes_key"] = (
                                    encrypted_aes_key)

                            update_last_seen(client_id)
                            # build the response payload with the client ID
                            # and encrypted AES key
                            response_payload = client_id + encrypted_aes_key
                            # build the response header with the client ID
                            # and encrypted AES key
                            response = build_response_header(
                                SEND_AES, len(response_payload))
                            conn.sendall(response)  # send the response header
                            # send the response payload
                            conn.sendall(response_payload)
                    elif code == SEND_FILE:
                        (content_size, original_file_size, packet_number,
                         total_packets, file_name,
                         file_content) = parse_file_payload(payload)

                        registered_name = find_client_by_id(client_id)
                        if registered_name is None:
                            raise ValueError("Client ID not registered")

                        transfer_id = (client_id, file_name)

                        if transfer_id in failed_transfers:
                            if packet_number == total_packets:
                                failed_transfers.remove(transfer_id)

                                response = build_response_header(
                                    SERVER_ERROR, 0)
                                conn.sendall(response)

                            continue

                        if transfer_id not in file_transfers:
                            with clients_lock:
                                aes_key = clients[registered_name].get(
                                    "aes_key")

                            if aes_key is None:
                                raise ValueError("Client has no AES key")

                            file_transfers[transfer_id] = {
                                "original_file_size": original_file_size,
                                "total_packets": total_packets,
                                "packets": {},
                                "content_size": content_size,
                                "aes_key": aes_key
                            }

                        # get the transfer info for the current transfer ID
                        transfer = file_transfers[transfer_id]

                        if (transfer["original_file_size"] !=
                           original_file_size):
                            raise ValueError(
                                "Original file size mismatch between packets")

                        if transfer["total_packets"] != total_packets:
                            raise ValueError("Total packet count mismatch")

                        if transfer["content_size"] != content_size:
                            raise ValueError(
                                "Encrypted file size mismatch between packets")

                        if (content_size == 0 or
                           content_size % AES.block_size != 0):
                            raise ValueError("Invalid encrypted file size")

                        if (total_packets < 1
                           or not (1 <= packet_number <= total_packets)):
                            raise ValueError("Invalid packet number")

                        if packet_number in transfer["packets"]:
                            raise ValueError("Duplicate packet received")

                        received_size = sum(
                            len(packet)
                            for packet in transfer["packets"].values()
                        )

                        if received_size + len(file_content) > content_size:
                            raise ValueError(
                                "Received data exceeds encrypted file size")

                        # store th received packet content in the transfer info
                        transfer["packets"][packet_number] = file_content

                        if (len(transfer["packets"]) ==
                           transfer["total_packets"]):
                            encrypted_file = b"".join(
                                transfer["packets"][i]
                                for i in range(1, total_packets + 1)
                            )

                            if len(encrypted_file) != transfer["content_size"]:
                                raise ValueError("Incomplete encrypted file")

                            # decrypt the received file content using
                            # the client's AES key
                            decrypted_file_content = decrypt_file(
                                encrypted_file, transfer["aes_key"])
                            if (len(decrypted_file_content) !=
                               original_file_size):
                                raise ValueError(
                                    "Decrypted file size mismatch")

                            print(f"Successfully received and "
                                  f"decrypted {file_name}")
                            print(f"Original file size: "
                                  f"{len(decrypted_file_content)} bytes")

                            transfer["decrypted_content"] = (
                                decrypted_file_content)
                            file_path = save_received_file(
                                client_id, file_name, decrypted_file_content)
                            save_file(client_id, file_name, file_path)
                            # calculate the CRC directly from bytes
                            crc = memcrc(decrypted_file_content)
                            transfer["crc"] = crc

                            # build the response payload with the client ID,
                            # encrypted file size, file name, and CRC
                            response_payload = build_file_crc_payload(
                                client_id, len(encrypted_file), file_name, crc)
                            # build the response header with the client ID,
                            # encrypted file size, file name, and CRC
                            response = build_response_header(
                                FILE_RECEIVED_WITH_CRC, len(response_payload))
                            conn.sendall(response)  # send the response header
                            conn.sendall(response_payload)
                    elif code == VALID_CRC:
                        if payload_size != NAME_SIZE:
                            raise ValueError(
                                "Invalid CRC validation payload size")
                        # parse the name from the payload
                        file_name = parse_name(payload)
                        # find if the name is registered with the client ID
                        registered_name = find_client_by_id(client_id)
                        if registered_name is None:
                            raise ValueError("Client ID not registered")
                        update_last_seen(client_id)
                        # create a unique transfer ID based on the
                        # client ID and file name
                        transfer_id = (client_id, file_name)
                        if transfer_id not in file_transfers:
                            raise ValueError("File transfer not found")
                        # get the transfer info for the current transfer ID
                        transfer = file_transfers[transfer_id]
                        if ("decrypted_content" not in transfer or
                           "crc" not in transfer):
                            raise ValueError("File transfer is not complete")
                        verify_file(client_id, file_name)
                        # build the response header for MESSAGE_RECEIVED
                        response = build_response_header(
                            MESSAGE_RECEIVED, CLIENT_ID_SIZE)
                        conn.sendall(response)
                        conn.sendall(client_id)
                        del file_transfers[transfer_id]
                    elif code == INVALID_CRC_RESEND:
                        if payload_size != NAME_SIZE:
                            raise ValueError("Invalid CRC retry payload size")

                        file_name = parse_name(payload)
                        transfer_id = (client_id, file_name)

                        if transfer_id not in file_transfers:
                            raise ValueError("File transfer not found")

                        del file_transfers[transfer_id]

                        print(f"CRC mismatch: retry requested for {file_name}")
                    elif code == INVALID_CRC_DONE:
                        if payload_size != NAME_SIZE:
                            raise ValueError(
                                "Invalid CRC failure payload size")

                        file_name = parse_name(payload)
                        transfer_id = (client_id, file_name)

                        file_transfers.pop(transfer_id, None)

                        print(f"File transfer failed"
                              f" CRC verification: {file_name}")

                        response_payload = client_id
                        response = build_response_header(
                            MESSAGE_RECEIVED,
                            len(response_payload)
                        )

                        conn.sendall(response)
                        conn.sendall(response_payload)
                    elif code == RECONNECT:
                        if payload_size != NAME_SIZE:
                            raise ValueError("Invalid reconnect payload size")

                        name = parse_name(payload)

                        with clients_lock:
                            client = get_client_by_name(name)

                            if client is not None:
                                stored_id, public_key, aes_key = client

                                if (stored_id == client_id and
                                   public_key is not None and
                                   aes_key is not None):
                                    clients[name] = {
                                        "id": stored_id,
                                        "public_key": public_key,
                                        "aes_key": aes_key
                                    }

                        if client is None:
                            response = build_response_header(
                                RECONNECT_FAILED, 0)
                            conn.sendall(response)

                        elif (stored_id != client_id or
                              public_key is None or aes_key is None):
                            response = build_response_header(
                                RECONNECT_FAILED, 0)
                            conn.sendall(response)

                        else:
                            encrypted_aes_key = encrypt_aes_key(
                                public_key, aes_key)
                            update_last_seen(stored_id)

                            response_payload = stored_id + encrypted_aes_key
                            response = build_response_header(
                                RECONNECT_SUCCESS, len(response_payload))

                            conn.sendall(response)
                            conn.sendall(response_payload)

                    else:
                        raise ValueError(f"Unknown request code: {code}")
                except (ValueError, sqlite3.Error, OSError) as e:
                    print(f"Server error: {e}")
                    if transfer_id is not None:
                        file_transfers.pop(transfer_id, None)
                    if (code == SEND_FILE
                            and transfer_id is not None
                            and packet_number < total_packets):

                        failed_transfers.add(transfer_id)

                    response = build_response_header(SERVER_ERROR, 0)
                    conn.sendall(response)

        except socket.timeout:
            print(
                f"Client {addr} disconnected after 5 minutes of inactivity")

        except ConnectionError:
            print(f"Client {addr} disconnected")

        except OSError as e:
            print(f"Connection error with {addr}: {e}")

        except ValueError as e:
            print(f"Invalid request from {addr}: {e}")

            try:
                response = build_response_header(SERVER_ERROR, 0)
                conn.sendall(response)
            except OSError:
                pass


def start_server(port):
    initialize_database()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((HOST, port))
        server_socket.listen()

        print(f"Server listening on port {port}")

        while True:
            conn, addr = server_socket.accept()
            client_thread = threading.Thread(
                target=handle_client,
                args=(conn, addr),
                daemon=True
            )
            client_thread.start()


def load_port():
    try:
        with open("port.info", "r") as f:
            return int(f.read().strip())
    except (OSError, ValueError):
        print("Warning: Could not read port.info. Using default port 1369.")
        return 1369


def register_client(name):
    with clients_lock:
        if name in clients or client_exists(name):
            raise ValueError(
                f"Client with name '{name}' is already registered")

        client_id = uuid.uuid4().bytes
        save_client(client_id, name)

        clients[name] = {
            "id": client_id
        }

        return client_id


# Find a client by its ID. Returns the client's name if found
def find_client_by_id(client_id):
    with clients_lock:
        for name, info in clients.items():
            if info["id"] == client_id:
                return name
        return None


# generate a random secure AES key of 32 bytes
def generate_aes_key():
    return get_random_bytes(32)


def encrypt_aes_key(public_key, aes_key):
    rsa_key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(rsa_key, hashAlgo=SHA1)
    encrypted_aes_key = cipher.encrypt(aes_key)
    return encrypted_aes_key


# Decrypts the AES-encrypted file content using
# the provided AES key.
def decrypt_file(encrypted_data, aes_key):
    if len(aes_key) != 32:
        raise ValueError("Invalid AES key size. Must be 32 bytes for AES-256.")

    # Validate the size of the encrypted data. It must be a
    # multiple of the AES block size (16 bytes) and not empty.
    if len(encrypted_data) == 0 or len(encrypted_data) % AES.block_size != 0:
        raise ValueError("Invalid encrypted data size")

    # Use a fixed IV of 16 zero bytes for AES-CBC mode.In a real-world scenario
    # you should use a random IV and send it along with the encrypted data.
    iv = b'\x00' * 16
    # Create a new AES cipher object in CBC mode with the provided
    # AES key and the fixed IV.
    AES_cipher = AES.new(aes_key, AES.MODE_CBC, iv=iv)
    # Decrypt the encrypted data using the AES cipher.
    decrypted_data = AES_cipher.decrypt(encrypted_data)
    # Remove the padding from the decrypted data to retrieve the
    # original plaintext.The unpad function ensures that
    # the padding is valid and removes it.
    original_data = unpad(decrypted_data, AES.block_size)
    return original_data


def save_received_file(client_id, file_name, file_content):
    # Reject unsafe filenames
    if (not file_name or file_name in (".", "..") or
            "/" in file_name or "\\" in file_name):
        raise ValueError("Invalid file name")

    # Create a directory for the client
    client_dir = os.path.join("received_files", client_id.hex())
    os.makedirs(client_dir, exist_ok=True)

    # Save the file in the client's directory
    file_path = os.path.join(client_dir, file_name)

    with open(file_path, "wb") as f:
        f.write(file_content)

    return file_path


def main():
    port = load_port()
    start_server(port)


if __name__ == "__main__":
    main()
