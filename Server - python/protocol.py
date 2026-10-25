import struct

VERSION = 3

# Request codes
REGISTER = 825
SEND_PUBLIC_KEY = 826
RECONNECT = 827
SEND_FILE = 828
VALID_CRC = 900
INVALID_CRC_RESEND = 901
INVALID_CRC_DONE = 902

# Response codes
REGISTRATION_SUCCESS = 1600
REGISTRATION_FAILED = 1601
SEND_AES = 1602
FILE_RECEIVED_WITH_CRC = 1603
MESSAGE_RECEIVED = 1604
RECONNECT_SUCCESS = 1605
RECONNECT_FAILED = 1606
SERVER_ERROR = 1607

REQUEST_FORMAT = "<16sBHI"
RESPONSE_FORMAT = "<BHI"

REQUEST_HEADER_SIZE = struct.calcsize(REQUEST_FORMAT)    # 23
RESPONSE_HEADER_SIZE = struct.calcsize(RESPONSE_FORMAT)   # 7

CLIENT_ID_SIZE = 16
NAME_SIZE = 255
PUBLIC_KEY_SIZE = 160
PUBLIC_KEY_REQUEST_PAYLOAD_SIZE = NAME_SIZE + PUBLIC_KEY_SIZE
FILE_PAYLOAD_FIXED_SIZE = 12 + NAME_SIZE


def parse_request_header(data):
    if len(data) < REQUEST_HEADER_SIZE:
        raise ValueError("Data is too short to contain a valid request header")
    return struct.unpack(REQUEST_FORMAT, data[:REQUEST_HEADER_SIZE])


def build_response_header(code, payload_size):
    return struct.pack(RESPONSE_FORMAT, VERSION, code, payload_size)


# parse the public key payload, which consists of a null-terminated
# name followed by a 160-byte public key
def parse_public_key_payload(payload):
    if len(payload) != PUBLIC_KEY_REQUEST_PAYLOAD_SIZE:
        raise ValueError("Invalid public key payload size")
    name = parse_name(payload[:NAME_SIZE])
    public_key = payload[NAME_SIZE:]
    return name, public_key


# parese the file payload
def parse_file_payload(payload):
    if len(payload) < FILE_PAYLOAD_FIXED_SIZE:
        raise ValueError("Invalid file payload size")
    # Unpack the first 12 bytes to get the file metadata
    (content_size, original_file_size, packet_number,
        total_packets) = struct.unpack("<IIHH", payload[:12])
    if packet_number < 1 or total_packets < 1 or packet_number > total_packets:
        raise ValueError("Invalid packet number")
    # Extract the file name from the next 255 bytes
    file_name = parse_name(payload[12:267])
    if not file_name:
        raise ValueError("Empty file name")
    file_content = payload[267:]  # The rest of the payload is the file content
    if content_size == 0:
        raise ValueError("Invalid AES encrypted content size")
    if len(file_content) == 0 or len(file_content) > content_size:
        raise ValueError("Invalid encrypted packet size")
    return (content_size, original_file_size, packet_number,
            total_packets, file_name, file_content)


def parse_name(payload):
    x = payload.find(b'\0')
    if x == -1:
        raise ValueError("Name is not null-terminated")
    if x == 0:
        raise ValueError("Name cannot be empty")
    if any(payload[x + 1:]):
        raise ValueError("Invalid padding after null terminator")
    return payload[:x].decode("ascii")


def build_file_crc_payload(client_id, encrypted_size, file_name, crc):
    if len(client_id) != CLIENT_ID_SIZE:
        raise ValueError("Invalid client ID size")
    file_name_bytes = file_name.encode("ascii")
    if not file_name_bytes or len(file_name_bytes) >= NAME_SIZE:
        raise ValueError("Invalid file name")
    file_name_bytes = file_name_bytes.ljust(NAME_SIZE, b'\0')
    return struct.pack("<16sI255sI", client_id, encrypted_size,
                       file_name_bytes, crc)
