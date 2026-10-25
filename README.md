# Secure File Transfer System

A client-server file transfer project developed in **C++** and **Python**, combining TCP socket programming, asymmetric and symmetric cryptography, and file-integrity verification.

The project was developed as part of a university Defensive Systems Programming course. It demonstrates how a client and server can exchange encrypted files using a custom binary protocol, manage client registration and reconnection, and verify transferred data.

## Features

- **C++ client and Python server** communicating over TCP sockets.
- **Client registration and reconnection** using a persistent client identity.
- **RSA and AES cryptography** for key exchange and encrypted file transfer.
- **CRC-based integrity checking** to detect transfer errors, with a retry flow for mismatches.
- **Custom binary protocol** with defined request and response codes.
- **File upload workflow** with server-side processing and status responses.
- **Socket timeout handling** to avoid leaving inactive connections open indefinitely.

## Architecture

```text
+----------------------------+         TCP          +----------------------------+
| C++ Client                 | <------------------> | Python Server              |
|                            |                      |                            |
| Registration / reconnect   |                      | Request parsing            |
| RSA key management         |                      | Client management          |
| AES file encryption        |                      | Key exchange               |
| CRC verification           |                      | File reception / storage   |
+----------------------------+                      +----------------------------+
```

### Typical transfer flow

1. The client connects to the server and registers or reconnects using its existing identity.
2. The client and server perform the protocol's key-exchange steps.
3. The client encrypts the selected file and sends it in the protocol-defined format.
4. The server receives and processes the encrypted data and returns a CRC-related response.
5. The client checks the result and follows the protocol's confirmation or retry flow.

## Technologies

| Component | Technology |
| --- | --- |
| Client | C++ |
| Server | Python 3 |
| Networking | TCP sockets, Winsock |
| Cryptography | RSA, AES, Crypto++ (client) |
| Integrity checking | CRC |
| Development environment | Visual Studio, Windows |

## Repository structure

```text
Secure-File-Transfer-System/
├── Client - c++/          # C++ client implementation
├── Server - python/      # Python server implementation
└── README.md
```

## Getting started

### Prerequisites

- Windows with a C++ compiler and Visual Studio configured for the client.
- Crypto++ installed and configured for the C++ build.
- Python 3 for the server.
- A local TCP port available for client-server communication.

### Run the server

Open a terminal in the `Server - python` directory and run the server's Python entry point. Configure the listening address and port as required by the server implementation.

### Build and run the client

1. Open or create a Visual Studio C++ project containing the files from `Client - c++`.
2. Configure the include and library paths for Crypto++ and link the required library.
3. Build the client for the selected architecture and configuration.
4. Set the server address, port, and file-transfer settings in the configuration files expected by the client.
5. Start the server first, then run the compiled client executable.

> **Note:** Exact build commands and configuration filenames depend on the checked-in source and local Crypto++ setup. No prebuilt Visual Studio solution is assumed.

## Protocol overview

The application uses a custom binary protocol with versioned messages, request codes, and response codes. The protocol supports registration, public-key exchange, reconnection, encrypted file transfer, and CRC confirmation or retry messages.

The protocol is an educational implementation rather than a standardized secure file-transfer protocol.

## Security considerations

This project explores secure-programming concepts, but **should not be used to protect sensitive files in production** without further security review and hardening.

In particular:

- CRC detects accidental corruption; it is **not** a cryptographic message-authentication mechanism.
- Encryption alone does not guarantee peer authentication or replay protection.
- Production deployments would require stronger authentication, authenticated encryption, replay defenses, resource limits, and comprehensive security testing.

## What I learned

- Designing and implementing a binary network protocol across two programming languages.
- Handling partial socket reads and writes and connection failures.
- Integrating asymmetric and symmetric cryptography into a file-transfer workflow.
- Coordinating client and server state during registration, reconnection, and file transfer.
- Debugging interoperability issues between C++ and Python.

## Author

**Pierre Shakour**  
[GitHub](https://github.com/PierreShakour)
