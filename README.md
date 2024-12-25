# FTP Server

A secure FTP server and client implementation in Python with support for TLS encryption, user authentication, and file system permissions.

## Features

- FTP server supporting standard FTP commands (RFC 959)
- TLS/SSL encryption support 
- User authentication and access control
- File system permissions management
- Interactive command line client
- Passive mode data transfers
- Support for basic FTP operations:
  - File upload/download
  - Directory listing
  - Directory creation/removal
  - File renaming
  - File deletion
  - Permission changes

## Installation

1. Clone the repository
2. Install dependencies:
```sh
pip install -r requirements.txt
```

## Usage

### Starting the Server

Run the server using:

```sh
python start_server.py
```

### Using the Client 

Run the interactive client:

```sh
python src/ftp_client/start_client.py
```

Available client commands:
- `USER <username>` - Login with username
- `PASS <password>` - Send password
- `LIST` - List files in current directory
- `CWD <path>` - Change working directory
- `PWD` - Print working directory
- `RETR <filename>` - Download file
- `STOR <filename>` - Upload file
- `DELE <filename>` - Delete file
- `MKD <dirname>` - Create directory
- `RMD <dirname>` - Remove directory
- `RNFR/RNTO` - Rename files
- `QUIT` - Exit session

### File System CLI

For direct file system management:

```sh
python file_system_cli.py
```

## Configuration

Server settings can be configured in 

server_config.json

:
- Port number
- TLS settings
- Root directory
- Database path

## Testing

Run the test suite:

```sh
python -m pytest test_server.py
```
