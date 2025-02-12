# Swift FTP Server With Custom TCP/IP Stack

A secure FTP server and client implementation in Python featuring a custom TCP/IP stack, built-in file system with SQLite backend, and interactive command-line interfaces.

## Features

### Core Features
- Standard FTP command support (RFC 959)
- TLS/SSL encryption (FTPS)
- User authentication and access control
- File system permissions management
- Passive mode data transfers
- Compatible with FileZilla and other standard FTP clients

### Built-in File System
- SQLite-backed virtual file system
- File ownership management
- Access control
- Interactive file system CLI

### Client Features
- Interactive command-line client
- TLS/FTPS support

### Custom TCP/IP Stack
- Raw socket TCP implementation
- Connection establishment (3-way handshake)
- Keep-Alive 
- TCP flags, sequence numbers, window sizing

## Supported FTP Commands

### Authentication Commands
- `USER` - Login username
- `PASS` - Login password
- `REIN` - Reinitialize session
- `QUIT` - End session

### File Operations
- `RETR` - Download file 
- `STOR` - Upload file
- `DELE` - Delete file
- `RNFR` - Rename from (source)
- `RNTO` - Rename to (destination)

### Directory Operations
- `LIST` - List files
- `MLSD` - Machine list directory
- `PWD` - Print working directory
- `CWD` - Change working directory 
- `CDUP` - Change to parent directory
- `MKD` - Create directory
- `RMD` - Remove directory

### Settings & Info
- `TYPE` - Set transfer type
- `OPTS` - Set options
- `FEAT` - Get features
- `SYST` - Get system info
- `HELP` - Show help
- `NOOP` - No operation

### Security Commands
- `AUTH TLS` - Initialize TLS
- `PBSZ` - Protection buffer size
- `PROT` - Data channel protection level

## File System CLI Commands

- `login <user> <pass>` - Login to system
- `logout` - Logout from system
- `ls [path]` - List directory contents
- `cd <path>` - Change directory
- 

pwd

 - Print working directory 

mkdir <path>

 - Create directory

rmdir <path>

 - Remove directory

touch <file>

 - Create empty file
- `rm <file>` - Remove file

chmod <path> <perms>

 - Change permissions

rename <old> <new>

 - Rename file/directory

## Installation

### Starting the Server
```bash
# Linux
./deploy_server.sh

# Windows 
.\deploy_server.ps1
```

Or manually:

1. Clone the repository
2. Install dependencies:
```bash 
pip install -r requirements.txt
```

```bash
pip install -r requirements.txt
python start_server.py
```

### Using the FTP Client
```bash
python src/ftp_client/start_client.py
```

### Using the File System CLI
```bash
python file_system_cli.py -i
```

## Configuration

Server settings in server_config.json
```json
{
    "ftp_host": "127.0.0.1", 
    "ftp_port": 229,
    "use_custom_transport": false,
    "support_FTPS": true
}
```
