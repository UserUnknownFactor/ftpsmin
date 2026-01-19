# ftpsmin - Minimal Secure FTP Server for Windows

[![Build](https://github.com/UserUnknownFactor/ftpsmin/actions/workflows/release.yml/badge.svg)](https://github.com/UserUnknownFactor/ftpsmin/actions/workflows/release.yml)
[![Release](https://img.shields.io/github/v/release/UserUnknownFactor/ftpsmin)](https://github.com/UserUnknownFactor/ftpsmin/releases)
[![License](https://img.shields.io/github/license/UserUnknownFactor/ftpsmin)](LICENSE)

A minimal, secure FTP server for Windows with TLS support, virtual directories, and Windows Service integration.

## Features

- **FTPS (FTP over TLS)** - Both explicit (AUTH TLS) and implicit TLS modes
- **Virtual Directories** - Map multiple physical directories to virtual paths
- **Per-Directory Permissions** - Read-only and hidden directory options
- **UTF-8 Support** - Full Unicode filename support
- **Resume Transfers** - REST command for resuming interrupted transfers
- **Windows Service** - Run as a Windows service with easy install/uninstall
- **JSON Configuration** - Simple, human-readable configuration file
- **MLSD/MLST** - Machine-readable directory listings (RFC 3659)
- **Multi-threaded** - Handles multiple simultaneous connections

## Quick Start

1. **Download** the latest release from the [Releases](https://github.com/UserUnknownFactor/ftpsmin/releases) page

2. **Generate a configuration file:**
   ```batch
   ftpsmin.exe -genconfig
   ```

3. **Edit `ftpsmin.json`** to configure your server

4. **Generate SSL certificate** (optional, for FTPS):
   ```batch
   openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes
   ```

5. **Run the server:**
   ```batch
   ftpsmin.exe
   ```

## Installation as Windows Service

```batch
# Install the service
ftpsmin.exe -install

# Start the service
ftpsmin.exe -start

# Check status
ftpsmin.exe -status

# Stop the service
ftpsmin.exe -stop

# Uninstall the service
ftpsmin.exe -uninstall
```

## Configuration

Example `ftpsmin.json`:

```json
{
    "port": 21,
    "passivePortStart": 50000,
    "passivePortEnd": 50100,

    "virtualDirs": [
        {
            "virtual": "/public",
            "physical": "C:\\FTP\\Public",
            "readOnly": false,
            "hidden": false
        },
        {
            "virtual": "/archive",
            "physical": "D:\\Archive",
            "readOnly": true,
            "hidden": false
        }
    ],

    "useTLS": true,
    "certFile": "server.crt",
    "keyFile": "server.key",

    "requireAuth": true,
    "username": "ftpuser",
    "password": "yourpassword",

    "defaultUtf8": true
}
```

### Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| `port` | Control port number | 21 |
| `hostAddress` | External IP address (for NAT) | (empty/auto-detect) |
| `passivePortStart` | Start of passive port range | 0 (random) |
| `passivePortEnd` | End of passive port range | 0 (random) |
| `virtualDirs` | Array of virtual directory mappings | [] |
| `useTLS` | Enable TLS support | false |
| `implicitTLS` | Use implicit TLS (port 990) | false |
| `certFile` | Path to SSL certificate | server.crt |
| `keyFile` | Path to SSL private key | server.key |
| `requireAuth` | Require username/password | false |
| `username` | Username for authentication | Anonymous |
| `password` | Password for authentication | (empty) |
| `defaultUtf8` | Enable UTF-8 by default | true |
| `getOnly` | Read-only mode (no uploads) | false |
| `logFile` | Path to log file | (empty/disabled) |
| `logLevel` | Log verbosity (0-3) | 2 |
| `maxConnections` | Maximum simultaneous connections | 10 |
| `idleTimeout` | Idle timeout in seconds | 300 |
| `transferTimeout` | Transfer timeout in seconds | 600 |
| `serviceName` | Windows service name | ftpsmin |
| `serviceDisplayName` | Service display name | FTPSMIN Secure FTP Server |
| `serviceDescription` | Service description | (see code) |
## Command Line Options

```
ftpsmin [options]

Options:
  -c <file>     Use specified JSON config file (default: ftpsmin.json)
  -genconfig    Generate sample configuration file
  -install      Install as Windows service
  -uninstall    Uninstall Windows service
  -start        Start the Windows service
  -stop         Stop the Windows service
  -status       Check Windows service status
  -h, -help     Show help message
  -version      Show version information
```

## Building from Source

### Prerequisites

- Visual Studio 2019/2022 or MinGW-w64
- OpenSSL development libraries

### Build with Visual Studio

```batch
# Open Developer Command Prompt
nmake
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

Based on the original ftpdmin by Matthias Wandel.