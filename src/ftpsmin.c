//------------------------------------------------------------------------------------
// Minimal FTPS server program
// Windows Service, JSON config, UTF-8, and multi-root support
//------------------------------------------------------------------------------------

#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <process.h>
#include <stdio.h>
#include <io.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <direct.h>
#include <time.h>
#include <sys/types.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <wchar.h>
#include <locale.h>
#include <stdarg.h>

#include "config.h"
#include "service.h"
#include "ssl_support.h"
#include "utf8_support.h"
#include "vfs.h"

#define FTPSMIN_VER "1.0"
#define FTPSMIN_DATE "2026"

//------------------------------------------------------------------------------------
// Global variables
//------------------------------------------------------------------------------------
ServerConfig g_Config;
BOOL g_RunAsService = FALSE;
BOOL g_ServiceStop = FALSE;

struct in_addr OurAddr;
char OurAddrStr[20];
int addrlen = sizeof(struct sockaddr_in);
char PortsUsed[256];
CRITICAL_SECTION g_PortsLock;

//------------------------------------------------------------------------------------
// Transfer type enumeration
//------------------------------------------------------------------------------------
typedef enum {
    TRANSFER_TYPE_ASCII,
    TRANSFER_TYPE_BINARY
} TransferType;

//------------------------------------------------------------------------------------
// Structure mode enumeration
//------------------------------------------------------------------------------------
typedef enum {
    STRUCT_FILE,
    STRUCT_RECORD,
    STRUCT_PAGE
} StructureMode;

//------------------------------------------------------------------------------------
// Transfer mode enumeration
//------------------------------------------------------------------------------------
typedef enum {
    MODE_STREAM,
    MODE_BLOCK,
    MODE_COMPRESSED
} TransferMode;

//------------------------------------------------------------------------------------
// Connection instance structure
//------------------------------------------------------------------------------------
typedef struct {
    struct sockaddr_in xfer_addr;
    struct sockaddr_in client_addr;
    BOOL PassiveMode;
    SOCKET PassiveSocket;
    char XferBuffer[262144];
    SOCKET CommandSocket;
    int XferPort;
    SSL *ssl;                       // SSL connection for control channel
    BOOL UseSSL;                    // Whether this connection uses SSL
    BOOL UseUTF8;                   // UTF-8 mode enabled
    BOOL DataProtection;            // Data channel protection (PROT P)
    char RenameFrom[MAX_PATH * 3];  // For RNFR/RNTO
    char CurrentDir[MAX_PATH * 3];  // Per-connection current directory

    // Transfer parameters
    TransferType Type;              // ASCII or Binary
    StructureMode Structure;        // File structure
    TransferMode Mode;              // Stream mode
    LONGLONG RestartOffset;         // REST offset for resumed transfers

    // State flags
    BOOL Authenticated;
    char Username[64];

    // Statistics
    ULONGLONG BytesSent;
    ULONGLONG BytesReceived;
    DWORD ConnectTime;
} Inst_t;

//------------------------------------------------------------------------------------
// FTP Command tokens
//------------------------------------------------------------------------------------
typedef enum {
    // Access control commands
    USER, PASS, ACCT, CWD, CDUP, SMNT, QUIT, REIN,

    // Transfer parameter commands
    PORT, PASV, TYPE, STRU, MODE,

    // FTP service commands
    RETR, STOR, STOU, APPE, ALLO, REST, RNFR, RNTO,
    ABOR, DELE, RMD, XRMD, MKD, XMKD, PWD, XPWD,
    LIST, NLST, SITE, SYST, STAT, HELP, NOOP,

    // Extended commands
    MDTM, xSIZE, MLST, MLSD, FEAT, OPTS, 

    // Security commands (RFC 4217)
    // Note: CONF renamed to FTP_CONF to avoid OpenSSL conflict
    AUTH, ADAT, PROT, PBSZ, CCC, MIC, FTP_CONF, ENC,

    // Other
    CLNT, EPRT, EPSV, LANG,

    UNKNOWN_COMMAND
} CmdTypes;

//------------------------------------------------------------------------------------
// Command lookup table
//------------------------------------------------------------------------------------
typedef struct {
    const char *command;
    CmdTypes CmdNum;
    BOOL requiresAuth;
    BOOL requiresArg;
    const char *help;       // Help text
} CommandDef;

static const CommandDef CommandTable[] = {
    // Access control
    {"USER", USER, FALSE, TRUE,  "Specify username"},
    {"PASS", PASS, FALSE, TRUE,  "Specify password"},
    {"ACCT", ACCT, TRUE,  TRUE,  "Specify account (not implemented)"},
    {"CWD",  CWD,  TRUE,  TRUE,  "Change working directory"},
    {"CDUP", CDUP, TRUE,  FALSE, "Change to parent directory"},
    {"SMNT", SMNT, TRUE,  TRUE,  "Structure mount (not implemented)"},
    {"QUIT", QUIT, FALSE, FALSE, "Disconnect"},
    {"REIN", REIN, FALSE, FALSE, "Reinitialize connection"},

    // Transfer parameters
    {"PORT", PORT, TRUE,  TRUE,  "Specify data port"},
    {"PASV", PASV, TRUE,  FALSE, "Enter passive mode"},
    {"EPRT", EPRT, TRUE,  TRUE,  "Extended port (IPv6)"},
    {"EPSV", EPSV, TRUE,  FALSE, "Extended passive mode"},
    {"TYPE", TYPE, TRUE,  TRUE,  "Set transfer type (A/I)"},
    {"STRU", STRU, TRUE,  TRUE,  "Set file structure"},
    {"MODE", MODE, TRUE,  TRUE,  "Set transfer mode"},

    // FTP service commands
    {"RETR", RETR, TRUE,  TRUE,  "Retrieve file"},
    {"STOR", STOR, TRUE,  TRUE,  "Store file"},
    {"STOU", STOU, TRUE,  FALSE, "Store unique file"},
    {"APPE", APPE, TRUE,  TRUE,  "Append to file"},
    {"ALLO", ALLO, TRUE,  TRUE,  "Allocate space (ignored)"},
    {"REST", REST, TRUE,  TRUE,  "Restart transfer at offset"},
    {"RNFR", RNFR, TRUE,  TRUE,  "Rename from"},
    {"RNTO", RNTO, TRUE,  TRUE,  "Rename to"},
    {"ABOR", ABOR, TRUE,  FALSE, "Abort transfer"},
    {"DELE", DELE, TRUE,  TRUE,  "Delete file"},
    {"RMD",  RMD,  TRUE,  TRUE,  "Remove directory"},
    {"XRMD", XRMD, TRUE,  TRUE,  "Remove directory"},
    {"MKD",  MKD,  TRUE,  TRUE,  "Make directory"},
    {"XMKD", XMKD, TRUE,  TRUE,  "Make directory"},
    {"PWD",  PWD,  TRUE,  FALSE, "Print working directory"},
    {"XPWD", XPWD, TRUE,  FALSE, "Print working directory"},
    {"LIST", LIST, TRUE,  FALSE, "List directory contents"},
    {"NLST", NLST, TRUE,  FALSE, "Name list"},
    {"SITE", SITE, TRUE,  TRUE,  "Site-specific commands"},
    {"SYST", SYST, FALSE, FALSE, "System type"},
    {"STAT", STAT, FALSE, FALSE, "Status"},
    {"HELP", HELP, FALSE, FALSE, "Help"},
    {"NOOP", NOOP, FALSE, FALSE, "No operation"},

    // Extended commands
    {"SIZE", xSIZE, TRUE, TRUE,  "Get file size"},
    {"MDTM", MDTM,  TRUE, TRUE,  "Get modification time"},
    {"MLST", MLST,  TRUE, FALSE, "Machine-readable list (single)"},
    {"MLSD", MLSD,  TRUE, FALSE, "Machine-readable list (directory)"},
    {"FEAT", FEAT,  FALSE, FALSE, "List features"},
    {"OPTS", OPTS,  FALSE, TRUE,  "Set options"},
    {"LANG", LANG,  FALSE, FALSE, "Set language"},
    {"CLNT", CLNT,  FALSE, TRUE,  "Client identification"},

    // Security commands
    {"AUTH", AUTH, FALSE, TRUE,  "Authentication mechanism"},
    {"PBSZ", PBSZ, FALSE, TRUE,  "Protection buffer size"},
    {"PROT", PROT, FALSE, TRUE,  "Data channel protection"},
    {"CCC",  CCC,  FALSE, FALSE, "Clear command channel"},
};

#define NUM_COMMANDS (sizeof(CommandTable) / sizeof(CommandDef))

//------------------------------------------------------------------------------------
// Month name helper
//------------------------------------------------------------------------------------
static const char* GetMonthName(int month)
{
    static const char *months[] = {
        "Jan", "Feb", "Mar", "Apr", "May", "Jun",
        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
    };
    if (month >= 1 && month <= 12) {
        return months[month - 1];
    }
    return "???";
}

//------------------------------------------------------------------------------------
// Logging function
//------------------------------------------------------------------------------------
void LogMessage(const char *format, ...)
{
    va_list args;
    char timestamp[32];
    time_t now;
    struct tm *tm_info;

    if (g_RunAsService) {
        // Could log to Windows Event Log or file here
        return;
    }

    time(&now);
    tm_info = localtime(&now);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);

    printf("[%s] ", timestamp);

    va_start(args, format);
    vprintf(format, args);
    va_end(args);

    printf("\n");
    fflush(stdout);
}

//------------------------------------------------------------------------------------
// SSL-aware send wrapper
//------------------------------------------------------------------------------------
static int SecureSend(Inst_t *Conn, SOCKET sock, const char *buf, int len, SSL *ssl)
{
    int totalSent = 0;

    while (totalSent < len) {
        int sent;
        if (ssl != NULL) {
            sent = SSL_write(ssl, buf + totalSent, len - totalSent);
            if (sent <= 0) {
                int err = SSL_get_error(ssl, sent);
                if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
                    continue;
                }
                LogMessage("SSL_write error: %d", err);
                return -1;
            }
        } else {
            sent = send(sock, buf + totalSent, len - totalSent, 0);
            if (sent < 0) {
                return -1;
            }
        }
        totalSent += sent;
    }
    return totalSent;
}

//------------------------------------------------------------------------------------
// SSL-aware recv wrapper
//------------------------------------------------------------------------------------
static int SecureRecv(Inst_t *Conn, SOCKET sock, char *buf, int len, SSL *ssl)
{
    if (ssl != NULL) {
        int result = SSL_read(ssl, buf, len);
        if (result <= 0) {
            int err = SSL_get_error(ssl, result);
            if (err != SSL_ERROR_ZERO_RETURN && 
                err != SSL_ERROR_WANT_READ && 
                err != SSL_ERROR_WANT_WRITE) {
                LogMessage("SSL_read error: %d", err);
            }
        }
        return result;
    }
    return recv(sock, buf, len, 0);
}

//------------------------------------------------------------------------------------
// Create a TCP/IP socket, return the socket for the connection
//------------------------------------------------------------------------------------
static SOCKET CreateTcpipSocket(int *Port)
{
    struct sockaddr_in socket_addr;
    SOCKET sock;
    int socket_addr_size = sizeof(socket_addr);
    int optval = 1;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        LogMessage("CreateTcpipSocket(): socket failed, error %d", WSAGetLastError());
        return INVALID_SOCKET;
    }

    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char*)&optval, sizeof(optval));

    memset(&socket_addr, 0, socket_addr_size);
    socket_addr.sin_family = AF_INET;
    socket_addr.sin_addr.s_addr = INADDR_ANY;
    socket_addr.sin_port = htons((short)*Port);

    if (bind(sock, (const struct sockaddr *)&socket_addr, socket_addr_size) < 0) {
        LogMessage("Could not bind to port %d, error %d", *Port, WSAGetLastError());
        closesocket(sock);
        return INVALID_SOCKET;
    }

    if (getsockname(sock, (struct sockaddr *)&socket_addr, &socket_addr_size) < 0) {
        LogMessage("getsockname() failed, error %d", WSAGetLastError());
        closesocket(sock);
        return INVALID_SOCKET;
    }

    *Port = ntohs(socket_addr.sin_port);
    return sock;
}

//------------------------------------------------------------------------------------
// Initiate a connection to a tcp/ip port
//------------------------------------------------------------------------------------
static SOCKET ConnectTcpip(struct sockaddr_in *addr, int addrlen)
{
    SOCKET sock;
    struct timeval timeout;
    fd_set writefds;
    u_long nonBlocking = 1;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        LogMessage("socket() failed, error %d", WSAGetLastError());
        return INVALID_SOCKET;
    }

    // Set non-blocking for connect with timeout
    ioctlsocket(sock, FIONBIO, &nonBlocking);

    if (connect(sock, (struct sockaddr *)addr, addrlen) < 0) {
        int err = WSAGetLastError();
        if (err != WSAEWOULDBLOCK) {
            LogMessage("connect() failed, error %d", err);
            closesocket(sock);
            return INVALID_SOCKET;
        }

        // Wait for connection with timeout
        FD_ZERO(&writefds);
        FD_SET(sock, &writefds);
        timeout.tv_sec = 30;
        timeout.tv_usec = 0;

        if (select(0, NULL, &writefds, NULL, &timeout) <= 0) {
            LogMessage("connect() timeout");
            closesocket(sock);
            return INVALID_SOCKET;
        }
    }

    // Set back to blocking
    nonBlocking = 0;
    ioctlsocket(sock, FIONBIO, &nonBlocking);

    return sock;
}

//------------------------------------------------------------------------------------
// Find command in table
//------------------------------------------------------------------------------------
static const CommandDef* FindCommand(const char *cmd)
{
    size_t i;
    for (i = 0; i < NUM_COMMANDS; i++) {
        if (_stricmp(cmd, CommandTable[i].command) == 0) {
            return &CommandTable[i];
        }
    }
    return NULL;
}

//------------------------------------------------------------------------------------
// Send a reply to the client
//------------------------------------------------------------------------------------
static void SendReply(Inst_t *Conn, const char *Reply)
{
    char ReplyStr[MAX_PATH * 3 + 32];

    LogMessage("> %s", Reply);

    snprintf(ReplyStr, sizeof(ReplyStr), "%s\r\n", Reply);
    SecureSend(Conn, Conn->CommandSocket, ReplyStr, (int)strlen(ReplyStr), Conn->ssl);
}

//------------------------------------------------------------------------------------
// Get a FTP command from the command stream
//------------------------------------------------------------------------------------
static CmdTypes GetCommand(Inst_t *Conn, char *CmdArg, const CommandDef **cmdDef)
{
    char InputString[2048];
    int CmdLen;
    char Command[8];
    int a, b;

    *cmdDef = NULL;
    CmdArg[0] = '\0';

    CmdLen = 0;
    memset(InputString, 0, sizeof(InputString));

    for (;;) {
        int n;
        fd_set readfds;
        struct timeval timeout;

        // Check for shutdown
        if (g_ServiceStop) {
            SendReply(Conn, "421 Server shutting down");
            Sleep(100);
            return (CmdTypes)-1;
        }

        FD_ZERO(&readfds);
        FD_SET(Conn->CommandSocket, &readfds);
        timeout.tv_sec = 1;  // 1 second
        timeout.tv_usec = 0;

        n = select(0, &readfds, NULL, NULL, &timeout);
        if (n < 0) {
            return (CmdTypes)-1;  // Socket error
        }
        if (n == 0) {
            continue;  // Timeout - loop back and check g_ServiceStop
        }

        // Data available, read it
        n = SecureRecv(Conn, Conn->CommandSocket, InputString + CmdLen,
                       (int)(sizeof(InputString) - CmdLen - 1), Conn->ssl);
        if (n <= 0) return (CmdTypes)-1;

        CmdLen += n;
        InputString[CmdLen] = '\0';
        if (strstr(InputString, "\r\n") || strstr(InputString, "\n")) break;
        if (CmdLen >= (int)(sizeof(InputString) - 1)) break;
    }

    // Parse command (up to 4 characters)
    memset(Command, 0, sizeof(Command));
    for (a = 0; a < 4 && InputString[a]; a++) {
        if (!isalpha((unsigned char)InputString[a])) break;
        Command[a] = (char)toupper((unsigned char)InputString[a]);
    }

    // Skip command and space, get argument
    b = 0;
    while (InputString[a] == ' ') a++;
    for (b = 0; b < MAX_PATH * 3 - 1; b++) {
        if (InputString[a + b] == '\r' || InputString[a + b] == '\n' ||
            InputString[a + b] == '\0') break;
        CmdArg[b] = InputString[a + b];
    }
    CmdArg[b] = '\0';

    // Trim trailing spaces from argument
    while (b > 0 && CmdArg[b-1] == ' ') {
        CmdArg[--b] = '\0';
    }

    if (_stricmp(Command, "PASS") == 0) {
        LogMessage("< PASS *******");
    } else {
        LogMessage("< %s %s", Command, CmdArg);
    }

    *cmdDef = FindCommand(Command);
    if (*cmdDef) {
        return (*cmdDef)->CmdNum;
    }

    LogMessage("Unknown command: %s", Command);
    return UNKNOWN_COMMAND;
}

//------------------------------------------------------------------------------------
// Send a formatted reply
//------------------------------------------------------------------------------------
static void SendReplyFmt(Inst_t *Conn, const char *format, ...)
{
    char Reply[MAX_PATH * 3 + 256];
    va_list args;

    va_start(args, format);
    vsnprintf(Reply, sizeof(Reply), format, args);
    va_end(args);

    SendReply(Conn, Reply);
}

//------------------------------------------------------------------------------------
// Send a multi-line reply
//------------------------------------------------------------------------------------
static void SendMultiLineReply(Inst_t *Conn, const char *Reply)
{
    // Log each line separately
    const char *line = Reply;
    while (*line) {
        const char *end = strstr(line, "\r\n");
        if (end) {
            char temp[512];
            size_t len = end - line;
            if (len >= sizeof(temp)) len = sizeof(temp) - 1;
            strncpy(temp, line, len);
            temp[len] = '\0';
            LogMessage("> %s", temp);
            line = end + 2;
        } else {
            LogMessage("> %s", line);
            break;
        }
    }

    SecureSend(Conn, Conn->CommandSocket, Reply, (int)strlen(Reply), Conn->ssl);
}

//------------------------------------------------------------------------------------
// Report file/system error with specific code
//------------------------------------------------------------------------------------
static void SendError(Inst_t *Conn, int code, const char *message)
{
    DWORD err = GetLastError();
    char *msgBuf = NULL;
    char ErrString[512];

    if (message) {
        snprintf(ErrString, sizeof(ErrString), "%d %s", code, message);
    } else {
        FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
                       NULL, err, 0, (LPSTR)&msgBuf, 0, NULL);

        if (msgBuf) {
            char *p = msgBuf + strlen(msgBuf) - 1;
            while (p >= msgBuf && (*p == '\r' || *p == '\n' || *p == '.')) *p-- = '\0';
            snprintf(ErrString, sizeof(ErrString), "%d %s", code, msgBuf);
            LocalFree(msgBuf);
        } else {
            snprintf(ErrString, sizeof(ErrString), "%d Error %lu", code, err);
        }
    }

    SendReply(Conn, ErrString);
}

//------------------------------------------------------------------------------------
// Send 550 error (file unavailable)
//------------------------------------------------------------------------------------
static void Send550Error(Inst_t *Conn)
{
    SendError(Conn, 550, NULL);
}

//------------------------------------------------------------------------------------
// Send 553 error (action not taken, file name not allowed)
//------------------------------------------------------------------------------------
static void Send553Error(Inst_t *Conn, const char *msg)
{
    SendError(Conn, 553, msg ? msg : "Permission denied");
}

//------------------------------------------------------------------------------------
// Create SSL connection for data channel
//------------------------------------------------------------------------------------
static SSL* CreateDataSSL(SOCKET sock)
{
    if (!g_Config.useTLS) return NULL;
    return SSL_CreateConnection(sock);
}

//------------------------------------------------------------------------------------
// Open data connection
//------------------------------------------------------------------------------------
static SOCKET OpenDataConnection(Inst_t *Conn, SSL **data_ssl)
{
    SOCKET xfer_sock;

    *data_ssl = NULL;

    if (Conn->PassiveMode) {
        struct timeval timeout;
        fd_set readfds;

        FD_ZERO(&readfds);
        FD_SET(Conn->PassiveSocket, &readfds);
        timeout.tv_sec = 60;
        timeout.tv_usec = 0;

        if (select(0, &readfds, NULL, NULL, &timeout) <= 0) {
            LogMessage("Passive mode connection timeout");
            return INVALID_SOCKET;
        }

        xfer_sock = accept(Conn->PassiveSocket, NULL, NULL);
        if (xfer_sock == INVALID_SOCKET) {
            LogMessage("Passive mode accept failed, error %d", WSAGetLastError());
            return INVALID_SOCKET;
        }
    } else {
        xfer_sock = ConnectTcpip(&Conn->xfer_addr, sizeof(Conn->xfer_addr));
        if (xfer_sock == INVALID_SOCKET) {
            return INVALID_SOCKET;
        }
    }

    // Set up SSL for data channel if required
    if (Conn->UseSSL && Conn->DataProtection && g_Config.useTLS) {
        *data_ssl = CreateDataSSL(xfer_sock);
        if (!*data_ssl) {
            LogMessage("Failed to establish SSL on data channel");
            closesocket(xfer_sock);
            return INVALID_SOCKET;
        }
    }

    return xfer_sock;
}

//------------------------------------------------------------------------------------
// Close data connection
//------------------------------------------------------------------------------------
static void CloseDataConnection(SOCKET sock, SSL *data_ssl)
{
    if (data_ssl) {
        SSL_FreeConnection(data_ssl);
    }
    if (sock != INVALID_SOCKET) {
        closesocket(sock);
    }
}

//------------------------------------------------------------------------------------
// Format file time for MLST/MLSD
//------------------------------------------------------------------------------------
static void FormatMlstTime(FILETIME *ft, char *buf, size_t bufSize)
{
    SYSTEMTIME st;
    FileTimeToSystemTime(ft, &st);
    snprintf(buf, bufSize, "%04d%02d%02d%02d%02d%02d",
             st.wYear, st.wMonth, st.wDay,
             st.wHour, st.wMinute, st.wSecond);
}

//------------------------------------------------------------------------------------
// Format file entry for MLST/MLSD
//------------------------------------------------------------------------------------
static void FormatMlstEntry(VFS_DirEntry *entry, char *buf, size_t bufSize, 
                            BOOL includePathPrefix, const char *path)
{
    char timeStr[32];
    char typeStr[32];
    char permStr[32];

    FormatMlstTime(&entry->modTime, timeStr, sizeof(timeStr));

    if (entry->isDirectory) {
        strcpy(typeStr, "type=dir");
        strcpy(permStr, "perm=el");  // enter, list
    } else {
        strcpy(typeStr, "type=file");
        strcpy(permStr, "perm=r");   // read
        if (!(entry->attributes & FILE_ATTRIBUTE_READONLY)) {
            strcat(permStr, "adfw");  // append, delete, rename, write
        }
    }

    if (entry->isDirectory) {
        snprintf(buf, bufSize, "%s;%s;modify=%s; %s%s",
                 typeStr, permStr, timeStr,
                 includePathPrefix && path ? path : "",
                 entry->name);
    } else {
        snprintf(buf, bufSize, "%s;%s;size=%llu;modify=%s; %s%s",
                 typeStr, permStr, entry->size, timeStr,
                 includePathPrefix && path ? path : "",
                 entry->name);
    }
}

//------------------------------------------------------------------------------------
// Handle the NLST/LIST command using VFS
//------------------------------------------------------------------------------------
static void Cmd_NLST(Inst_t *Conn, char *filename, BOOL Long, BOOL UseCtrlConn)
{
    SOCKET xfer_sock = INVALID_SOCKET;
    char repbuf[2048];
    BOOL ListAll = FALSE;
    SSL *data_ssl = NULL;
    VFS_FindHandle *findHandle;
    VFS_DirEntry entry;
    char pattern[MAX_PATH * 3];

    // Parse options from filename (e.g., -la)
    strcpy(pattern, filename);
    if (pattern[0] == '-') {
        int a;
        for (a = 1; pattern[a] && pattern[a] != ' '; a++) {
            switch (pattern[a]) {
                case 'a': case 'A': ListAll = TRUE; break;
                case 'l': case 'L': Long = TRUE; break;
                // Ignore other options
            }
        }
        char *p = pattern + a;
        while (*p == ' ') p++;
        if (*p) {
            memmove(pattern, p, strlen(p) + 1);
        } else {
            pattern[0] = '\0';
        }
    }

    if (UseCtrlConn) {
        xfer_sock = Conn->CommandSocket;
        data_ssl = Conn->ssl;
        SendReply(Conn, "213-Status follows:");
    } else {
        SendReply(Conn, "150 Opening data connection for directory listing");

        xfer_sock = OpenDataConnection(Conn, &data_ssl);
        if (xfer_sock == INVALID_SOCKET) {
            SendError(Conn, 425, "Cannot open data connection");
            return;
        }
    }

    findHandle = VFS_FindFirst(Conn->CurrentDir, pattern[0] ? pattern : "*", &entry);

    if (findHandle) {
        do {
            if (!ListAll) {
                if (entry.attributes & FILE_ATTRIBUTE_HIDDEN) continue;
                if (entry.attributes & FILE_ATTRIBUTE_SYSTEM) continue;
            }

            if (Long) {
                SYSTEMTIME st;
                char timestr[32];
                char DirAttr;
                char WriteAttr;
                time_t now;
                struct tm *tm_now;
                int current_year;

                FileTimeToSystemTime(&entry.modTime, &st);

                time(&now);
                tm_now = localtime(&now);
                current_year = tm_now->tm_year + 1900;

                if (st.wYear == current_year) {
                    snprintf(timestr, sizeof(timestr), "%s %2d %02d:%02d",
                            GetMonthName(st.wMonth), st.wDay,
                            st.wHour, st.wMinute);
                } else {
                    snprintf(timestr, sizeof(timestr), "%s %2d  %04d",
                            GetMonthName(st.wMonth), st.wDay, st.wYear);
                }

                DirAttr = entry.isDirectory ? 'd' : '-';

                if (entry.attributes & FILE_ATTRIBUTE_READONLY) {
                    WriteAttr = '-';
                } else if (g_Config.getOnly || VFS_IsReadOnly(Conn->CurrentDir)) {
                    WriteAttr = '-';
                } else {
                    WriteAttr = 'w';
                }

                snprintf(repbuf, sizeof(repbuf),
                        "%cr%c-r%c-r%c-   1 owner    group    %13llu %s %s\r\n",
                        DirAttr, WriteAttr, WriteAttr, WriteAttr,
                        entry.size,
                        timestr,
                        entry.name);
            } else {
                snprintf(repbuf, sizeof(repbuf), "%s\r\n", entry.name);
            }

            SecureSend(Conn, xfer_sock, repbuf, (int)strlen(repbuf), data_ssl);

        } while (VFS_FindNext(findHandle, &entry));

        VFS_FindClose(findHandle);
    }

    if (UseCtrlConn) {
        SendReply(Conn, "213 End of status");
    } else {
        CloseDataConnection(xfer_sock, data_ssl);
        SendReply(Conn, "226 Transfer complete");
    }
}

//------------------------------------------------------------------------------------
// Handle MLSD command (machine-readable directory listing)
//------------------------------------------------------------------------------------
static void Cmd_MLSD(Inst_t *Conn, char *dirname)
{
    SOCKET xfer_sock;
    char repbuf[2048];
    SSL *data_ssl = NULL;
    VFS_FindHandle *findHandle;
    VFS_DirEntry entry;

    SendReply(Conn, "150 Opening data connection for MLSD");

    xfer_sock = OpenDataConnection(Conn, &data_ssl);
    if (xfer_sock == INVALID_SOCKET) {
        SendError(Conn, 425, "Cannot open data connection");
        return;
    }

    findHandle = VFS_FindFirst(Conn->CurrentDir, dirname[0] ? dirname : "*", &entry);

    if (findHandle) {
        do {
            FormatMlstEntry(&entry, repbuf, sizeof(repbuf) - 2, FALSE, NULL);
            strcat(repbuf, "\r\n");
            SecureSend(Conn, xfer_sock, repbuf, (int)strlen(repbuf), data_ssl);
        } while (VFS_FindNext(findHandle, &entry));

        VFS_FindClose(findHandle);
    }

    CloseDataConnection(xfer_sock, data_ssl);
    SendReply(Conn, "226 Transfer complete");
}

//------------------------------------------------------------------------------------
// Handle MLST command (machine-readable single file info)
//------------------------------------------------------------------------------------
static void Cmd_MLST(Inst_t *Conn, char *filename)
{
    VFS_DirEntry entry;
    char repbuf[2048];
    WIN32_FILE_ATTRIBUTE_DATA info;

    if (!filename[0]) {
        // Info about current directory
        strcpy(entry.name, ".");
        entry.isDirectory = TRUE;
        entry.isVirtualRoot = FALSE;
        entry.size = 0;
        entry.attributes = FILE_ATTRIBUTE_DIRECTORY;
        GetSystemTimeAsFileTime(&entry.modTime);
    } else {
        if (!VFS_GetFileInfo(Conn->CurrentDir, filename, &info)) {
            Send550Error(Conn);
            return;
        }

        strcpy(entry.name, filename);
        entry.isDirectory = (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
        entry.isVirtualRoot = FALSE;
        entry.attributes = info.dwFileAttributes;
        entry.modTime = info.ftLastWriteTime;

        ULARGE_INTEGER size;
        size.LowPart = info.nFileSizeLow;
        size.HighPart = info.nFileSizeHigh;
        entry.size = size.QuadPart;
    }

    FormatMlstEntry(&entry, repbuf, sizeof(repbuf), TRUE, Conn->CurrentDir);

    SendReplyFmt(Conn, "250-Listing %s", filename[0] ? filename : ".");
    SendReplyFmt(Conn, " %s", repbuf);
    SendReply(Conn, "250 End");
}

//------------------------------------------------------------------------------------
// Handle the RETR command using VFS with REST support
//------------------------------------------------------------------------------------
static void Cmd_RETR(Inst_t *Conn, char *filename)
{
    HANDLE file;
    SOCKET xfer_sock;
    DWORD bytesRead;
    SSL *data_ssl = NULL;
    ULONGLONG totalBytes = 0;
    LARGE_INTEGER fileSize;
    LARGE_INTEGER seekPos;

    file = VFS_CreateFile(Conn->CurrentDir, filename, GENERIC_READ, FILE_SHARE_READ,
                          OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN);

    if (file == INVALID_HANDLE_VALUE) {
        Send550Error(Conn);
        return;
    }

    GetFileSizeEx(file, &fileSize);

    // Handle REST (restart)
    if (Conn->RestartOffset > 0) {
        if (Conn->RestartOffset >= (LONGLONG)fileSize.QuadPart) {
            CloseHandle(file);
            SendError(Conn, 554, "REST offset beyond end of file");
            Conn->RestartOffset = 0;
            return;
        }

        seekPos.QuadPart = Conn->RestartOffset;
        if (!SetFilePointerEx(file, seekPos, NULL, FILE_BEGIN)) {
            CloseHandle(file);
            Send550Error(Conn);
            Conn->RestartOffset = 0;
            return;
        }

        LogMessage("Resuming transfer at offset %lld", Conn->RestartOffset);
    }

    if (Conn->RestartOffset > 0) {
        SendReplyFmt(Conn, "150 Opening BINARY mode data connection for %s (%lld bytes, restarting at %lld)",
                     filename, fileSize.QuadPart, Conn->RestartOffset);
    } else {
        SendReplyFmt(Conn, "150 Opening BINARY mode data connection for %s (%lld bytes)",
                     filename, fileSize.QuadPart);
    }

    xfer_sock = OpenDataConnection(Conn, &data_ssl);
    if (xfer_sock == INVALID_SOCKET) {
        SendError(Conn, 425, "Cannot open data connection");
        CloseHandle(file);
        Conn->RestartOffset = 0;
        return;
    }

    // Transfer file
    BOOL success = TRUE;
    while (ReadFile(file, Conn->XferBuffer, sizeof(Conn->XferBuffer), &bytesRead, NULL)
           && bytesRead > 0) {
        int sent = SecureSend(Conn, xfer_sock, Conn->XferBuffer, (int)bytesRead, data_ssl);
        if (sent < 0) {
            LogMessage("Send failed during transfer");
            SendError(Conn, 426, "Connection closed; transfer aborted");
            success = FALSE;
            break;
        }
        totalBytes += bytesRead;
        Conn->BytesSent += bytesRead;
    }

    CloseDataConnection(xfer_sock, data_ssl);
    CloseHandle(file);
    Conn->RestartOffset = 0;

    if (success) {
        LogMessage("Sent %llu bytes", totalBytes);
        SendReply(Conn, "226 Transfer complete");
    }
}

//------------------------------------------------------------------------------------
// Handle the STOR command using VFS with REST support
//------------------------------------------------------------------------------------
static void Cmd_STOR(Inst_t *Conn, char *filename, BOOL append, BOOL unique)
{
    HANDLE file;
    SOCKET xfer_sock;
    int size;
    DWORD bytesWritten;
    SSL *data_ssl = NULL;
    ULONGLONG totalBytes = 0;
    char actualFilename[MAX_PATH * 3];
    LARGE_INTEGER seekPos;

    // Check permissions
    if (g_Config.getOnly) {
        Send553Error(Conn, "Server is read-only");
        return;
    }

    if (VFS_IsReadOnly(Conn->CurrentDir)) {
        Send553Error(Conn, "Directory is read-only");
        return;
    }

    strcpy(actualFilename, filename);

    // Handle STOU (store unique)
    if (unique) {
        char baseName[MAX_PATH];
        char ext[MAX_PATH];
        char *dot;
        int counter = 1;
        WIN32_FILE_ATTRIBUTE_DATA info;

        strcpy(baseName, filename[0] ? filename : "upload");
        ext[0] = '\0';

        dot = strrchr(baseName, '.');
        if (dot) {
            strcpy(ext, dot);
            *dot = '\0';
        }

        while (VFS_GetFileInfo(Conn->CurrentDir, actualFilename, &info)) {
            snprintf(actualFilename, sizeof(actualFilename), "%s.%d%s", 
                     baseName, counter++, ext);
            if (counter > 10000) {
                SendError(Conn, 452, "Cannot create unique filename");
                return;
            }
        }
    }

    DWORD creation;
    DWORD flags = FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN;

    if (append) {
        creation = OPEN_ALWAYS;
    } else if (Conn->RestartOffset > 0) {
        creation = OPEN_ALWAYS;  // For REST, we need the file to exist or be created
    } else {
        creation = CREATE_ALWAYS;
    }

    file = VFS_CreateFile(Conn->CurrentDir, actualFilename, GENERIC_WRITE, 0,
                          creation, flags);

    if (file == INVALID_HANDLE_VALUE) {
        Send550Error(Conn);
        Conn->RestartOffset = 0;
        return;
    }

    // Handle append or REST
    if (append) {
        SetFilePointer(file, 0, NULL, FILE_END);
    } else if (Conn->RestartOffset > 0) {
        seekPos.QuadPart = Conn->RestartOffset;
        if (!SetFilePointerEx(file, seekPos, NULL, FILE_BEGIN)) {
            CloseHandle(file);
            Send550Error(Conn);
            Conn->RestartOffset = 0;
            return;
        }
        // Truncate file at this position
        SetEndOfFile(file);
        LogMessage("Resuming upload at offset %lld", Conn->RestartOffset);
    }

    if (unique) {
        SendReplyFmt(Conn, "150 FILE: %s", actualFilename);
    } else if (Conn->RestartOffset > 0) {
        SendReplyFmt(Conn, "150 Opening BINARY mode data connection for %s (restarting at %lld)",
                     actualFilename, Conn->RestartOffset);
    } else {
        SendReplyFmt(Conn, "150 Opening BINARY mode data connection for %s", actualFilename);
    }

    xfer_sock = OpenDataConnection(Conn, &data_ssl);
    if (xfer_sock == INVALID_SOCKET) {
        SendError(Conn, 425, "Cannot open data connection");
        CloseHandle(file);
        Conn->RestartOffset = 0;
        return;
    }

    // Transfer file
    BOOL success = TRUE;
    for (;;) {
        size = SecureRecv(Conn, xfer_sock, Conn->XferBuffer,
                          sizeof(Conn->XferBuffer), data_ssl);
        if (size <= 0) break;

        if (!WriteFile(file, Conn->XferBuffer, size, &bytesWritten, NULL) ||
            bytesWritten != (DWORD)size) {
            Send550Error(Conn);
            success = FALSE;
            break;
        }
        totalBytes += bytesWritten;
        Conn->BytesReceived += bytesWritten;
    }

    CloseDataConnection(xfer_sock, data_ssl);
    CloseHandle(file);
    Conn->RestartOffset = 0;

    if (success) {
        LogMessage("Received %llu bytes", totalBytes);
        if (unique) {
            SendReplyFmt(Conn, "226 Transfer complete (unique filename: %s)", actualFilename);
        } else {
            SendReply(Conn, "226 Transfer complete");
        }
    }
}

//------------------------------------------------------------------------------------
// Handle MDTM command - get or set modification time
//------------------------------------------------------------------------------------
static void Cmd_MDTM(Inst_t *Conn, char *arg)
{
    WIN32_FILE_ATTRIBUTE_DATA fileInfo;
    char reply[64];
    SYSTEMTIME st;
    char *filename = arg;

    // Check if this is a set operation (MDTM YYYYMMDDhhmmss filename)
    if (strlen(arg) > 14 && arg[14] == ' ') {
        // Setting modification time - parse timestamp
        int year, month, day, hour, min, sec;
        if (sscanf(arg, "%4d%2d%2d%2d%2d%2d", &year, &month, &day, &hour, &min, &sec) == 6) {
            filename = arg + 15;

            if (g_Config.getOnly || VFS_IsReadOnly(Conn->CurrentDir)) {
                Send553Error(Conn, "Cannot modify file time");
                return;
            }

            // Set file modification time
            HANDLE file = VFS_CreateFile(Conn->CurrentDir, filename, 
                                         FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ,
                                         OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL);
            if (file == INVALID_HANDLE_VALUE) {
                Send550Error(Conn);
                return;
            }

            SYSTEMTIME setSt;
            FILETIME ft;
            memset(&setSt, 0, sizeof(setSt));
            setSt.wYear = (WORD)year;
            setSt.wMonth = (WORD)month;
            setSt.wDay = (WORD)day;
            setSt.wHour = (WORD)hour;
            setSt.wMinute = (WORD)min;
            setSt.wSecond = (WORD)sec;

            SystemTimeToFileTime(&setSt, &ft);
            BOOL ok = SetFileTime(file, NULL, NULL, &ft);
            CloseHandle(file);

            if (ok) {
                SendReply(Conn, "253 Date/time changed okay");
            } else {
                Send550Error(Conn);
            }
            return;
        }
    }

    // Get modification time
    if (!VFS_GetFileInfo(Conn->CurrentDir, filename, &fileInfo)) {
        Send550Error(Conn);
        return;
    }

    if (fileInfo.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
        SendError(Conn, 550, "Not a plain file");
        return;
    }

    FileTimeToSystemTime(&fileInfo.ftLastWriteTime, &st);
    snprintf(reply, sizeof(reply), "213 %04d%02d%02d%02d%02d%02d",
             st.wYear, st.wMonth, st.wDay,
             st.wHour, st.wMinute, st.wSecond);
    SendReply(Conn, reply);
}

//------------------------------------------------------------------------------------
// Handle SIZE command
//------------------------------------------------------------------------------------
static void Cmd_SIZE(Inst_t *Conn, char *filename)
{
    WIN32_FILE_ATTRIBUTE_DATA fileInfo;
    char reply[64];
    ULARGE_INTEGER size;

    if (!VFS_GetFileInfo(Conn->CurrentDir, filename, &fileInfo)) {
        Send550Error(Conn);
        return;
    }

    if (fileInfo.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
        SendError(Conn, 550, "Not a plain file");
        return;
    }

    size.LowPart = fileInfo.nFileSizeLow;
    size.HighPart = fileInfo.nFileSizeHigh;
    snprintf(reply, sizeof(reply), "213 %llu", size.QuadPart);
    SendReply(Conn, reply);
}

//------------------------------------------------------------------------------------
// Handle SITE commands
//------------------------------------------------------------------------------------
static void Cmd_SITE(Inst_t *Conn, char *arg)
{
    char cmd[32];
    char *params;
    int i;

    // Parse SITE command
    for (i = 0; i < 31 && arg[i] && arg[i] != ' '; i++) {
        cmd[i] = (char)toupper((unsigned char)arg[i]);
    }
    cmd[i] = '\0';

    params = arg + i;
    while (*params == ' ') params++;

    if (strcmp(cmd, "CHMOD") == 0) {
        // SITE CHMOD mode filename - not really implemented on Windows
        SendError(Conn, 502, "CHMOD not supported on Windows");
    } else if (strcmp(cmd, "HELP") == 0) {
        SendReply(Conn, "214-The following SITE commands are recognized:");
        SendReply(Conn, " CHMOD (not functional on Windows)");
        SendReply(Conn, "214 End of SITE help");
    } else {
        SendError(Conn, 504, "Unknown SITE command");
    }
}

//------------------------------------------------------------------------------------
// Allocate a port for passive mode
//------------------------------------------------------------------------------------
static int AllocatePassivePort(void)
{
    int port;

    EnterCriticalSection(&g_PortsLock);

    if (g_Config.passivePortStart > 0 && g_Config.passivePortEnd >= g_Config.passivePortStart) {
        for (port = g_Config.passivePortStart; port <= g_Config.passivePortEnd; port++) {
            int idx = port & 255;
            if (!PortsUsed[idx]) {
                PortsUsed[idx] = 1;
                LeaveCriticalSection(&g_PortsLock);
                return port;
            }
        }
    }

    // Let OS assign port
    LeaveCriticalSection(&g_PortsLock);
    return 0;
}

//------------------------------------------------------------------------------------
// Release a passive port
//------------------------------------------------------------------------------------
static void ReleasePassivePort(int port)
{
    if (port > 0) {
        EnterCriticalSection(&g_PortsLock);
        PortsUsed[port & 255] = 0;
        LeaveCriticalSection(&g_PortsLock);
    }
}

//------------------------------------------------------------------------------------
// Initialize connection state
//------------------------------------------------------------------------------------
static void InitConnection(Inst_t *Conn)
{
    strcpy(Conn->CurrentDir, "/");
    Conn->PassiveMode = FALSE;
    Conn->UseSSL = FALSE;
    Conn->UseUTF8 = g_Config.defaultUtf8;
    Conn->DataProtection = FALSE;
    Conn->RenameFrom[0] = '\0';
    Conn->Type = TRANSFER_TYPE_BINARY;
    Conn->Structure = STRUCT_FILE;
    Conn->Mode = MODE_STREAM;
    Conn->RestartOffset = 0;
    Conn->Authenticated = FALSE;
    Conn->Username[0] = '\0';
    Conn->BytesSent = 0;
    Conn->BytesReceived = 0;
    Conn->ConnectTime = GetTickCount();
}

//------------------------------------------------------------------------------------
// Main command processing loop
//------------------------------------------------------------------------------------
static void ProcessCommands(Inst_t *Conn)
{
    char buf[MAX_PATH * 3];
    char repbuf[MAX_PATH * 3 + 256];
    const CommandDef *cmdDef;
    int a;

    InitConnection(Conn);

    // Allocate passive socket
    Conn->XferPort = AllocatePassivePort();
    Conn->PassiveSocket = CreateTcpipSocket(&Conn->XferPort);
    if (Conn->PassiveSocket == INVALID_SOCKET) {
        LogMessage("Failed to create passive socket");
        goto EndConnection;
    }

    if (listen(Conn->PassiveSocket, 1) == -1) {
        LogMessage("Passive socket listen failed");
        goto EndConnection;
    }

    // Handle implicit TLS
    if (g_Config.useTLS && g_Config.implicitTLS) {
        Conn->ssl = SSL_CreateConnection(Conn->CommandSocket);
        if (!Conn->ssl) {
            LogMessage("Implicit TLS handshake failed");
            goto EndConnection;
        }
        Conn->UseSSL = TRUE;
        Conn->DataProtection = TRUE;
        LogMessage("Implicit TLS established");
    }

    // Send welcome message
    if (g_Config.useTLS && !g_Config.implicitTLS) {
        SendReply(Conn, "220 ftpsmin " FTPSMIN_VER " ready (TLS available)");
    } else {
        SendReply(Conn, "220 ftpsmin " FTPSMIN_VER " ready");
    }

    // Command loop
    for (;;) {
        CmdTypes FtpCommand;

        // Check for shutdown before getting command
        if (g_ServiceStop) {
            SendReply(Conn, "421 Server shutting down");
            goto EndConnection;
        }

        FtpCommand = GetCommand(Conn, buf, &cmdDef);

        // Check for connection closed or shutdown
        if (FtpCommand == (CmdTypes)-1) {
            goto EndConnection;
        }

        // Check authentication requirement
        if (cmdDef && cmdDef->requiresAuth && !Conn->Authenticated && g_Config.requireAuth) {
            SendReply(Conn, "530 Please login with USER and PASS");
            continue;
        }

        // Check for required argument
        if (cmdDef && cmdDef->requiresArg && buf[0] == '\0') {
            SendError(Conn, 501, "Syntax error: argument required");
            continue;
        }

        // Clear REST offset if command is not RETR or STOR
        if (FtpCommand != RETR && FtpCommand != STOR && FtpCommand != APPE && 
            FtpCommand != REST && FtpCommand != STOU) {
            if (Conn->RestartOffset != 0) {
                LogMessage("REST offset cleared (was %lld)", Conn->RestartOffset);
                Conn->RestartOffset = 0;
            }
        }

        switch (FtpCommand) {
            //------------------------------------------------------------------
            // Security commands
            //------------------------------------------------------------------
            case AUTH:
                if (_stricmp(buf, "TLS") == 0 || _stricmp(buf, "SSL") == 0) {
                    if (!g_Config.useTLS) {
                        SendReply(Conn, "502 TLS not configured");
                        break;
                    }
                    if (Conn->ssl) {
                        SendReply(Conn, "503 TLS already active");
                        break;
                    }
                    SendReply(Conn, "234 AUTH TLS successful");
                    Conn->ssl = SSL_CreateConnection(Conn->CommandSocket);
                    if (!Conn->ssl) {
                        LogMessage("TLS handshake failed");
                        goto EndConnection;
                    }
                    Conn->UseSSL = TRUE;

                    LogMessage("Explicit TLS established");
                } else {
                    SendError(Conn, 504, "AUTH type not supported");
                }
                break;

            case PBSZ:
                if (!Conn->UseSSL) {
                    SendReply(Conn, "503 TLS not active, issue AUTH first");
                } else {
                    // We only support PBSZ 0
                    SendReply(Conn, "200 PBSZ=0");
                }
                break;

            case PROT:
                if (!Conn->UseSSL) {
                    SendReply(Conn, "503 TLS not active, issue AUTH first");
                } else if (buf[0] == 'P' || buf[0] == 'p') {
                    Conn->DataProtection = TRUE;
                    SendReply(Conn, "200 Protection level set to Private");
                } else if (buf[0] == 'C' || buf[0] == 'c') {
                    Conn->DataProtection = FALSE;
                    SendReply(Conn, "200 Protection level set to Clear");
                } else if (buf[0] == 'S' || buf[0] == 's') {
                    SendError(Conn, 536, "PROT S not supported");
                } else if (buf[0] == 'E' || buf[0] == 'e') {
                    SendError(Conn, 536, "PROT E not supported");
                } else {
                    SendError(Conn, 504, "Unknown protection level");
                }
                break;

            case CCC:
                // Clear Command Channel - downgrade to unencrypted
                if (!Conn->UseSSL) {
                    SendReply(Conn, "533 TLS not active");
                } else {
                    SendReply(Conn, "200 CCC successful, command channel is now unencrypted");
                    SSL_FreeConnection(Conn->ssl);
                    Conn->ssl = NULL;
                    Conn->UseSSL = FALSE;
                }
                break;

            //------------------------------------------------------------------
            // Feature and option commands
            //------------------------------------------------------------------
            case FEAT:
                {
                    char featReply[2048];
                    strcpy(featReply, "211-Features:\r\n");
                    strcat(featReply, " SIZE\r\n");
                    strcat(featReply, " MDTM\r\n");
                    strcat(featReply, " MLST type*;size*;modify*;perm*;\r\n");
                    strcat(featReply, " MLSD\r\n");
                    strcat(featReply, " REST STREAM\r\n");
                    strcat(featReply, " PASV\r\n");
                    strcat(featReply, " EPSV\r\n");
                    strcat(featReply, " EPRT\r\n");
                    strcat(featReply, " UTF8\r\n");
                    strcat(featReply, " CLNT\r\n");
                    strcat(featReply, " MFMT\r\n");
                    if (g_Config.useTLS) {
                        strcat(featReply, " AUTH TLS\r\n");
                        strcat(featReply, " AUTH SSL\r\n");
                        strcat(featReply, " PBSZ\r\n");
                        strcat(featReply, " PROT\r\n");
                        strcat(featReply, " CCC\r\n");
                    }
                    strcat(featReply, "211 End\r\n");
                    SendMultiLineReply(Conn, featReply);
                }
                break;

            case OPTS:
                if (_strnicmp(buf, "UTF8", 4) == 0) {
                    char *arg = buf + 4;
                    while (*arg == ' ') arg++;
                    if (*arg == '\0' || _stricmp(arg, "ON") == 0) {
                        Conn->UseUTF8 = TRUE;
                        SendReply(Conn, "200 UTF-8 mode enabled");
                    } else if (_stricmp(arg, "OFF") == 0) {
                        Conn->UseUTF8 = FALSE;
                        SendReply(Conn, "200 UTF-8 mode disabled");
                    } else {
                        SendError(Conn, 501, "Invalid UTF8 option");
                    }
                } else if (_strnicmp(buf, "MLST", 4) == 0) {
                    // Accept MLST options but we always send all facts
                    SendReply(Conn, "200 MLST options accepted");
                } else {
                    SendError(Conn, 501, "Option not recognized");
                }
                break;

            case LANG:
                SendReply(Conn, "200 Language set to EN");
                break;

            case CLNT:
                LogMessage("Client software: %s", buf);
                SendReply(Conn, "200 Noted");
                break;

            case HELP:
                if (buf[0] == '\0') {
                    SendReply(Conn, "214-The following commands are recognized:");
                    snprintf(repbuf, sizeof(repbuf), " ");
                    for (a = 0; a < (int)NUM_COMMANDS; a++) {
                        strcat(repbuf, CommandTable[a].command);
                        strcat(repbuf, " ");
                        if ((a + 1) % 8 == 0) {
                            SendReply(Conn, repbuf);
                            snprintf(repbuf, sizeof(repbuf), " ");
                        }
                    }
                    if (strlen(repbuf) > 1) {
                        SendReply(Conn, repbuf);
                    }
                    SendReply(Conn, "214 HELP command successful");
                } else {
                    const CommandDef *helpCmd = FindCommand(buf);
                    if (helpCmd) {
                        SendReplyFmt(Conn, "214 %s: %s", helpCmd->command, helpCmd->help);
                    } else {
                        SendError(Conn, 502, "Unknown command");
                    }
                }
                break;

            //------------------------------------------------------------------
            // Authentication commands
            //------------------------------------------------------------------
            case USER:
                strncpy(Conn->Username, buf, sizeof(Conn->Username) - 1);
                Conn->Username[sizeof(Conn->Username) - 1] = '\0';
                Conn->Authenticated = FALSE;
                if (g_Config.requireAuth) {
                    SendReply(Conn, "331 Password required");
                } else {
                    Conn->Authenticated = TRUE;
                    LogMessage("User '%s' logged in (no auth required)", Conn->Username);
                    SendReply(Conn, "230 User logged in");
                }
                break;

            case PASS:
                if (Conn->Username[0] == '\0') {
                    SendReply(Conn, "503 Login with USER first");
                } else if (g_Config.requireAuth) {
                    if (strcmp(Conn->Username, g_Config.username) == 0 &&
                        strcmp(buf, g_Config.password) == 0) {
                        Conn->Authenticated = TRUE;
                        LogMessage("User '%s' authenticated successfully", Conn->Username);
                        SendReply(Conn, "230 User logged in");
                    } else {
                        LogMessage("Authentication failed for user '%s'", Conn->Username);
                        Conn->Username[0] = '\0';
                        SendReply(Conn, "530 Login incorrect");
                    }
                } else {
                    Conn->Authenticated = TRUE;
                    SendReply(Conn, "230 User logged in");
                }
                break;

            case ACCT:
                SendReply(Conn, "202 ACCT not implemented");
                break;

            case REIN:
                // Reinitialize - logout but keep connection
                InitConnection(Conn);
                SendReply(Conn, "220 Service ready for new user");
                break;

            //------------------------------------------------------------------
            // Transfer parameter commands
            //------------------------------------------------------------------
            case TYPE:
                if (buf[0] == 'A' || buf[0] == 'a') {
                    Conn->Type = TRANSFER_TYPE_ASCII;
                    SendReply(Conn, "200 Type set to A");
                } else if (buf[0] == 'I' || buf[0] == 'i') {
                    Conn->Type = TRANSFER_TYPE_BINARY;
                    SendReply(Conn, "200 Type set to I");
                } else if (buf[0] == 'L' || buf[0] == 'l') {
                    // TYPE L 8 is same as TYPE I
                    Conn->Type = TRANSFER_TYPE_BINARY;
                    SendReply(Conn, "200 Type set to L");
                } else {
                    SendError(Conn, 504, "Type not supported");
                }
                break;

            case STRU:
                if (buf[0] == 'F' || buf[0] == 'f') {
                    Conn->Structure = STRUCT_FILE;
                    SendReply(Conn, "200 Structure set to F");
                } else if (buf[0] == 'R' || buf[0] == 'r') {
                    SendError(Conn, 504, "STRU R not supported");
                } else if (buf[0] == 'P' || buf[0] == 'p') {
                    SendError(Conn, 504, "STRU P not supported");
                } else {
                    SendError(Conn, 504, "Unknown structure");
                }
                break;

            case MODE:
                if (buf[0] == 'S' || buf[0] == 's') {
                    Conn->Mode = MODE_STREAM;
                    SendReply(Conn, "200 Mode set to S");
                } else if (buf[0] == 'B' || buf[0] == 'b') {
                    SendError(Conn, 504, "MODE B not supported");
                } else if (buf[0] == 'C' || buf[0] == 'c') {
                    SendError(Conn, 504, "MODE C not supported");
                } else {
                    SendError(Conn, 504, "Unknown mode");
                }
                break;

            case REST:
                {
                    LONGLONG offset = 0;
                    if (sscanf(buf, "%lld", &offset) != 1 || offset < 0) {
                        SendError(Conn, 501, "Invalid REST argument");
                    } else {
                        Conn->RestartOffset = offset;
                        SendReplyFmt(Conn, "350 Restarting at %lld. Send STOR or RETR", offset);
                    }
                }
                break;

            case ALLO:
                // ALLO is obsolete, just acknowledge
                SendReply(Conn, "202 ALLO command ignored");
                break;

            //------------------------------------------------------------------
            // Data connection commands
            //------------------------------------------------------------------
            case PASV:
                {
                    if (Conn->PassiveSocket != INVALID_SOCKET) {
                        closesocket(Conn->PassiveSocket);
                    }
                    ReleasePassivePort(Conn->XferPort);

                    Conn->XferPort = AllocatePassivePort();
                    Conn->PassiveSocket = CreateTcpipSocket(&Conn->XferPort);

                    if (Conn->PassiveSocket == INVALID_SOCKET) {
                        SendError(Conn, 425, "Cannot open passive connection");
                        break;
                    }

                    if (listen(Conn->PassiveSocket, 1) == -1) {
                        SendError(Conn, 425, "Cannot listen on passive socket");
                        break;
                    }

                    snprintf(repbuf, sizeof(repbuf), "227 Entering Passive Mode (%s,%d,%d)",
                             OurAddrStr, Conn->XferPort >> 8, Conn->XferPort & 0xff);

                    for (a = 0; repbuf[a]; a++) {
                        if (repbuf[a] == '.') repbuf[a] = ',';
                    }

                    SendReply(Conn, repbuf);
                    Conn->PassiveMode = TRUE;
                }
                break;

            case EPSV:
                {
                    if (Conn->PassiveSocket != INVALID_SOCKET) {
                        closesocket(Conn->PassiveSocket);
                    }
                    ReleasePassivePort(Conn->XferPort);

                    Conn->XferPort = AllocatePassivePort();
                    Conn->PassiveSocket = CreateTcpipSocket(&Conn->XferPort);

                    if (Conn->PassiveSocket == INVALID_SOCKET) {
                        SendError(Conn, 425, "Cannot open passive connection");
                        break;
                    }

                    if (listen(Conn->PassiveSocket, 1) == -1) {
                        SendError(Conn, 425, "Cannot listen on passive socket");
                        break;
                    }

                    SendReplyFmt(Conn, "229 Entering Extended Passive Mode (|||%d|)", Conn->XferPort);
                    Conn->PassiveMode = TRUE;
                }
                break;

            case PORT:
                {
                    int h1, h2, h3, h4, p1, p2;
                    if (sscanf(buf, "%d,%d,%d,%d,%d,%d", &h1, &h2, &h3, &h4, &p1, &p2) != 6) {
                        SendError(Conn, 501, "Invalid PORT command");
                        break;
                    }

                    // Validate values
                    if (h1 < 0 || h1 > 255 || h2 < 0 || h2 > 255 ||
                        h3 < 0 || h3 > 255 || h4 < 0 || h4 > 255 ||
                        p1 < 0 || p1 > 255 || p2 < 0 || p2 > 255) {
                        SendError(Conn, 501, "Invalid PORT values");
                        break;
                    }

                    unsigned char *addr = (unsigned char *)&Conn->xfer_addr.sin_addr;
                    unsigned char *port = (unsigned char *)&Conn->xfer_addr.sin_port;
                    addr[0] = (unsigned char)h1;
                    addr[1] = (unsigned char)h2;
                    addr[2] = (unsigned char)h3;
                    addr[3] = (unsigned char)h4;
                    port[0] = (unsigned char)p1;
                    port[1] = (unsigned char)p2;
                    Conn->xfer_addr.sin_family = AF_INET;

                    Conn->PassiveMode = FALSE;
                    SendReply(Conn, "200 PORT command successful");
                }
                break;

            case EPRT:
                {
                    // EPRT |protocol|address|port|
                    char delim = buf[0];
                    int protocol;
                    char address[64];
                    int eprt_port;
                    char delim2, delim3, delim4;

                    if (sscanf(buf, "%c%d%c%63[^|]%c%d%c", 
                               &delim, &protocol, &delim2, address, &delim3, &eprt_port, &delim4) != 7) {
                        SendError(Conn, 501, "Invalid EPRT command");
                        break;
                    }

                    if (protocol != 1) {  // Only IPv4 supported
                        SendError(Conn, 522, "Network protocol not supported, use (1)");
                        break;
                    }

                    Conn->xfer_addr.sin_family = AF_INET;
                    Conn->xfer_addr.sin_addr.s_addr = inet_addr(address);
                    Conn->xfer_addr.sin_port = htons((unsigned short)eprt_port);

                    Conn->PassiveMode = FALSE;
                    SendReply(Conn, "200 EPRT command successful");
                }
                break;

            //------------------------------------------------------------------
            // Directory commands
            //------------------------------------------------------------------
            case PWD:
            case XPWD:
                SendReplyFmt(Conn, "257 \"%s\" is current directory", Conn->CurrentDir);
                break;

            case CWD:
                if (!VFS_SetDirectory(Conn->CurrentDir, buf, Conn->CurrentDir,
                                      sizeof(Conn->CurrentDir))) {
                    SendError(Conn, 550, "Directory not found or access denied");
                } else {
                    SendReply(Conn, "250 CWD command successful");
                }
                break;

            case CDUP:
                if (!VFS_SetDirectory(Conn->CurrentDir, "..", Conn->CurrentDir,
                                      sizeof(Conn->CurrentDir))) {
                    SendError(Conn, 550, "Cannot go up from root");
                } else {
                    SendReply(Conn, "250 CDUP command successful");
                }
                break;

            case SMNT:
                SendError(Conn, 502, "SMNT not implemented");
                break;

            case LIST:
                Cmd_NLST(Conn, buf, TRUE, FALSE);
                break;

            case NLST:
                Cmd_NLST(Conn, buf, FALSE, FALSE);
                break;

            case MLSD:
                Cmd_MLSD(Conn, buf);
                break;

            case MLST:
                Cmd_MLST(Conn, buf);
                break;

            //------------------------------------------------------------------
            // File transfer commands
            //------------------------------------------------------------------
            case RETR:
                Cmd_RETR(Conn, buf);
                break;

            case STOR:
                Cmd_STOR(Conn, buf, FALSE, FALSE);
                break;

            case APPE:
                Cmd_STOR(Conn, buf, TRUE, FALSE);
                break;

            case STOU:
                Cmd_STOR(Conn, buf[0] ? buf : "upload", FALSE, TRUE);
                break;

            //------------------------------------------------------------------
            // File management commands
            //------------------------------------------------------------------
            case DELE:
                if (g_Config.getOnly) {
                    Send553Error(Conn, "Server is read-only");
                    break;
                }
                if (VFS_IsReadOnly(Conn->CurrentDir)) {
                    Send553Error(Conn, "Directory is read-only");
                    break;
                }
                if (!VFS_DeleteFile(Conn->CurrentDir, buf)) {
                    Send550Error(Conn);
                } else {
                    SendReply(Conn, "250 DELE command successful");
                }
                break;

            case MKD:
            case XMKD:
                if (g_Config.getOnly) {
                    Send553Error(Conn, "Server is read-only");
                    break;
                }
                if (VFS_IsReadOnly(Conn->CurrentDir)) {
                    Send553Error(Conn, "Directory is read-only");
                    break;
                }
                if (!VFS_CreateDirectory(Conn->CurrentDir, buf)) {
                    Send550Error(Conn);
                } else {
                    // Include the created directory name in quotes
                    if (buf[0] == '/') {
                        SendReplyFmt(Conn, "257 \"%s\" directory created", buf);
                    } else {
                        SendReplyFmt(Conn, "257 \"%s/%s\" directory created", 
                                     strcmp(Conn->CurrentDir, "/") == 0 ? "" : Conn->CurrentDir, 
                                     buf);
                    }
                }
                break;

            case RMD:
            case XRMD:
                if (g_Config.getOnly) {
                    Send553Error(Conn, "Server is read-only");
                    break;
                }
                if (VFS_IsReadOnly(Conn->CurrentDir)) {
                    Send553Error(Conn, "Directory is read-only");
                    break;
                }
                if (!VFS_RemoveDirectory(Conn->CurrentDir, buf)) {
                    Send550Error(Conn);
                } else {
                    SendReply(Conn, "250 RMD command successful");
                }
                break;

            case RNFR:
                {
                    WIN32_FILE_ATTRIBUTE_DATA info;
                    if (!VFS_GetFileInfo(Conn->CurrentDir, buf, &info)) {
                        Send550Error(Conn);
                    } else {
                        strncpy(Conn->RenameFrom, buf, sizeof(Conn->RenameFrom) - 1);
                        Conn->RenameFrom[sizeof(Conn->RenameFrom) - 1] = '\0';
                        SendReply(Conn, "350 File exists, ready for destination name");
                    }
                }
                break;

            case RNTO:
                if (Conn->RenameFrom[0] == '\0') {
                    SendReply(Conn, "503 RNFR required first");
                    break;
                }
                if (g_Config.getOnly) {
                    Conn->RenameFrom[0] = '\0';
                    Send553Error(Conn, "Server is read-only");
                    break;
                }
                if (VFS_IsReadOnly(Conn->CurrentDir)) {
                    Conn->RenameFrom[0] = '\0';
                    Send553Error(Conn, "Directory is read-only");
                    break;
                }
                if (!VFS_MoveFile(Conn->CurrentDir, Conn->RenameFrom, buf)) {
                    Send550Error(Conn);
                } else {
                    SendReply(Conn, "250 RNTO command successful");
                }
                Conn->RenameFrom[0] = '\0';
                break;

            case SITE:
                Cmd_SITE(Conn, buf);
                break;

            //------------------------------------------------------------------
            // Information commands
            //------------------------------------------------------------------
            case xSIZE:
                Cmd_SIZE(Conn, buf);
                break;

            case MDTM:
                Cmd_MDTM(Conn, buf);
                break;

            case SYST:
                SendReply(Conn, "215 UNIX Type: L8");
                break;

            case STAT:
                if (buf[0] == '\0') {
                    DWORD uptime = (GetTickCount() - Conn->ConnectTime) / 1000;
                                        snprintf(repbuf, sizeof(repbuf),
                             "211-ftpsmin " FTPSMIN_VER " Server Status\r\n"
                             " Connected to %s\r\n"
                             " Logged in as %s\r\n"
                             " Session time: %lu seconds\r\n"
                             " TYPE: %s, STRU: File, MODE: Stream\r\n"
                             " Data connection: %s\r\n"
                             " TLS: %s, Data protection: %s\r\n"
                             " UTF-8: %s\r\n"
                             " Bytes sent: %llu, received: %llu\r\n"
                             "211 End of status\r\n",
                             OurAddrStr,
                             Conn->Authenticated ? Conn->Username : "(not logged in)",
                             uptime,
                             Conn->Type == TRANSFER_TYPE_ASCII ? "ASCII" : "Binary",
                             Conn->PassiveMode ? "Passive" : "Active",
                             Conn->UseSSL ? "Active" : "Inactive",
                             Conn->DataProtection ? "Private" : "Clear",
                             Conn->UseUTF8 ? "Enabled" : "Disabled",
                             Conn->BytesSent, Conn->BytesReceived);
                    SendMultiLineReply(Conn, repbuf);
                } else {
                    // STAT with path - directory listing over control connection
                    Cmd_NLST(Conn, buf, TRUE, TRUE);
                }
                break;

            case NOOP:
                SendReply(Conn, "200 NOOP ok");
                break;

            case ABOR:
                // In a real implementation, this would abort an in-progress transfer
                // Since we're single-threaded per connection, just acknowledge
                SendReply(Conn, "226 ABOR command successful");
                break;

            //------------------------------------------------------------------
            // Session commands
            //------------------------------------------------------------------
            case QUIT:
                {
                    DWORD sessionTime = (GetTickCount() - Conn->ConnectTime) / 1000;
                    LogMessage("Session ended. Duration: %lu seconds, Sent: %llu bytes, Received: %llu bytes",
                               sessionTime, Conn->BytesSent, Conn->BytesReceived);
                    SendReply(Conn, "221 Goodbye");
                    goto EndConnection;
                }

            case UNKNOWN_COMMAND:
                SendError(Conn, 500, "Command not recognized");
                break;

            default:
                SendError(Conn, 502, "Command not implemented");
                break;
        }
    }

EndConnection:
    LogMessage("Connection closed");

    if (Conn->ssl) {
        SSL_FreeConnection(Conn->ssl);
        Conn->ssl = NULL;
    }

    if (Conn->PassiveSocket != INVALID_SOCKET) {
        closesocket(Conn->PassiveSocket);
    }

    if (Conn->CommandSocket != INVALID_SOCKET) {
        closesocket(Conn->CommandSocket);
    }
    ReleasePassivePort(Conn->XferPort);
    free(Conn);
}

//------------------------------------------------------------------------------------
// Connection handler thread
//------------------------------------------------------------------------------------
static unsigned __stdcall ConnectionThread(void *param)
{
    Inst_t *Conn = (Inst_t *)param;

    ProcessCommands(Conn);

    _endthreadex(0);
    return 0;
}

//------------------------------------------------------------------------------------
// Signal handler for console mode
//------------------------------------------------------------------------------------
static BOOL WINAPI ConsoleHandler(DWORD signal)
{
    switch (signal) {
    case CTRL_C_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_CLOSE_EVENT:
    case CTRL_SHUTDOWN_EVENT:
        LogMessage("Shutdown signal received");
        g_ServiceStop = TRUE;
        return TRUE;
    }
    return FALSE;
}

//------------------------------------------------------------------------------------
// Main server loop
//------------------------------------------------------------------------------------
void ServerMain(void)
{
    SOCKET sock;
    int ControlPort;
    char hostname[256];
    struct hostent *hostinfo;
    int connectionCount = 0;

    ControlPort = g_Config.port;

    // Initialize critical section for port allocation
    InitializeCriticalSection(&g_PortsLock);
    memset(PortsUsed, 0, sizeof(PortsUsed));

    // Set console handler for clean shutdown
    if (!g_RunAsService) {
        SetConsoleCtrlHandler(ConsoleHandler, TRUE);
    }

    // Initialize SSL if needed
    if (g_Config.useTLS) {
        if (!SSL_Initialize(g_Config.certFile, g_Config.keyFile)) {
            LogMessage("Failed to initialize SSL - check certificate files");
            LogMessage("  Certificate: %s", g_Config.certFile);
            LogMessage("  Private key: %s", g_Config.keyFile);
            goto Cleanup;
        }
        LogMessage("SSL/TLS initialized successfully");
        if (g_Config.implicitTLS) {
            LogMessage("Implicit TLS mode enabled (FTPS)");
        } else {
            LogMessage("Explicit TLS mode (AUTH TLS) available");
        }
    }

    // Initialize VFS
    if (!VFS_Initialize(&g_Config)) {
        LogMessage("Failed to initialize virtual file system");
        goto Cleanup;
    }

    // Log virtual directories
    if (g_Config.numVirtualDirs > 0) {
        int i;
        LogMessage("Virtual directories:");
        for (i = 0; i < g_Config.numVirtualDirs; i++) {
            LogMessage("  %s -> %s%s%s",
                       g_Config.virtualDirs[i].virtualPath,
                       g_Config.virtualDirs[i].physicalPath,
                       g_Config.virtualDirs[i].readOnly ? " [read-only]" : "",
                       g_Config.virtualDirs[i].hidden ? " [hidden]" : "");
        }
    }

    // Get our IP address
    if (gethostname(hostname, sizeof(hostname)) == 0) {
        hostinfo = gethostbyname(hostname);
        if (hostinfo && hostinfo->h_addr_list[0]) {
            memcpy(&OurAddr, hostinfo->h_addr_list[0], sizeof(struct in_addr));
        }
    }

    strcpy(OurAddrStr, inet_ntoa(OurAddr));
    if (g_Config.hostAddress[0] != '\0') {
        strncpy(OurAddrStr, g_Config.hostAddress, sizeof(OurAddrStr) - 1);
        OurAddrStr[sizeof(OurAddrStr) - 1] = '\0';
        LogMessage("Using configured host address: %s", OurAddrStr);
    }

    // Create listening socket
    sock = CreateTcpipSocket(&ControlPort);
    if (sock == INVALID_SOCKET) {
        // Try alternate ports if default fails
        int altPorts[] = {2121, 8021, 9021, 0};
        int i;
        for (i = 0; altPorts[i] != 0; i++) {
            ControlPort = altPorts[i];
            sock = CreateTcpipSocket(&ControlPort);
            if (sock != INVALID_SOCKET) break;
        }
        if (sock == INVALID_SOCKET) {
            LogMessage("Failed to create listening socket on any port");
            goto Cleanup;
        }
    }

    if (listen(sock, SOMAXCONN) == -1) {
        LogMessage("Listen failed, error %d", WSAGetLastError());
        closesocket(sock);
        goto Cleanup;
    }

    // Print startup banner
    LogMessage("========================================");
    LogMessage("ftpsmin " FTPSMIN_VER " started");
    LogMessage("========================================");
    LogMessage("Listening on %s://%s:%d",
               g_Config.useTLS && g_Config.implicitTLS ? "ftps" : "ftp",
               OurAddrStr, ControlPort);

    if (g_Config.passivePortStart > 0 && g_Config.passivePortEnd > 0) {
        LogMessage("Passive port range: %d-%d", 
                   g_Config.passivePortStart, g_Config.passivePortEnd);
    }

    if (g_Config.requireAuth) {
        LogMessage("Authentication required (user: %s)", g_Config.username);
    } else {
        LogMessage("Anonymous access enabled");
    }

    if (g_Config.getOnly) {
        LogMessage("Read-only mode enabled");
    }

    if (g_Config.defaultUtf8) {
        LogMessage("UTF-8 enabled by default");
    }

    LogMessage("Ready to accept connections");
    LogMessage("----------------------------------------");

    // Main accept loop
    while (!g_ServiceStop) {
        SOCKET CommandSocket;
        Inst_t *Conn;
        fd_set readfds;
        struct timeval timeout;
        struct sockaddr_in clientAddr;
        int clientAddrLen = sizeof(clientAddr);

        // Use select with timeout for clean shutdown
        FD_ZERO(&readfds);
        FD_SET(sock, &readfds);
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;

        if (select(0, &readfds, NULL, NULL, &timeout) <= 0) {
            continue;
        }

        CommandSocket = accept(sock, (struct sockaddr *)&clientAddr, &clientAddrLen);
        if (CommandSocket == INVALID_SOCKET) {
            if (!g_ServiceStop) {
                LogMessage("Accept failed, error %d", WSAGetLastError());
            }
            continue;
        }

        connectionCount++;
        LogMessage("Connection #%d from %s:%d",
                   connectionCount,
                   inet_ntoa(clientAddr.sin_addr),
                   ntohs(clientAddr.sin_port));

        // Set socket options
        {
            int keepAlive = 1;
            int noDelay = 1;
            struct linger ling = {1, 10};  // Linger for 10 seconds on close

            setsockopt(CommandSocket, SOL_SOCKET, SO_KEEPALIVE, (char*)&keepAlive, sizeof(keepAlive));
            setsockopt(CommandSocket, IPPROTO_TCP, TCP_NODELAY, (char*)&noDelay, sizeof(noDelay));
            setsockopt(CommandSocket, SOL_SOCKET, SO_LINGER, (char*)&ling, sizeof(ling));
        }

        // Allocate connection structure
        Conn = (Inst_t *)calloc(1, sizeof(Inst_t));
        if (!Conn) {
            LogMessage("Out of memory allocating connection");
            closesocket(CommandSocket);
            continue;
        }

        Conn->CommandSocket = CommandSocket;
        Conn->PassiveSocket = INVALID_SOCKET;
        Conn->client_addr = clientAddr;
        Conn->xfer_addr = clientAddr;  // Default data address is client address

        // Start connection thread
        {
            HANDLE hThread = (HANDLE)_beginthreadex(NULL, 0, ConnectionThread, Conn, 0, NULL);
            if (hThread) {
                CloseHandle(hThread);  // We don't need to track it
            } else {
                LogMessage("Failed to create thread (error %d), handling in main thread", GetLastError());
                ProcessCommands(Conn);
            }
        }
    }

    // Cleanup
    LogMessage("Shutting down...");

    Sleep(1000);

    closesocket(sock);

Cleanup:
    if (g_Config.useTLS) {
        SSL_Cleanup();
    }

    VFS_Cleanup();
    DeleteCriticalSection(&g_PortsLock);

    LogMessage("Server stopped");
}

//------------------------------------------------------------------------------------
// Print usage information
//------------------------------------------------------------------------------------
static void PrintUsage(void)
{
    printf("\nftpsmin " FTPSMIN_VER " - Minimal Secure FTP Server\n");
    printf("========================================\n\n");
    printf("Usage: ftpsmin [options]\n\n");
    printf("Options:\n");
    printf("  -c <file>     Use specified JSON config file (default: ftpsmin.json)\n");
    printf("  -install      Install as Windows service\n");
    printf("  -uninstall    Uninstall Windows service\n");
    printf("  -start        Start the Windows service\n");
    printf("  -stop         Stop the Windows service\n");
    printf("  -status       Check Windows service status\n");
    printf("  -h, -help     Show this help message\n");
    printf("\n");
    printf("Quick start:\n");
    printf("  1. Create ftpsmin.json configuration file\n");
    printf("  2. Run: ftpsmin.exe\n");
    printf("  3. Connect with any FTP client\n");
    printf("\n");
    printf("Example configuration (ftpsmin.json):\n");
    printf("{\n");
    printf("    \"port\": 21,\n");
    printf("    \"virtualDirs\": [\n");
    printf("        {\n");
    printf("            \"virtual\": \"/files\",\n");
    printf("            \"physical\": \"C:\\\\FTPRoot\",\n");
    printf("            \"readOnly\": false\n");
    printf("        },\n");
    printf("        {\n");
    printf("            \"virtual\": \"/backup\",\n");
    printf("            \"physical\": \"D:\\\\Backup\",\n");
    printf("            \"readOnly\": true\n");
    printf("        }\n");
    printf("    ],\n");
    printf("    \"useTLS\": true,\n");
    printf("    \"certFile\": \"server.crt\",\n");
    printf("    \"keyFile\": \"server.key\",\n");
    printf("    \"requireAuth\": true,\n");
    printf("    \"username\": \"ftpuser\",\n");
    printf("    \"password\": \"secretpassword\",\n");
    printf("    \"passivePortStart\": 50000,\n");
    printf("    \"passivePortEnd\": 50100,\n");
    printf("    \"defaultUtf8\": true\n");
    printf("}\n");
    printf("\n");
    printf("To generate SSL certificate:\n");
    printf("  openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes\n");
    printf("\n");
    printf("Features:\n");
    printf("  - FTPS (FTP over TLS) - explicit and implicit modes\n");
    printf("  - Multiple virtual directories with per-directory permissions\n");
    printf("  - UTF-8 filename support\n");
    printf("  - Resume transfers (REST command)\n");
    printf("  - Windows Service support\n");
    printf("  - MLSD/MLST for machine-readable listings\n");
    printf("\n");
}

//------------------------------------------------------------------------------------
// Print version information
//------------------------------------------------------------------------------------
static void PrintVersion(void)
{
    printf("ftpsmin " FTPSMIN_VER "\n");
    printf("Built: " __DATE__ " " __TIME__ "\n");
    printf("Features: FTPS");
#ifdef _WIN64
    printf(", 64-bit");
#else
    printf(", 32-bit");
#endif
    printf(", VFS, UTF-8, REST\n");
}

//------------------------------------------------------------------------------------
// Check Windows service status
//------------------------------------------------------------------------------------
static int ServiceStatus(void)
{
    SC_HANDLE schSCManager;
    SC_HANDLE schService;
    SERVICE_STATUS_PROCESS status;
    DWORD bytesNeeded;
    const char *stateStr;

    schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (!schSCManager) {
        printf("Cannot connect to Service Control Manager (error %d)\n", GetLastError());
        printf("Run as Administrator to check service status.\n");
        return 1;
    }

    schService = OpenService(schSCManager,
                             g_Config.serviceName[0] ? g_Config.serviceName : "ftpsmin",
                             SERVICE_QUERY_STATUS);

    if (!schService) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_DOES_NOT_EXIST) {
            printf("Service is not installed.\n");
        } else {
            printf("Cannot open service (error %d)\n", err);
        }
        CloseServiceHandle(schSCManager);
        return 1;
    }

    if (!QueryServiceStatusEx(schService, SC_STATUS_PROCESS_INFO,
                              (LPBYTE)&status, sizeof(status), &bytesNeeded)) {
        printf("Cannot query service status (error %d)\n", GetLastError());
        CloseServiceHandle(schService);
        CloseServiceHandle(schSCManager);
        return 1;
    }

    switch (status.dwCurrentState) {
        case SERVICE_STOPPED:          stateStr = "STOPPED"; break;
        case SERVICE_START_PENDING:    stateStr = "STARTING"; break;
        case SERVICE_STOP_PENDING:     stateStr = "STOPPING"; break;
        case SERVICE_RUNNING:          stateStr = "RUNNING"; break;
        case SERVICE_CONTINUE_PENDING: stateStr = "CONTINUING"; break;
        case SERVICE_PAUSE_PENDING:    stateStr = "PAUSING"; break;
        case SERVICE_PAUSED:           stateStr = "PAUSED"; break;
        default:                       stateStr = "UNKNOWN"; break;
    }

    printf("Service '%s' status: %s\n",
           g_Config.serviceName[0] ? g_Config.serviceName : "ftpsmin",
           stateStr);

    if (status.dwCurrentState == SERVICE_RUNNING) {
        printf("Process ID: %d\n", status.dwProcessId);
    }

    CloseServiceHandle(schService);
    CloseServiceHandle(schSCManager);
    return 0;
}

//------------------------------------------------------------------------------------
// Validate configuration
//------------------------------------------------------------------------------------
static BOOL ValidateConfig(ServerConfig *config)
{
    BOOL valid = TRUE;

    // Check port
    if (config->port < 1 || config->port > 65535) {
        printf("Error: Invalid port number %d\n", config->port);
        valid = FALSE;
    }

    // Check passive port range
    if (config->passivePortStart > 0 || config->passivePortEnd > 0) {
        if (config->passivePortStart < 1024 || config->passivePortStart > 65535) {
            printf("Error: Invalid passive port start %d\n", config->passivePortStart);
            valid = FALSE;
        }
        if (config->passivePortEnd < config->passivePortStart || config->passivePortEnd > 65535) {
            printf("Error: Invalid passive port end %d\n", config->passivePortEnd);
            valid = FALSE;
        }
    }

    // Check TLS files if TLS enabled
    if (config->useTLS) {
        FILE *f;
        if (config->certFile[0] == '\0') {
            printf("Error: TLS enabled but no certificate file specified\n");
            valid = FALSE;
        } else {
            f = fopen(config->certFile, "r");
            if (!f) {
                printf("Warning: Cannot open certificate file '%s'\n", config->certFile);
            } else {
                fclose(f);
            }
        }

        if (config->keyFile[0] == '\0') {
            printf("Error: TLS enabled but no key file specified\n");
            valid = FALSE;
        } else {
            f = fopen(config->keyFile, "r");
            if (!f) {
                printf("Warning: Cannot open key file '%s'\n", config->keyFile);
            } else {
                fclose(f);
            }
        }
    }

    // Check virtual directories
    if (config->numVirtualDirs == 0) {
        printf("Warning: No virtual directories configured\n");
    } else {
        int i;
        for (i = 0; i < config->numVirtualDirs; i++) {
            if (config->virtualDirs[i].virtualPath[0] == '\0') {
                printf("Error: Virtual directory %d has no virtual path\n", i + 1);
                valid = FALSE;
            }
            if (config->virtualDirs[i].physicalPath[0] == '\0') {
                printf("Error: Virtual directory %d has no physical path\n", i + 1);
                valid = FALSE;
            }
        }
    }

    // Check authentication
    if (config->requireAuth) {
        if (config->username[0] == '\0') {
            printf("Error: Authentication required but no username specified\n");
            valid = FALSE;
        }
        if (config->password[0] == '\0') {
            printf("Warning: Authentication required but password is empty\n");
        }
    }

    return valid;
}

//------------------------------------------------------------------------------------
// Generate sample configuration file
//------------------------------------------------------------------------------------
static void GenerateSampleConfig(const char *filename)
{
    FILE *f = fopen(filename, "w");
    if (!f) {
        printf("Cannot create file '%s'\n", filename);
        return;
    }

    fprintf(f, "{\n");
    fprintf(f, "    \"port\": 21,\n");
    fprintf(f, "    \"hostAddress\": \"\",\n");
    fprintf(f, "    \"getOnly\": false,\n");
    fprintf(f, "    \n");
    fprintf(f, "    \"virtualDirs\": [\n");
    fprintf(f, "        {\n");
    fprintf(f, "            \"virtual\": \"/readonly\",\n");
    fprintf(f, "            \"physical\": \"C:\\\\inetpub\",\n");
    fprintf(f, "            \"readOnly\": true,\n");
    fprintf(f, "            \"hidden\": false\n");
    fprintf(f, "        },\n");
    fprintf(f, "        {\n");
    fprintf(f, "            \"virtual\": \"/public\",\n");
    fprintf(f, "            \"physical\": \"C:\\\\FTP\",\n");
    fprintf(f, "            \"readOnly\": false,\n");
    fprintf(f, "            \"hidden\": false\n");
    fprintf(f, "        }\n");
    fprintf(f, "    ],\n");
    fprintf(f, "    \n");
    fprintf(f, "    \"passivePortStart\": 50000,\n");
    fprintf(f, "    \"passivePortEnd\": 50100,\n");
    fprintf(f, "    \n");
    fprintf(f, "    \"useTLS\": false,\n");
    fprintf(f, "    \"implicitTLS\": false,\n");
    fprintf(f, "    \"certFile\": \"server.crt\",\n");
    fprintf(f, "    \"keyFile\": \"server.key\",\n");
    fprintf(f, "    \n");
    fprintf(f, "    \"requireAuth\": true,\n");
    fprintf(f, "    \"username\": \"ftpuser\",\n");
    fprintf(f, "    \"password\": \"changeme\",\n");
    fprintf(f, "    \n");
    fprintf(f, "    \"defaultUtf8\": true,\n");
    fprintf(f, "    \n");
    fprintf(f, "    \"serviceName\": \"ftpsmin\",\n");
    fprintf(f, "    \"serviceDisplayName\": \"FTPSMIN Secure FTP Server\"\n");
    fprintf(f, "}\n");

    fclose(f);
    printf("Sample configuration written to '%s'\n", filename);
}

//------------------------------------------------------------------------------------
// Main entry point
//------------------------------------------------------------------------------------
int main(int argc, char **argv)
{
    WSADATA wsaData;
    char configFile[MAX_PATH] = "ftpsmin.json";
    int argn;
    BOOL generateConfig = FALSE;

    // Check for service mode first (before printing anything)
    for (argn = 1; argn < argc; argn++) {
        if (strcmp(argv[argn], "-service") == 0) {
            g_RunAsService = TRUE;
            break;
        }
    }

    // Print banner in console mode
    if (!g_RunAsService) {
        PrintVersion();
        printf("\n");
    }

    // Parse command line arguments
    for (argn = 1; argn < argc; argn++) {
        char *arg = argv[argn];

        if (strcmp(arg, "-c") == 0 || strcmp(arg, "--config") == 0) {
            if (argn + 1 < argc) {
                strncpy(configFile, argv[++argn], MAX_PATH - 1);
                configFile[MAX_PATH - 1] = '\0';
            } else {
                printf("Error: -c requires a filename\n");
                return 1;
            }
        } else if (strcmp(arg, "-install") == 0) {
            if (!LoadConfig(configFile, &g_Config)) {
                SetDefaultConfig(&g_Config);
            }
            return ServiceInstall();
        } else if (strcmp(arg, "-uninstall") == 0) {
            if (!LoadConfig(configFile, &g_Config)) {
                SetDefaultConfig(&g_Config);
            }
            return ServiceUninstall();
        } else if (strcmp(arg, "-start") == 0) {
            if (!LoadConfig(configFile, &g_Config)) {
                SetDefaultConfig(&g_Config);
            }
            return ServiceStart();
        } else if (strcmp(arg, "-stop") == 0) {
            if (!LoadConfig(configFile, &g_Config)) {
                SetDefaultConfig(&g_Config);
            }
            return ServiceStop();
        } else if (strcmp(arg, "-status") == 0) {
            if (!LoadConfig(configFile, &g_Config)) {
                SetDefaultConfig(&g_Config);
            }
            return ServiceStatus();
        } else if (strcmp(arg, "-service") == 0) {
            // Already handled
        } else if (strcmp(arg, "-genconfig") == 0) {
            generateConfig = TRUE;
        } else if (strcmp(arg, "-v") == 0 || strcmp(arg, "-version") == 0 ||
                   strcmp(arg, "--version") == 0) {
            // Version already printed
            return 0;
        } else if (strcmp(arg, "-h") == 0 || strcmp(arg, "-help") == 0 ||
                   strcmp(arg, "--help") == 0 || strcmp(arg, "/?") == 0) {
            PrintUsage();
            return 0;
        } else {
            printf("Unknown option: %s\n", arg);
            printf("Use -h for help\n");
            return 1;
        }
    }

    // Generate sample config if requested
    if (generateConfig) {
        GenerateSampleConfig(configFile);
        return 0;
    }

    // Load configuration
    if (!LoadConfig(configFile, &g_Config)) {
        if (!g_RunAsService) {
            printf("Could not load config file '%s'\n", configFile);

            // Check if file exists
            FILE *f = fopen(configFile, "r");
            if (!f) {
                printf("File does not exist. Use -genconfig to create a sample.\n");
            } else {
                fclose(f);
                printf("File exists but may have syntax errors.\n");
            }
            printf("Using default configuration.\n\n");
        }
        SetDefaultConfig(&g_Config);
    } else {
        if (!g_RunAsService) {
            printf("Loaded configuration from '%s'\n", configFile);
        }
    }

    // Validate configuration
    if (!g_RunAsService) {
        if (!ValidateConfig(&g_Config)) {
            printf("\nConfiguration validation failed. Please fix the errors above.\n");
            return 1;
        }
    }

    // Initialize Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        if (!g_RunAsService) {
            printf("Failed to initialize Winsock (error %d)\n", WSAGetLastError());
        }
        return 1;
    }

    // Check Winsock version
    if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2) {
        if (!g_RunAsService) {
            printf("Winsock 2.2 required\n");
        }
        WSACleanup();
        return 1;
    }

    if (g_RunAsService) {
        // Run as Windows Service
        ServiceRun();
    } else {
        // Run in console mode
        printf("\nPress Ctrl+C to stop the server\n\n");
        ServerMain();
    }

    WSACleanup();
    return 0;
}