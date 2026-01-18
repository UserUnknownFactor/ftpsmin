//------------------------------------------------------------------------------------
// JSON Configuration Header
//------------------------------------------------------------------------------------
#ifndef CONFIG_H
#define CONFIG_H

#include <windows.h>

#define MAX_CONFIG_STRING 256
#define MAX_VIRTUAL_DIRS 64

// Virtual directory mapping
typedef struct {
    char virtualPath[MAX_PATH];     // Virtual path (e.g., "/c_ftp")
    char physicalPath[MAX_PATH];    // Physical path (e.g., "C:\\ftp")
    BOOL readOnly;                  // Read-only access for this directory
    BOOL hidden;                    // Hidden from root listing
} VirtualDir;

typedef struct {
    int port;                               // Control port (default 21)
    char hostAddress[64];                   // External IP address (for NAT)
    BOOL getOnly;                           // Disallow uploads globally
    int passivePortStart;                   // Passive mode port range start
    int passivePortEnd;                     // Passive mode port range end
    
    // Virtual directories
    int numVirtualDirs;
    VirtualDir virtualDirs[MAX_VIRTUAL_DIRS];
    
    // TLS/SSL settings
    BOOL useTLS;                            // Enable TLS support
    BOOL implicitTLS;                       // Use implicit TLS (port 990)
    BOOL requireTLS;                        // Require TLS for all connections
    char certFile[MAX_PATH];                // Path to certificate file
    char keyFile[MAX_PATH];                 // Path to private key file
    
    // Authentication
    BOOL requireAuth;                       // Require username/password
    char username[MAX_CONFIG_STRING];       // Username
    char password[MAX_CONFIG_STRING];       // Password
    
    // UTF-8 settings
    BOOL defaultUtf8;                       // Enable UTF-8 by default
    
    // Logging
    char logFile[MAX_PATH];                 // Log file path (empty = console only)
    int logLevel;                           // 0=errors, 1=warnings, 2=info, 3=debug
    
    // Limits
    int maxConnections;                     // Maximum simultaneous connections
    int idleTimeout;                        // Idle timeout in seconds
    int transferTimeout;                    // Transfer timeout in seconds
    
    // Service settings
    char serviceName[MAX_CONFIG_STRING];
    char serviceDisplayName[MAX_CONFIG_STRING];
    char serviceDescription[MAX_CONFIG_STRING];
} ServerConfig;

// Function prototypes
BOOL LoadConfig(const char *filename, ServerConfig *config);
void SetDefaultConfig(ServerConfig *config);
BOOL SaveConfig(const char *filename, ServerConfig *config);

#endif // CONFIG_H