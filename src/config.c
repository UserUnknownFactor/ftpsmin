//------------------------------------------------------------------------------------
// JSON Configuration Implementation
//------------------------------------------------------------------------------------
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "config.h"

//------------------------------------------------------------------------------------
// Skip whitespace in JSON
//------------------------------------------------------------------------------------
static const char* SkipWhitespace(const char *json)
{
    while (*json && isspace((unsigned char)*json)) json++;
    return json;
}

//------------------------------------------------------------------------------------
// Skip a JSON value (for unknown keys)
//------------------------------------------------------------------------------------
static const char* SkipValue(const char *json)
{
    json = SkipWhitespace(json);
    
    if (*json == '"') {
        // String
        json++;
        while (*json && *json != '"') {
            if (*json == '\\' && *(json+1)) json++;
            json++;
        }
        if (*json == '"') json++;
    } else if (*json == '{') {
        // Object
        int depth = 1;
        json++;
        while (*json && depth > 0) {
            if (*json == '{') depth++;
            else if (*json == '}') depth--;
            else if (*json == '"') {
                json++;
                while (*json && *json != '"') {
                    if (*json == '\\' && *(json+1)) json++;
                    json++;
                }
            }
            if (*json) json++;
        }
    } else if (*json == '[') {
        // Array
        int depth = 1;
        json++;
        while (*json && depth > 0) {
            if (*json == '[') depth++;
            else if (*json == ']') depth--;
            else if (*json == '"') {
                json++;
                while (*json && *json != '"') {
                    if (*json == '\\' && *(json+1)) json++;
                    json++;
                }
            }
            if (*json) json++;
        }
    } else if (*json == 't') {
        // true
        if (strncmp(json, "true", 4) == 0) json += 4;
    } else if (*json == 'f') {
        // false
        if (strncmp(json, "false", 5) == 0) json += 5;
    } else if (*json == 'n') {
        // null
        if (strncmp(json, "null", 4) == 0) json += 4;
    } else if (*json == '-' || isdigit((unsigned char)*json)) {
        // Number
        if (*json == '-') json++;
        while (isdigit((unsigned char)*json)) json++;
        if (*json == '.') {
            json++;
            while (isdigit((unsigned char)*json)) json++;
        }
        if (*json == 'e' || *json == 'E') {
            json++;
            if (*json == '+' || *json == '-') json++;
            while (isdigit((unsigned char)*json)) json++;
        }
    }
    
    return json;
}

//------------------------------------------------------------------------------------
// Parse a JSON string
//------------------------------------------------------------------------------------
static const char* ParseString(const char *json, char *buffer, size_t bufSize)
{
    size_t i = 0;
    
    json = SkipWhitespace(json);
    
    if (*json != '"') return NULL;
    json++;
    
    while (*json && *json != '"' && i < bufSize - 1) {
        if (*json == '\\') {
            json++;
            switch (*json) {
                case 'n': buffer[i++] = '\n'; break;
                case 'r': buffer[i++] = '\r'; break;
                case 't': buffer[i++] = '\t'; break;
                case '\\': buffer[i++] = '\\'; break;
                case '"': buffer[i++] = '"'; break;
                case '/': buffer[i++] = '/'; break;
                case 'b': buffer[i++] = '\b'; break;
                case 'f': buffer[i++] = '\f'; break;
                case 'u':
                    // Unicode escape - simplified handling
                    buffer[i++] = '?';
                    if (json[1] && json[2] && json[3] && json[4]) json += 4;
                    break;
                default: 
                    buffer[i++] = *json;
            }
        } else {
            buffer[i++] = *json;
        }
        json++;
    }
    buffer[i] = '\0';
    
    if (*json == '"') json++;
    return json;
}

//------------------------------------------------------------------------------------
// Parse a JSON number
//------------------------------------------------------------------------------------
static const char* ParseNumber(const char *json, double *value)
{
    char *end;
    json = SkipWhitespace(json);
    *value = strtod(json, &end);
    return end;
}

//------------------------------------------------------------------------------------
// Parse a JSON integer
//------------------------------------------------------------------------------------
static const char* ParseInt(const char *json, int *value)
{
    double d;
    json = ParseNumber(json, &d);
    *value = (int)d;
    return json;
}

//------------------------------------------------------------------------------------
// Parse a JSON boolean
//------------------------------------------------------------------------------------
static const char* ParseBool(const char *json, BOOL *value)
{
    json = SkipWhitespace(json);
    
    if (strncmp(json, "true", 4) == 0) {
        *value = TRUE;
        return json + 4;
    } else if (strncmp(json, "false", 5) == 0) {
        *value = FALSE;
        return json + 5;
    }
    return NULL;
}

//------------------------------------------------------------------------------------
// Set default configuration values
//------------------------------------------------------------------------------------
void SetDefaultConfig(ServerConfig *config)
{
    memset(config, 0, sizeof(ServerConfig));
    
    config->port = 21;
    config->hostAddress[0] = '\0';
    config->getOnly = FALSE;
    config->passivePortStart = 0;
    config->passivePortEnd = 0;
    
    config->numVirtualDirs = 0;
    
    config->useTLS = FALSE;
    config->implicitTLS = FALSE;
    config->requireTLS = FALSE;
    strcpy(config->certFile, "server.crt");
    strcpy(config->keyFile, "server.key");
    
    config->requireAuth = FALSE;
    strcpy(config->username, "anonymous");
    config->password[0] = '\0';
    
    config->defaultUtf8 = TRUE;
    
    config->logFile[0] = '\0';
    config->logLevel = 2;
    
    config->maxConnections = 10;
    config->idleTimeout = 300;
    config->transferTimeout = 600;
    
    strcpy(config->serviceName, "ftpsmin");
    strcpy(config->serviceDisplayName, "FTPSMIN Secure FTP Server");
    strcpy(config->serviceDescription, "Minimal secure FTP server with UTF-8 and virtual directory support");
}

//------------------------------------------------------------------------------------
// Parse a virtual directory object
//------------------------------------------------------------------------------------
static const char* ParseVirtualDir(const char *json, VirtualDir *vdir)
{
    char key[64];
    
    memset(vdir, 0, sizeof(VirtualDir));
    
    json = SkipWhitespace(json);
    if (*json != '{') return NULL;
    json++;
    
    while (*json) {
        json = SkipWhitespace(json);
        
        if (*json == '}') {
            json++;
            break;
        }
        if (*json == ',') {
            json++;
            continue;
        }
        
        // Parse key
        json = ParseString(json, key, sizeof(key));
        if (!json) return NULL;
        
        json = SkipWhitespace(json);
        if (*json != ':') return NULL;
        json++;
        json = SkipWhitespace(json);
        
        // Parse value
        if (strcmp(key, "virtual") == 0) {
            json = ParseString(json, vdir->virtualPath, sizeof(vdir->virtualPath));
        } else if (strcmp(key, "physical") == 0) {
            json = ParseString(json, vdir->physicalPath, sizeof(vdir->physicalPath));
        } else if (strcmp(key, "readOnly") == 0) {
            json = ParseBool(json, &vdir->readOnly);
        } else if (strcmp(key, "hidden") == 0) {
            json = ParseBool(json, &vdir->hidden);
        } else {
            json = SkipValue(json);
        }
        
        if (!json) return NULL;
    }
    
    return json;
}

//------------------------------------------------------------------------------------
// Load configuration from JSON file
//------------------------------------------------------------------------------------
BOOL LoadConfig(const char *filename, ServerConfig *config)
{
    FILE *file;
    char *buffer;
    long fileSize;
    const char *json;
    char key[256];
    
    SetDefaultConfig(config);
    
    file = fopen(filename, "rb");
    if (!file) {
        return FALSE;
    }
    
    fseek(file, 0, SEEK_END);
    fileSize = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    if (fileSize <= 0 || fileSize > 1024 * 1024) {  // Max 1MB config
        fclose(file);
        return FALSE;
    }
    
    buffer = (char *)malloc(fileSize + 1);
    if (!buffer) {
        fclose(file);
        return FALSE;
    }
    
    if (fread(buffer, 1, fileSize, file) != (size_t)fileSize) {
        free(buffer);
        fclose(file);
        return FALSE;
    }
    buffer[fileSize] = '\0';
    fclose(file);
    
    json = SkipWhitespace(buffer);
    
    // Expect opening brace
    if (*json != '{') {
        free(buffer);
        return FALSE;
    }
    json++;
    
    while (*json) {
        json = SkipWhitespace(json);
        
        if (*json == '}') break;
        if (*json == ',') { json++; continue; }
        
        // Parse key
        json = ParseString(json, key, sizeof(key));
        if (!json) break;
        
        json = SkipWhitespace(json);
        if (*json != ':') break;
        json++;
        json = SkipWhitespace(json);
        
        // Parse value based on key
        if (strcmp(key, "port") == 0) {
            json = ParseInt(json, &config->port);
        }
        else if (strcmp(key, "hostAddress") == 0) {
            json = ParseString(json, config->hostAddress, sizeof(config->hostAddress));
        }
        else if (strcmp(key, "getOnly") == 0) {
            json = ParseBool(json, &config->getOnly);
        }
        else if (strcmp(key, "passivePortStart") == 0) {
            json = ParseInt(json, &config->passivePortStart);
        }
        else if (strcmp(key, "passivePortEnd") == 0) {
            json = ParseInt(json, &config->passivePortEnd);
        }
        else if (strcmp(key, "useTLS") == 0) {
            json = ParseBool(json, &config->useTLS);
        }
        else if (strcmp(key, "implicitTLS") == 0) {
            json = ParseBool(json, &config->implicitTLS);
        }
        else if (strcmp(key, "requireTLS") == 0) {
            json = ParseBool(json, &config->requireTLS);
        }
        else if (strcmp(key, "certFile") == 0) {
            json = ParseString(json, config->certFile, sizeof(config->certFile));
        }
        else if (strcmp(key, "keyFile") == 0) {
            json = ParseString(json, config->keyFile, sizeof(config->keyFile));
        }
        else if (strcmp(key, "requireAuth") == 0) {
            json = ParseBool(json, &config->requireAuth);
        }
        else if (strcmp(key, "username") == 0) {
            json = ParseString(json, config->username, sizeof(config->username));
        }
        else if (strcmp(key, "password") == 0) {
            json = ParseString(json, config->password, sizeof(config->password));
        }
        else if (strcmp(key, "defaultUtf8") == 0) {
            json = ParseBool(json, &config->defaultUtf8);
        }
        else if (strcmp(key, "logFile") == 0) {
            json = ParseString(json, config->logFile, sizeof(config->logFile));
        }
        else if (strcmp(key, "logLevel") == 0) {
            json = ParseInt(json, &config->logLevel);
        }
        else if (strcmp(key, "maxConnections") == 0) {
            json = ParseInt(json, &config->maxConnections);
        }
        else if (strcmp(key, "idleTimeout") == 0) {
            json = ParseInt(json, &config->idleTimeout);
        }
        else if (strcmp(key, "transferTimeout") == 0) {
            json = ParseInt(json, &config->transferTimeout);
        }
        else if (strcmp(key, "serviceName") == 0) {
            json = ParseString(json, config->serviceName, sizeof(config->serviceName));
        }
        else if (strcmp(key, "serviceDisplayName") == 0) {
            json = ParseString(json, config->serviceDisplayName, sizeof(config->serviceDisplayName));
        }
        else if (strcmp(key, "serviceDescription") == 0) {
            json = ParseString(json, config->serviceDescription, sizeof(config->serviceDescription));
        }
        else if (strcmp(key, "virtualDirs") == 0) {
            // Parse array of virtual directories
            json = SkipWhitespace(json);
            if (*json != '[') {
                json = SkipValue(json);
                continue;
            }
            json++;
            
            config->numVirtualDirs = 0;
            
            while (*json && config->numVirtualDirs < MAX_VIRTUAL_DIRS) {
                json = SkipWhitespace(json);
                if (*json == ']') { json++; break; }
                if (*json == ',') { json++; continue; }
                
                json = ParseVirtualDir(json, &config->virtualDirs[config->numVirtualDirs]);
                if (!json) break;
                
                // Validate and add
                if (config->virtualDirs[config->numVirtualDirs].virtualPath[0] &&
                    config->virtualDirs[config->numVirtualDirs].physicalPath[0]) {
                    config->numVirtualDirs++;
                }
            }
        }
        else {
            // Skip unknown keys
            json = SkipValue(json);
        }
        
        if (!json) break;
    }
    
    free(buffer);
    
    // Post-processing
    if (config->implicitTLS && config->port == 21) {
        config->port = 990;
    }
    
    if (config->maxConnections <= 0) {
        config->maxConnections = 10;
    }
    
    if (config->idleTimeout <= 0) {
        config->idleTimeout = 300;
    }
    
    if (config->transferTimeout <= 0) {
        config->transferTimeout = 600;
    }
    
    return TRUE;
}

//------------------------------------------------------------------------------------
// Save configuration to JSON file
//------------------------------------------------------------------------------------
BOOL SaveConfig(const char *filename, ServerConfig *config)
{
    FILE *file;
    int i;
    
    file = fopen(filename, "w");
    if (!file) {
        return FALSE;
    }
    
    fprintf(file, "{\n");
    fprintf(file, "    \"port\": %d,\n", config->port);
    fprintf(file, "    \"hostAddress\": \"%s\",\n", config->hostAddress);
    fprintf(file, "    \"getOnly\": %s,\n", config->getOnly ? "true" : "false");
    fprintf(file, "    \"passivePortStart\": %d,\n", config->passivePortStart);
    fprintf(file, "    \"passivePortEnd\": %d,\n", config->passivePortEnd);
    fprintf(file, "\n");
    
    fprintf(file, "    \"virtualDirs\": [\n");
    for (i = 0; i < config->numVirtualDirs; i++) {
        fprintf(file, "        {\n");
        fprintf(file, "            \"virtual\": \"%s\",\n", config->virtualDirs[i].virtualPath);
        fprintf(file, "            \"physical\": \"%s\",\n", config->virtualDirs[i].physicalPath);
        fprintf(file, "            \"readOnly\": %s,\n", config->virtualDirs[i].readOnly ? "true" : "false");
        fprintf(file, "            \"hidden\": %s\n", config->virtualDirs[i].hidden ? "true" : "false");
        fprintf(file, "        }%s\n", (i < config->numVirtualDirs - 1) ? "," : "");
    }
    fprintf(file, "    ],\n");
    fprintf(file, "\n");
    
    fprintf(file, "    \"useTLS\": %s,\n", config->useTLS ? "true" : "false");
    fprintf(file, "    \"implicitTLS\": %s,\n", config->implicitTLS ? "true" : "false");
    fprintf(file, "    \"requireTLS\": %s,\n", config->requireTLS ? "true" : "false");
    fprintf(file, "    \"certFile\": \"%s\",\n", config->certFile);
    fprintf(file, "    \"keyFile\": \"%s\",\n", config->keyFile);
    fprintf(file, "\n");
    
    fprintf(file, "    \"requireAuth\": %s,\n", config->requireAuth ? "true" : "false");
    fprintf(file, "    \"username\": \"%s\",\n", config->username);
    fprintf(file, "    \"password\": \"%s\",\n", config->password);
    fprintf(file, "\n");
    
    fprintf(file, "    \"defaultUtf8\": %s,\n", config->defaultUtf8 ? "true" : "false");
    fprintf(file, "    \"logFile\": \"%s\",\n", config->logFile);
    fprintf(file, "    \"logLevel\": %d,\n", config->logLevel);
    fprintf(file, "\n");
    
    fprintf(file, "    \"maxConnections\": %d,\n", config->maxConnections);
    fprintf(file, "    \"idleTimeout\": %d,\n", config->idleTimeout);
    fprintf(file, "    \"transferTimeout\": %d,\n", config->transferTimeout);
    fprintf(file, "\n");
    
    fprintf(file, "    \"serviceName\": \"%s\",\n", config->serviceName);
    fprintf(file, "    \"serviceDisplayName\": \"%s\",\n", config->serviceDisplayName);
    fprintf(file, "    \"serviceDescription\": \"%s\"\n", config->serviceDescription);
    fprintf(file, "}\n");
    
    fclose(file);
    return TRUE;
}