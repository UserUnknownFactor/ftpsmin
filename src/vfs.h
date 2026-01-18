//------------------------------------------------------------------------------------
// Virtual File System Header - Handles multiple root directories
//------------------------------------------------------------------------------------
#ifndef VFS_H
#define VFS_H

#include <windows.h>
#include "config.h"

// Directory entry for listings
typedef struct {
    char name[MAX_PATH * 3];    // UTF-8 filename
    BOOL isDirectory;
    BOOL isVirtualRoot;         // TRUE if this is a virtual directory mount point
    ULONGLONG size;
    FILETIME modTime;
    DWORD attributes;
} VFS_DirEntry;

// Find handle for directory enumeration
typedef struct {
    HANDLE findHandle;
    int virtualDirIndex;
    BOOL listingVirtualRoots;
    BOOL listingPhysical;
    char baseDir[MAX_PATH * 3];
    char pattern[MAX_PATH];
    WIN32_FIND_DATAW findData;
} VFS_FindHandle;

// Initialize VFS with configuration
BOOL VFS_Initialize(ServerConfig *config);

// Cleanup VFS
void VFS_Cleanup(void);

// Set current virtual directory
// currentDir: current directory (in/out)
// newDir: directory to change to (relative or absolute)
// outDir: buffer to receive new directory
// outDirSize: size of outDir buffer
// Returns TRUE on success
BOOL VFS_SetDirectory(const char *currentDir, const char *newDir, 
                      char *outDir, size_t outDirSize);

// Translate virtual path to physical path
// Returns pointer to static buffer, or NULL if path invalid
char* VFS_TranslatePath(const char *currentDir, const char *virtualPath);

// Check if path is read-only
BOOL VFS_IsReadOnly(const char *virtualPath);

// Directory enumeration
VFS_FindHandle* VFS_FindFirst(const char *currentDir, const char *pattern, VFS_DirEntry *entry);
BOOL VFS_FindNext(VFS_FindHandle *handle, VFS_DirEntry *entry);
void VFS_FindClose(VFS_FindHandle *handle);

// File operations
HANDLE VFS_CreateFile(const char *currentDir, const char *filename, 
                      DWORD access, DWORD shareMode, DWORD creation, DWORD flags);
BOOL VFS_DeleteFile(const char *currentDir, const char *filename);
BOOL VFS_CreateDirectory(const char *currentDir, const char *dirname);
BOOL VFS_RemoveDirectory(const char *currentDir, const char *dirname);
BOOL VFS_MoveFile(const char *currentDir, const char *oldName, const char *newName);
BOOL VFS_GetFileInfo(const char *currentDir, const char *filename, 
                     WIN32_FILE_ATTRIBUTE_DATA *info);

#endif // VFS_H