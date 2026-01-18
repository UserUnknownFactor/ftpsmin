//------------------------------------------------------------------------------------
// Virtual File System Implementation - Handles multiple root directories
//------------------------------------------------------------------------------------
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "vfs.h"
#include "utf8_support.h"

static ServerConfig *g_VFSConfig = NULL;
extern void LogMessage(const char *format, ...);

//------------------------------------------------------------------------------------
// Normalize a virtual path (remove double slashes, handle . and ..)
//------------------------------------------------------------------------------------
static void NormalizePath(char *path)
{
    char *src, *dst;
    char *segments[256];
    int numSegments = 0;
    char temp[MAX_PATH * 3];
    int i;

    if (!path || !*path) {
        if (path) strcpy(path, "/");
        return;
    }

    for (src = path; *src; src++) {
        if (*src == '\\') *src = '/';
    }

    strncpy(temp, path, sizeof(temp) - 1);
    temp[sizeof(temp) - 1] = '\0';
    src = temp;

    while (*src) {
        while (*src == '/') src++;
        if (!*src) break;

        dst = src;
        while (*dst && *dst != '/') dst++;

        char savedChar = *dst;
        *dst = '\0';  // Null-terminate segment

        if (strcmp(src, ".") == 0) {
            // Skip
        } else if (strcmp(src, "..") == 0) {
            if (numSegments > 0) numSegments--;
        } else {
            segments[numSegments++] = src;
        }

        // DON'T restore - just advance past the null
        if (savedChar) {
            src = dst + 1;
        } else {
            break;
        }
    }

    // Rebuild
    path[0] = '/';
    path[1] = '\0';

    for (i = 0; i < numSegments; i++) {
        if (strlen(path) > 1) strcat(path, "/");
        strcat(path, segments[i]);
    }
}

//------------------------------------------------------------------------------------
// Find which virtual directory a path belongs to
// Returns index or -1 if none
//------------------------------------------------------------------------------------
static int FindVirtualDir(const char *virtualPath)
{
    int i;
    size_t pathLen;
    char normPath[MAX_PATH * 3];
    
    if (!virtualPath || !g_VFSConfig) return -1;
    
    strncpy(normPath, virtualPath, sizeof(normPath) - 1);
    normPath[sizeof(normPath) - 1] = '\0';
    NormalizePath(normPath);
    
    pathLen = strlen(normPath);
    
    // Find the best (longest) matching virtual directory
    int bestMatch = -1;
    size_t bestLen = 0;
    
    for (i = 0; i < g_VFSConfig->numVirtualDirs; i++) {
        size_t vdirLen = strlen(g_VFSConfig->virtualDirs[i].virtualPath);
        
        // Check if path starts with this virtual dir
        if (_strnicmp(normPath, g_VFSConfig->virtualDirs[i].virtualPath, vdirLen) == 0) {
            // Must be exact match or followed by /
            if (pathLen == vdirLen || normPath[vdirLen] == '/' || normPath[vdirLen] == '\0') {
                if (vdirLen > bestLen) {
                    bestMatch = i;
                    bestLen = vdirLen;
                }
            }
        }
    }
    
    return bestMatch;
}

//------------------------------------------------------------------------------------
// Initialize VFS
//------------------------------------------------------------------------------------
BOOL VFS_Initialize(ServerConfig *config)
{
    int i;
    
    g_VFSConfig = config;
    
    // Normalize and validate virtual directories
    for (i = 0; i < config->numVirtualDirs; i++) {
        VirtualDir *vdir = &config->virtualDirs[i];
        wchar_t *widePath;
        DWORD attrs;
        
        // Ensure virtual path starts with /
        if (vdir->virtualPath[0] != '/') {
            char temp[MAX_PATH];
            snprintf(temp, sizeof(temp), "/%s", vdir->virtualPath);
            strncpy(vdir->virtualPath, temp, sizeof(vdir->virtualPath) - 1);
        }
        
        // Remove trailing slashes from virtual path (except root)
        size_t len = strlen(vdir->virtualPath);
        while (len > 1 && vdir->virtualPath[len - 1] == '/') {
            vdir->virtualPath[--len] = '\0';
        }
        
        // Normalize virtual path
        NormalizePath(vdir->virtualPath);
        
        // Remove trailing backslash from physical path (except for root like C:\)
        len = strlen(vdir->physicalPath);
        while (len > 3 && (vdir->physicalPath[len - 1] == '\\' || vdir->physicalPath[len - 1] == '/')) {
            vdir->physicalPath[--len] = '\0';
        }
        
        // Validate physical path exists
        widePath = Utf8ToWide(vdir->physicalPath);
        if (!widePath) {
            LogMessage("Warning: Invalid encoding for virtual directory '%s'", 
                       vdir->virtualPath);
            continue;
        }
        
        attrs = GetFileAttributesW(widePath);
        FreeWideString(widePath);
        
        if (attrs == INVALID_FILE_ATTRIBUTES) {
            LogMessage("Warning: Physical path does not exist for '%s': %s",
                       vdir->virtualPath, vdir->physicalPath);
        } else if (!(attrs & FILE_ATTRIBUTE_DIRECTORY)) {
            LogMessage("Warning: Physical path is not a directory for '%s': %s",
                       vdir->virtualPath, vdir->physicalPath);
        } else {
            //LogMessage("VFS: Mapped '%s' -> '%s'", vdir->virtualPath, vdir->physicalPath);
        }
    }
    
    return TRUE;
}

//------------------------------------------------------------------------------------
// Cleanup VFS
//------------------------------------------------------------------------------------
void VFS_Cleanup(void)
{
    g_VFSConfig = NULL;
}

//------------------------------------------------------------------------------------
// Translate virtual path to physical path
// Note: Returns pointer to static buffer - copy result if needed
//------------------------------------------------------------------------------------
char* VFS_TranslatePath(const char *currentDir, const char *virtualPath)
{
    static char physPath[MAX_PATH * 3];
    char fullPath[MAX_PATH * 3];
    int vdirIndex;
    VirtualDir *vdir;
    const char *relPath;
    char *p;
    
    if (!virtualPath) return NULL;
    
    // Handle "." as current directory
    if (strcmp(virtualPath, ".") == 0) {
        if (currentDir) {
            strncpy(fullPath, currentDir, sizeof(fullPath) - 1);
            fullPath[sizeof(fullPath) - 1] = '\0';
        } else {
            strcpy(fullPath, "/");
        }
    }
    // Build full virtual path
    else if (virtualPath[0] == '/' || virtualPath[0] == '\\') {
        strncpy(fullPath, virtualPath, sizeof(fullPath) - 1);
        fullPath[sizeof(fullPath) - 1] = '\0';
    } else if (currentDir) {
        strncpy(fullPath, currentDir, sizeof(fullPath) - 1);
        fullPath[sizeof(fullPath) - 1] = '\0';
        size_t len = strlen(fullPath);
        if (len > 0 && fullPath[len - 1] != '/') {
            strncat(fullPath, "/", sizeof(fullPath) - len - 1);
        }
        strncat(fullPath, virtualPath, sizeof(fullPath) - strlen(fullPath) - 1);
    } else {
        snprintf(fullPath, sizeof(fullPath), "/%s", virtualPath);
    }
    
    NormalizePath(fullPath);
    
    // Cannot access root directly
    if (strcmp(fullPath, "/") == 0) {
        return NULL;
    }
    
    // Find virtual directory
    vdirIndex = FindVirtualDir(fullPath);
    if (vdirIndex < 0) {
        //LogMessage("VFS_TranslatePath: No virtual dir for '%s'", fullPath);
        return NULL;
    }
    
    vdir = &g_VFSConfig->virtualDirs[vdirIndex];
    
    // Get relative path within virtual directory
    relPath = fullPath + strlen(vdir->virtualPath);
    while (*relPath == '/') relPath++;  // Skip leading slashes
    
    // Build physical path
    if (*relPath) {
        snprintf(physPath, sizeof(physPath), "%s\\%s", vdir->physicalPath, relPath);
    } else {
        strncpy(physPath, vdir->physicalPath, sizeof(physPath) - 1);
        physPath[sizeof(physPath) - 1] = '\0';
    }
    
    // Convert forward slashes to backslashes
    for (p = physPath; *p; p++) {
        if (*p == '/') *p = '\\';
    }
    
    return physPath;
}

//------------------------------------------------------------------------------------
// Set current virtual directory
//------------------------------------------------------------------------------------
BOOL VFS_SetDirectory(const char *currentDir, const char *newDir, 
                      char *outDir, size_t outDirSize)
{
    char fullPath[MAX_PATH * 3];
    int vdirIndex;
    
    if (!currentDir || !newDir || !outDir || outDirSize == 0) {
        return FALSE;
    }
    
    //LogMessage("VFS_SetDirectory: current='%s' new='%s'", currentDir, newDir);
    
    // Handle empty newDir
    if (newDir[0] == '\0') {
        strncpy(outDir, currentDir, outDirSize - 1);
        outDir[outDirSize - 1] = '\0';
        return TRUE;
    }
    
    // Build full path
    if (newDir[0] == '/' || newDir[0] == '\\') {
        // Absolute path
        strncpy(fullPath, newDir, sizeof(fullPath) - 1);
        fullPath[sizeof(fullPath) - 1] = '\0';
    } else {
        // Relative path
        strncpy(fullPath, currentDir, sizeof(fullPath) - 1);
        fullPath[sizeof(fullPath) - 1] = '\0';
        size_t len = strlen(fullPath);
        if (len > 0 && fullPath[len - 1] != '/') {
            strncat(fullPath, "/", sizeof(fullPath) - len - 1);
        }
        strncat(fullPath, newDir, sizeof(fullPath) - strlen(fullPath) - 1);
    }
    
    //LogMessage("VFS_SetDirectory (pre-normalize): fullPath='%s'", fullPath);
    NormalizePath(fullPath);
    //LogMessage("VFS_SetDirectory: fullPath='%s'", fullPath);
    
    // Root is always valid
    if (strcmp(fullPath, "/") == 0) {
        strncpy(outDir, "/", outDirSize - 1);
        outDir[outDirSize - 1] = '\0';
        return TRUE;
    }
    
    // Find matching virtual directory
    vdirIndex = FindVirtualDir(fullPath);
    if (vdirIndex < 0) {
        //LogMessage("VFS_SetDirectory: No virtual dir matches '%s'", fullPath);
        return FALSE;
    }
    
    // Verify the physical path exists
    VirtualDir *vdir = &g_VFSConfig->virtualDirs[vdirIndex];
    size_t vdirLen = strlen(vdir->virtualPath);
    
    //LogMessage("VFS_SetDirectory: Matched vdir '%s' -> '%s'", 
               //vdir->virtualPath, vdir->physicalPath);
    
    // Get relative path after virtual directory
    const char *relPath = fullPath + vdirLen;
    while (*relPath == '/') relPath++;  // Skip any leading slashes
    
    // Build physical path
    char physPath[MAX_PATH * 3];
    
    if (*relPath) {
        // Subdirectory
        snprintf(physPath, sizeof(physPath), "%s\\%s", vdir->physicalPath, relPath);
        
        // Convert forward slashes to backslashes
        char *p;
        for (p = physPath; *p; p++) {
            if (*p == '/') *p = '\\';
        }
    } else {
        // Virtual directory root
        strncpy(physPath, vdir->physicalPath, sizeof(physPath) - 1);
        physPath[sizeof(physPath) - 1] = '\0';
    }
    
    //LogMessage("VFS_SetDirectory: Checking physical path '%s'", physPath);
    
    // Verify directory exists
    wchar_t *widePath = Utf8ToWide(physPath);
    if (!widePath) {
        LogMessage("VFS_SetDirectory: UTF-8 conversion failed");
        return FALSE;
    }
    
    DWORD attrs = GetFileAttributesW(widePath);
    DWORD err = GetLastError();
    FreeWideString(widePath);
    
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        LogMessage("VFS_SetDirectory: Path not found '%s' (error %lu)", physPath, err);
        return FALSE;
    }
    
    if (!(attrs & FILE_ATTRIBUTE_DIRECTORY)) {
        LogMessage("VFS_SetDirectory: Not a directory '%s'", physPath);
        return FALSE;
    }
    
    // Success
    strncpy(outDir, fullPath, outDirSize - 1);
    outDir[outDirSize - 1] = '\0';
    //LogMessage("VFS_SetDirectory: Success, outDir='%s'", outDir);
    return TRUE;
}

//------------------------------------------------------------------------------------
// Check if path is read-only
//------------------------------------------------------------------------------------
BOOL VFS_IsReadOnly(const char *virtualPath)
{
    int vdirIndex;
    char normPath[MAX_PATH * 3];
    
    if (!virtualPath || !g_VFSConfig) return TRUE;
    
    // Root is always read-only (can't create files there)
    strncpy(normPath, virtualPath, sizeof(normPath) - 1);
    normPath[sizeof(normPath) - 1] = '\0';
    NormalizePath(normPath);
    
    if (strcmp(normPath, "/") == 0) {
        return TRUE;
    }
    
    vdirIndex = FindVirtualDir(normPath);
    if (vdirIndex < 0) {
        return TRUE;
    }
    
    return g_VFSConfig->virtualDirs[vdirIndex].readOnly;
}

//------------------------------------------------------------------------------------
// Fill VFS_DirEntry from WIN32_FIND_DATAW
//------------------------------------------------------------------------------------
static void FillDirEntry(VFS_DirEntry *entry, WIN32_FIND_DATAW *findData)
{
    char *utf8Name = WideToUtf8(findData->cFileName);
    if (utf8Name) {
        strncpy(entry->name, utf8Name, sizeof(entry->name) - 1);
        entry->name[sizeof(entry->name) - 1] = '\0';
        FreeUtf8String(utf8Name);
    } else {
        strcpy(entry->name, "?");
    }
    
    entry->isDirectory = (findData->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
    entry->isVirtualRoot = FALSE;
    entry->attributes = findData->dwFileAttributes;
    entry->modTime = findData->ftLastWriteTime;
    
    ULARGE_INTEGER size;
    size.LowPart = findData->nFileSizeLow;
    size.HighPart = findData->nFileSizeHigh;
    entry->size = size.QuadPart;
}

//------------------------------------------------------------------------------------
// Start directory enumeration
//------------------------------------------------------------------------------------
VFS_FindHandle* VFS_FindFirst(const char *currentDir, const char *pattern, VFS_DirEntry *entry)
{
    VFS_FindHandle *handle;
    char fullPath[MAX_PATH * 3];
    char searchPath[MAX_PATH * 3];
    wchar_t *wideSearch;
    int vdirIndex;
    
    handle = (VFS_FindHandle*)calloc(1, sizeof(VFS_FindHandle));
    if (!handle) return NULL;
    
    handle->findHandle = INVALID_HANDLE_VALUE;
    handle->virtualDirIndex = 0;
    handle->listingVirtualRoots = FALSE;
    handle->listingPhysical = FALSE;
    
    // Determine base directory
    if (currentDir) {
        strncpy(handle->baseDir, currentDir, sizeof(handle->baseDir) - 1);
    } else {
        strcpy(handle->baseDir, "/");
    }
    handle->baseDir[sizeof(handle->baseDir) - 1] = '\0';
    
    // Store pattern
    if (pattern && *pattern && strcmp(pattern, "*") != 0 && strcmp(pattern, "*.*") != 0) {
        strncpy(handle->pattern, pattern, sizeof(handle->pattern) - 1);
    } else {
        strcpy(handle->pattern, "*");
    }
    handle->pattern[sizeof(handle->pattern) - 1] = '\0';
    
    // Build full path
    strncpy(fullPath, handle->baseDir, sizeof(fullPath) - 1);
    fullPath[sizeof(fullPath) - 1] = '\0';
    NormalizePath(fullPath);
    
    // Check if we're at root - list virtual directories
    if (strcmp(fullPath, "/") == 0) {
        handle->listingVirtualRoots = TRUE;
        handle->virtualDirIndex = 0;
        
        // Find first non-hidden virtual directory
        while (handle->virtualDirIndex < g_VFSConfig->numVirtualDirs) {
            VirtualDir *vdir = &g_VFSConfig->virtualDirs[handle->virtualDirIndex];
            
            if (!vdir->hidden) {
                // Skip leading slash for display
                const char *name = vdir->virtualPath;
                if (*name == '/') name++;
                
                // Only show top-level virtual dirs at root
                if (strchr(name, '/') == NULL) {
                    strncpy(entry->name, name, sizeof(entry->name) - 1);
                    entry->name[sizeof(entry->name) - 1] = '\0';
                    entry->isDirectory = TRUE;
                    entry->isVirtualRoot = TRUE;
                    entry->size = 0;
                    entry->attributes = FILE_ATTRIBUTE_DIRECTORY;
                    GetSystemTimeAsFileTime(&entry->modTime);
                    
                    handle->virtualDirIndex++;
                    return handle;
                }
            }
            handle->virtualDirIndex++;
        }
        
        // No virtual directories to show
        free(handle);
        return NULL;
    }
    
    // Find virtual directory for this path
    vdirIndex = FindVirtualDir(fullPath);
    if (vdirIndex < 0) {
        free(handle);
        return NULL;
    }
    
    // Build physical search path
    char *physPath = VFS_TranslatePath(fullPath, ".");
    if (!physPath) {
        free(handle);
        return NULL;
    }
    
    snprintf(searchPath, sizeof(searchPath), "%s\\%s", physPath, handle->pattern);
    
    wideSearch = Utf8ToWide(searchPath);
    if (!wideSearch) {
        free(handle);
        return NULL;
    }
    
    handle->findHandle = FindFirstFileW(wideSearch, &handle->findData);
    FreeWideString(wideSearch);
    
    if (handle->findHandle == INVALID_HANDLE_VALUE) {
        free(handle);
        return NULL;
    }
    
    handle->listingPhysical = TRUE;
    
    // Skip . and ..
    while (wcscmp(handle->findData.cFileName, L".") == 0 ||
           wcscmp(handle->findData.cFileName, L"..") == 0) {
        if (!FindNextFileW(handle->findHandle, &handle->findData)) {
            FindClose(handle->findHandle);
            free(handle);
            return NULL;
        }
    }
    
    FillDirEntry(entry, &handle->findData);
    return handle;
}

//------------------------------------------------------------------------------------
// Get next directory entry
//------------------------------------------------------------------------------------
BOOL VFS_FindNext(VFS_FindHandle *handle, VFS_DirEntry *entry)
{
    if (!handle || !entry) return FALSE;
    
    // Listing virtual roots
    if (handle->listingVirtualRoots) {
        while (handle->virtualDirIndex < g_VFSConfig->numVirtualDirs) {
            VirtualDir *vdir = &g_VFSConfig->virtualDirs[handle->virtualDirIndex];
            handle->virtualDirIndex++;
            
            if (vdir->hidden) continue;
            
            const char *name = vdir->virtualPath;
            if (*name == '/') name++;
            
            // Only show top-level at root
            if (strchr(name, '/') == NULL) {
                strncpy(entry->name, name, sizeof(entry->name) - 1);
                entry->name[sizeof(entry->name) - 1] = '\0';
                entry->isDirectory = TRUE;
                entry->isVirtualRoot = TRUE;
                entry->size = 0;
                entry->attributes = FILE_ATTRIBUTE_DIRECTORY;
                GetSystemTimeAsFileTime(&entry->modTime);
                return TRUE;
            }
        }
        return FALSE;
    }
    
    // Listing physical directory
    if (handle->listingPhysical && handle->findHandle != INVALID_HANDLE_VALUE) {
        while (FindNextFileW(handle->findHandle, &handle->findData)) {
            // Skip . and ..
            if (wcscmp(handle->findData.cFileName, L".") == 0 ||
                wcscmp(handle->findData.cFileName, L"..") == 0) {
                continue;
            }
            
            FillDirEntry(entry, &handle->findData);
            return TRUE;
        }
    }
    
    return FALSE;
}

//------------------------------------------------------------------------------------
// Close find handle
//------------------------------------------------------------------------------------
void VFS_FindClose(VFS_FindHandle *handle)
{
    if (!handle) return;
    
    if (handle->findHandle != INVALID_HANDLE_VALUE) {
        FindClose(handle->findHandle);
    }
    
    free(handle);
}

//------------------------------------------------------------------------------------
// Create/open a file
//------------------------------------------------------------------------------------
HANDLE VFS_CreateFile(const char *currentDir, const char *filename,
                      DWORD access, DWORD shareMode, DWORD creation, DWORD flags)
{
    char *physPath;
    wchar_t *widePath;
    HANDLE handle;
    
    physPath = VFS_TranslatePath(currentDir, filename);
    if (!physPath) {
        SetLastError(ERROR_PATH_NOT_FOUND);
        return INVALID_HANDLE_VALUE;
    }
    
    widePath = Utf8ToWide(physPath);
    if (!widePath) {
        SetLastError(ERROR_INVALID_NAME);
        return INVALID_HANDLE_VALUE;
    }
    
    handle = CreateFileW(widePath, access, shareMode, NULL, creation, flags, NULL);
    FreeWideString(widePath);
    
    return handle;
}

//------------------------------------------------------------------------------------
// Delete a file
//------------------------------------------------------------------------------------
BOOL VFS_DeleteFile(const char *currentDir, const char *filename)
{
    char *physPath;
    wchar_t *widePath;
    BOOL result;
    
    physPath = VFS_TranslatePath(currentDir, filename);
    if (!physPath) {
        SetLastError(ERROR_PATH_NOT_FOUND);
        return FALSE;
    }
    
    widePath = Utf8ToWide(physPath);
    if (!widePath) {
        SetLastError(ERROR_INVALID_NAME);
        return FALSE;
    }
    
    result = DeleteFileW(widePath);
    FreeWideString(widePath);
    
    return result;
}

//------------------------------------------------------------------------------------
// Create a directory
//------------------------------------------------------------------------------------
BOOL VFS_CreateDirectory(const char *currentDir, const char *dirname)
{
    char *physPath;
    wchar_t *widePath;
    BOOL result;
    
    physPath = VFS_TranslatePath(currentDir, dirname);
    if (!physPath) {
        SetLastError(ERROR_PATH_NOT_FOUND);
        return FALSE;
    }
    
    widePath = Utf8ToWide(physPath);
    if (!widePath) {
        SetLastError(ERROR_INVALID_NAME);
        return FALSE;
    }
    
    result = CreateDirectoryW(widePath, NULL);
    FreeWideString(widePath);
    
    return result;
}

//------------------------------------------------------------------------------------
// Remove a directory
//------------------------------------------------------------------------------------
BOOL VFS_RemoveDirectory(const char *currentDir, const char *dirname)
{
    char *physPath;
    wchar_t *widePath;
    BOOL result;
    
    physPath = VFS_TranslatePath(currentDir, dirname);
    if (!physPath) {
        SetLastError(ERROR_PATH_NOT_FOUND);
        return FALSE;
    }
    
    widePath = Utf8ToWide(physPath);
    if (!widePath) {
        SetLastError(ERROR_INVALID_NAME);
        return FALSE;
    }
    
    result = RemoveDirectoryW(widePath);
    FreeWideString(widePath);
    
    return result;
}

//------------------------------------------------------------------------------------
// Move/rename a file
//------------------------------------------------------------------------------------
BOOL VFS_MoveFile(const char *currentDir, const char *oldName, const char *newName)
{
    char *oldPhys, *newPhys;
    char oldPhysCopy[MAX_PATH * 3];
    wchar_t *wideOld, *wideNew;
    BOOL result;
    
    oldPhys = VFS_TranslatePath(currentDir, oldName);
    if (!oldPhys) {
        SetLastError(ERROR_PATH_NOT_FOUND);
        return FALSE;
    }
    strncpy(oldPhysCopy, oldPhys, sizeof(oldPhysCopy) - 1);
    oldPhysCopy[sizeof(oldPhysCopy) - 1] = '\0';
    
    newPhys = VFS_TranslatePath(currentDir, newName);
    if (!newPhys) {
        SetLastError(ERROR_PATH_NOT_FOUND);
        return FALSE;
    }
    
    wideOld = Utf8ToWide(oldPhysCopy);
    wideNew = Utf8ToWide(newPhys);
    
    if (!wideOld || !wideNew) {
        if (wideOld) FreeWideString(wideOld);
        if (wideNew) FreeWideString(wideNew);
        SetLastError(ERROR_INVALID_NAME);
        return FALSE;
    }
    
    result = MoveFileW(wideOld, wideNew);
    FreeWideString(wideOld);
    FreeWideString(wideNew);
    
    return result;
}

//------------------------------------------------------------------------------------
// Get file information
//------------------------------------------------------------------------------------
BOOL VFS_GetFileInfo(const char *currentDir, const char *filename,
                     WIN32_FILE_ATTRIBUTE_DATA *info)
{
    char *physPath;
    wchar_t *widePath;
    BOOL result;
    
    physPath = VFS_TranslatePath(currentDir, filename);
    if (!physPath) {
        SetLastError(ERROR_PATH_NOT_FOUND);
        return FALSE;
    }
    
    widePath = Utf8ToWide(physPath);
    if (!widePath) {
        SetLastError(ERROR_INVALID_NAME);
        return FALSE;
    }
    
    result = GetFileAttributesExW(widePath, GetFileExInfoStandard, info);
    FreeWideString(widePath);
    
    return result;
}