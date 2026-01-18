//------------------------------------------------------------------------------------
// UTF-8 Support Implementation for Windows FTP Server
//------------------------------------------------------------------------------------
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "utf8_support.h"

//------------------------------------------------------------------------------------
// Convert UTF-8 string to Windows wide string (UTF-16)
//------------------------------------------------------------------------------------
wchar_t* Utf8ToWide(const char *utf8str)
{
    int len;
    wchar_t *widestr;
    
    if (!utf8str) return NULL;
    if (*utf8str == '\0') {
        widestr = (wchar_t*)malloc(sizeof(wchar_t));
        if (widestr) widestr[0] = L'\0';
        return widestr;
    }
    
    len = MultiByteToWideChar(CP_UTF8, 0, utf8str, -1, NULL, 0);
    if (len == 0) return NULL;
    
    widestr = (wchar_t*)malloc(len * sizeof(wchar_t));
    if (!widestr) return NULL;
    
    if (MultiByteToWideChar(CP_UTF8, 0, utf8str, -1, widestr, len) == 0) {
        free(widestr);
        return NULL;
    }
    
    return widestr;
}

//------------------------------------------------------------------------------------
// Convert Windows wide string (UTF-16) to UTF-8
//------------------------------------------------------------------------------------
char* WideToUtf8(const wchar_t *widestr)
{
    int len;
    char *utf8str;
    
    if (!widestr) return NULL;
    if (*widestr == L'\0') {
        utf8str = (char*)malloc(1);
        if (utf8str) utf8str[0] = '\0';
        return utf8str;
    }
    
    len = WideCharToMultiByte(CP_UTF8, 0, widestr, -1, NULL, 0, NULL, NULL);
    if (len == 0) return NULL;
    
    utf8str = (char*)malloc(len);
    if (!utf8str) return NULL;
    
    if (WideCharToMultiByte(CP_UTF8, 0, widestr, -1, utf8str, len, NULL, NULL) == 0) {
        free(utf8str);
        return NULL;
    }
    
    return utf8str;
}

//------------------------------------------------------------------------------------
// Convert local (ANSI/system codepage) string to UTF-8
//------------------------------------------------------------------------------------
char* LocalToUtf8(const char *localstr)
{
    wchar_t *widestr;
    char *utf8str;
    int len;
    
    if (!localstr) return NULL;
    
    // First convert from local codepage to wide
    len = MultiByteToWideChar(CP_ACP, 0, localstr, -1, NULL, 0);
    if (len == 0) return NULL;
    
    widestr = (wchar_t*)malloc(len * sizeof(wchar_t));
    if (!widestr) return NULL;
    
    if (MultiByteToWideChar(CP_ACP, 0, localstr, -1, widestr, len) == 0) {
        free(widestr);
        return NULL;
    }
    
    // Then convert from wide to UTF-8
    utf8str = WideToUtf8(widestr);
    free(widestr);
    
    return utf8str;
}

//------------------------------------------------------------------------------------
// Convert UTF-8 string to local (ANSI/system codepage)
//------------------------------------------------------------------------------------
char* Utf8ToLocal(const char *utf8str)
{
    wchar_t *widestr;
    char *localstr;
    int len;
    
    if (!utf8str) return NULL;
    
    // First convert from UTF-8 to wide
    widestr = Utf8ToWide(utf8str);
    if (!widestr) return NULL;
    
    // Then convert from wide to local codepage
    len = WideCharToMultiByte(CP_ACP, 0, widestr, -1, NULL, 0, NULL, NULL);
    if (len == 0) {
        free(widestr);
        return NULL;
    }
    
    localstr = (char*)malloc(len);
    if (!localstr) {
        free(widestr);
        return NULL;
    }
    
    if (WideCharToMultiByte(CP_ACP, 0, widestr, -1, localstr, len, "?", NULL) == 0) {
        free(widestr);
        free(localstr);
        return NULL;
    }
    
    free(widestr);
    return localstr;
}

//------------------------------------------------------------------------------------
// Check if a string is valid UTF-8
//------------------------------------------------------------------------------------
BOOL IsValidUtf8(const char *str)
{
    const unsigned char *bytes = (const unsigned char*)str;
    
    if (!str) return FALSE;
    
    while (*bytes) {
        if (bytes[0] <= 0x7F) {
            // ASCII character (0xxxxxxx)
            bytes++;
        } else if ((bytes[0] & 0xE0) == 0xC0) {
            // 2-byte sequence (110xxxxx 10xxxxxx)
            if ((bytes[1] & 0xC0) != 0x80) return FALSE;
            // Check for overlong encoding
            if ((bytes[0] & 0xFE) == 0xC0) return FALSE;
            bytes += 2;
        } else if ((bytes[0] & 0xF0) == 0xE0) {
            // 3-byte sequence (1110xxxx 10xxxxxx 10xxxxxx)
            if ((bytes[1] & 0xC0) != 0x80) return FALSE;
            if ((bytes[2] & 0xC0) != 0x80) return FALSE;
            // Check for overlong encoding
            if (bytes[0] == 0xE0 && (bytes[1] & 0xE0) == 0x80) return FALSE;
            // Check for surrogate pairs (invalid in UTF-8)
            if (bytes[0] == 0xED && (bytes[1] & 0xE0) == 0xA0) return FALSE;
            bytes += 3;
        } else if ((bytes[0] & 0xF8) == 0xF0) {
            // 4-byte sequence (11110xxx 10xxxxxx 10xxxxxx 10xxxxxx)
            if ((bytes[1] & 0xC0) != 0x80) return FALSE;
            if ((bytes[2] & 0xC0) != 0x80) return FALSE;
            if ((bytes[3] & 0xC0) != 0x80) return FALSE;
            // Check for overlong encoding
            if (bytes[0] == 0xF0 && (bytes[1] & 0xF0) == 0x80) return FALSE;
            // Check for values > U+10FFFF
            if (bytes[0] > 0xF4) return FALSE;
            if (bytes[0] == 0xF4 && bytes[1] > 0x8F) return FALSE;
            bytes += 4;
        } else {
            // Invalid UTF-8 byte
            return FALSE;
        }
    }
    
    return TRUE;
}

//------------------------------------------------------------------------------------
// Free allocated UTF-8 string
//------------------------------------------------------------------------------------
void FreeUtf8String(char *str)
{
    if (str) free(str);
}

//------------------------------------------------------------------------------------
// Free allocated wide string
//------------------------------------------------------------------------------------
void FreeWideString(wchar_t *str)
{
    if (str) free(str);
}