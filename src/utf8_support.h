//------------------------------------------------------------------------------------
// UTF-8 Support Header for Windows FTP Server
//------------------------------------------------------------------------------------
#ifndef UTF8_SUPPORT_H
#define UTF8_SUPPORT_H

#include <windows.h>

// Convert UTF-8 string to Windows wide string (UTF-16)
wchar_t* Utf8ToWide(const char *utf8str);

// Convert Windows wide string (UTF-16) to UTF-8
char* WideToUtf8(const wchar_t *widestr);

// Convert local (ANSI/system codepage) string to UTF-8
char* LocalToUtf8(const char *localstr);

// Convert UTF-8 string to local (ANSI/system codepage)
char* Utf8ToLocal(const char *utf8str);

// Check if a string is valid UTF-8
BOOL IsValidUtf8(const char *str);

// Free allocated string
void FreeUtf8String(char *str);
void FreeWideString(wchar_t *str);

#endif // UTF8_SUPPORT_H