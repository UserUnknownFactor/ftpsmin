# Makefile for ftpsmin with OpenSSL support
# For Visual Studio: nmake
# For MinGW: mingw32-make -f Makefile.mingw

# Visual Studio settings
CC = cl
LINK = link
RC = rc

# Compiler flags
# /MT = static C runtime (no VCRUNTIME/MSVCRT DLL dependency)
CFLAGS = /nologo /O2 /W3 /MT /D_CRT_SECURE_NO_WARNINGS /DWIN32 /D_WINDOWS

# OpenSSL paths
OPENSSL_DIR = .\opnssl
OPENSSL_INC = $(OPENSSL_DIR)\include

# Choose runtime: MDd (debug dynamic), MD (dynamic), MTd (debug static), MT (static)
# Must match the /MT or /MD flag above
RUNTIME = MT

# Architecture: x64 or x86
!IF "$(PLATFORM)" == "x86"
ARCH = x86
!ELSE
ARCH = x64
!ENDIF

# OpenSSL library path
OPENSSL_LIBRARY = $(OPENSSL_DIR)\lib\VC\$(ARCH)\$(RUNTIME)

# Include paths
INCLUDES = /I"$(OPENSSL_INC)"

# System libraries (required by static OpenSSL)
SYSLIBS = ws2_32.lib advapi32.lib user32.lib crypt32.lib gdi32.lib

# OpenSSL static libraries
# Use libssl_static.lib if available, otherwise libssl.lib from MT folder
!IF EXIST("$(OPENSSL_LIBRARY)\libssl_static.lib")
SSLLIBS = "$(OPENSSL_LIBRARY)\libssl_static.lib" "$(OPENSSL_LIBRARY)\libcrypto_static.lib"
!ELSE
SSLLIBS = "$(OPENSSL_LIBRARY)\libssl.lib" "$(OPENSSL_LIBRARY)\libcrypto.lib"
!ENDIF

LIBS = $(SYSLIBS) $(SSLLIBS)

# Linker flags
LDFLAGS = /nologo /subsystem:console

# Source files
SOURCES = ftpsmin.c config.c service.c ssl_support.c utf8_support.c vfs.c

# Object files
OBJECTS = ftpsmin.obj config.obj service.obj ssl_support.obj utf8_support.obj vfs.obj

# Target
TARGET = ftpsmin.exe

# Default target
all: info $(TARGET)
	@echo.
	@echo Build complete. Checking dependencies:
	@dumpbin /dependents $(TARGET) | findstr /i ".dll"

info:
	@echo ========================================
	@echo Building for $(ARCH) with /$(RUNTIME) runtime
	@echo OpenSSL lib path: $(OPENSSL_LIBRARY)
	@echo ========================================

$(TARGET): $(OBJECTS)
	$(LINK) $(LDFLAGS) /out:$@ $(OBJECTS) $(LIBS)

# Compile rules
.c.obj:
	$(CC) $(CFLAGS) $(INCLUDES) /c $<

# Dependencies
ftpsmin.obj: ftpsmin.c config.h service.h ssl_support.h utf8_support.h vfs.h
config.obj: config.c config.h
service.obj: service.c service.h config.h
ssl_support.obj: ssl_support.c ssl_support.h
utf8_support.obj: utf8_support.c utf8_support.h
vfs.obj: vfs.c vfs.h config.h utf8_support.h

# Clean
clean:
	-del *.obj 2>nul
	-del $(TARGET) 2>nul

# Check dependencies
check:
	@echo Dependencies for $(TARGET):
	@dumpbin /dependents $(TARGET)

.PHONY: all clean info check