//------------------------------------------------------------------------------------
// Windows Service Support Header
//------------------------------------------------------------------------------------
#ifndef SERVICE_H
#define SERVICE_H

#include <windows.h>

// Service control functions
int ServiceInstall(void);
int ServiceUninstall(void);
int ServiceStart(void);
int ServiceStop(void);
void ServiceRun(void);

// Globals shared between service and main
extern BOOL g_RunAsService;
extern BOOL g_ServiceStop;

// Main server function (called by service or console mode)
extern void ServerMain(void);

#endif // SERVICE_H