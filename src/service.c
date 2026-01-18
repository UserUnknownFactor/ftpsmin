//------------------------------------------------------------------------------------
// Windows Service Support Implementation
//------------------------------------------------------------------------------------
#include <windows.h>
#include <stdio.h>
#include "service.h"
#include "config.h"

extern ServerConfig g_Config;

static SERVICE_STATUS g_ServiceStatus;
static SERVICE_STATUS_HANDLE g_ServiceStatusHandle;
static HANDLE g_ServiceStopEvent = NULL;

//------------------------------------------------------------------------------------
// Report service status to SCM
//------------------------------------------------------------------------------------
static void ReportServiceStatus(DWORD currentState, DWORD exitCode, DWORD waitHint)
{
    static DWORD checkPoint = 1;
    
    g_ServiceStatus.dwCurrentState = currentState;
    g_ServiceStatus.dwWin32ExitCode = exitCode;
    g_ServiceStatus.dwWaitHint = waitHint;
    
    if (currentState == SERVICE_START_PENDING) {
        g_ServiceStatus.dwControlsAccepted = 0;
    } else {
        g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    }
    
    if (currentState == SERVICE_RUNNING || currentState == SERVICE_STOPPED) {
        g_ServiceStatus.dwCheckPoint = 0;
    } else {
        g_ServiceStatus.dwCheckPoint = checkPoint++;
    }
    
    SetServiceStatus(g_ServiceStatusHandle, &g_ServiceStatus);
}

//------------------------------------------------------------------------------------
// Service control handler
//------------------------------------------------------------------------------------
static void WINAPI ServiceCtrlHandler(DWORD control)
{
    switch (control) {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
            ReportServiceStatus(SERVICE_STOP_PENDING, NO_ERROR, 3000);
            g_ServiceStop = TRUE;
            if (g_ServiceStopEvent) {
                SetEvent(g_ServiceStopEvent);
            }
            return;
            
        case SERVICE_CONTROL_INTERROGATE:
            break;
            
        default:
            break;
    }
    
    ReportServiceStatus(g_ServiceStatus.dwCurrentState, NO_ERROR, 0);
}

//------------------------------------------------------------------------------------
// Service main function
//------------------------------------------------------------------------------------
static void WINAPI ServiceMain(DWORD argc, LPSTR *argv)
{
    // Register service control handler
    g_ServiceStatusHandle = RegisterServiceCtrlHandler(
        g_Config.serviceName[0] ? g_Config.serviceName : "ftpsmin",
        ServiceCtrlHandler);
    
    if (!g_ServiceStatusHandle) {
        return;
    }
    
    // Initialize service status
    g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_ServiceStatus.dwServiceSpecificExitCode = 0;
    
    // Create stop event
    g_ServiceStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    
    // Report starting
    ReportServiceStatus(SERVICE_START_PENDING, NO_ERROR, 3000);
    
    // Report running
    ReportServiceStatus(SERVICE_RUNNING, NO_ERROR, 0);
    
    // Run the server
    ServerMain();
    
    // Clean up
    if (g_ServiceStopEvent) {
        CloseHandle(g_ServiceStopEvent);
        g_ServiceStopEvent = NULL;
    }
    
    ReportServiceStatus(SERVICE_STOPPED, NO_ERROR, 0);
}

//------------------------------------------------------------------------------------
// Run as Windows service
//------------------------------------------------------------------------------------
void ServiceRun(void)
{
    SERVICE_TABLE_ENTRY serviceTable[] = {
        { g_Config.serviceName[0] ? g_Config.serviceName : "ftpsmin", ServiceMain },
        { NULL, NULL }
    };
    
    if (!StartServiceCtrlDispatcher(serviceTable)) {
        DWORD err = GetLastError();
        if (err == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
            // Not running as service, this shouldn't happen if -service was passed
            g_RunAsService = FALSE;
            ServerMain();
        }
    }
}

//------------------------------------------------------------------------------------
// Install the service
//------------------------------------------------------------------------------------
int ServiceInstall(void)
{
    SC_HANDLE schSCManager;
    SC_HANDLE schService;
    char path[MAX_PATH];
    char cmdLine[MAX_PATH + 64];
    SERVICE_DESCRIPTION sd;
    
    if (!GetModuleFileName(NULL, path, MAX_PATH)) {
        printf("Cannot get module file name (error %d)\n", GetLastError());
        return 1;
    }
    
    // Build command line with -service flag
    snprintf(cmdLine, sizeof(cmdLine), "\"%s\" -service", path);
    
    schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!schSCManager) {
        DWORD err = GetLastError();
        if (err == ERROR_ACCESS_DENIED) {
            printf("Access denied. Please run as Administrator.\n");
        } else {
            printf("OpenSCManager failed (error %d)\n", err);
        }
        return 1;
    }
    
    // Check if service already exists
    schService = OpenService(schSCManager,
                             g_Config.serviceName[0] ? g_Config.serviceName : "ftpsmin",
                             SERVICE_QUERY_STATUS);
    if (schService) {
        printf("Service already exists. Use -uninstall first to reinstall.\n");
        CloseServiceHandle(schService);
        CloseServiceHandle(schSCManager);
        return 1;
    }
    
    schService = CreateService(
        schSCManager,
        g_Config.serviceName[0] ? g_Config.serviceName : "ftpsmin",
        g_Config.serviceDisplayName[0] ? g_Config.serviceDisplayName : "FTPSMIN FTP Server",
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START,
        SERVICE_ERROR_NORMAL,
        cmdLine,
        NULL,       // No load ordering group
        NULL,       // No tag identifier
        NULL,       // No dependencies
        NULL,       // LocalSystem account
        NULL);      // No password
    
    if (!schService) {
        printf("CreateService failed (error %d)\n", GetLastError());
        CloseServiceHandle(schSCManager);
        return 1;
    }
    
    // Set service description
    sd.lpDescription = g_Config.serviceDescription[0] ? 
                       g_Config.serviceDescription : 
                       "Minimal secure FTP server";
    ChangeServiceConfig2(schService, SERVICE_CONFIG_DESCRIPTION, &sd);
    
    printf("Service installed successfully.\n");
    printf("  Name: %s\n", g_Config.serviceName[0] ? g_Config.serviceName : "ftpsmin");
    printf("  Display Name: %s\n", g_Config.serviceDisplayName[0] ? 
           g_Config.serviceDisplayName : "FTPSMIN FTP Server");
    printf("\nUse 'ftpsmin -start' to start the service.\n");
    
    CloseServiceHandle(schService);
    CloseServiceHandle(schSCManager);
    return 0;
}

//------------------------------------------------------------------------------------
// Uninstall the service
//------------------------------------------------------------------------------------
int ServiceUninstall(void)
{
    SC_HANDLE schSCManager;
    SC_HANDLE schService;
    SERVICE_STATUS status;
    
    schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!schSCManager) {
        DWORD err = GetLastError();
        if (err == ERROR_ACCESS_DENIED) {
            printf("Access denied. Please run as Administrator.\n");
        } else {
            printf("OpenSCManager failed (error %d)\n", err);
        }
        return 1;
    }
    
    schService = OpenService(schSCManager,
                             g_Config.serviceName[0] ? g_Config.serviceName : "ftpsmin",
                             SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS);
    
    if (!schService) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_DOES_NOT_EXIST) {
            printf("Service is not installed.\n");
        } else {
            printf("OpenService failed (error %d)\n", err);
        }
        CloseServiceHandle(schSCManager);
        return 1;
    }
    
    // Stop the service if running
    if (ControlService(schService, SERVICE_CONTROL_STOP, &status)) {
        printf("Stopping service...\n");
        Sleep(1000);
        
        while (QueryServiceStatus(schService, &status)) {
            if (status.dwCurrentState == SERVICE_STOP_PENDING) {
                printf(".");
                Sleep(1000);
            } else {
                break;
            }
        }
        printf("\n");
        
        if (status.dwCurrentState == SERVICE_STOPPED) {
            printf("Service stopped.\n");
        } else {
            printf("Service did not stop cleanly.\n");
        }
    }
    
    if (!DeleteService(schService)) {
        printf("DeleteService failed (error %d)\n", GetLastError());
        CloseServiceHandle(schService);
        CloseServiceHandle(schSCManager);
        return 1;
    }
    
    printf("Service uninstalled successfully.\n");
    
    CloseServiceHandle(schService);
    CloseServiceHandle(schSCManager);
    return 0;
}

//------------------------------------------------------------------------------------
// Start the service
//------------------------------------------------------------------------------------
int ServiceStart(void)
{
    SC_HANDLE schSCManager;
    SC_HANDLE schService;
    SERVICE_STATUS_PROCESS status;
    DWORD bytesNeeded;
    DWORD startTickCount;
    DWORD oldCheckPoint;
    DWORD waitTime;
    
    schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!schSCManager) {
        DWORD err = GetLastError();
        if (err == ERROR_ACCESS_DENIED) {
            printf("Access denied. Please run as Administrator.\n");
        } else {
            printf("OpenSCManager failed (error %d)\n", err);
        }
        return 1;
    }
    
    schService = OpenService(schSCManager,
                             g_Config.serviceName[0] ? g_Config.serviceName : "ftpsmin",
                             SERVICE_START | SERVICE_QUERY_STATUS);
    
    if (!schService) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_DOES_NOT_EXIST) {
            printf("Service is not installed. Use -install first.\n");
        } else {
            printf("OpenService failed (error %d)\n", err);
        }
        CloseServiceHandle(schSCManager);
        return 1;
    }
    
    // Check if already running
    if (!QueryServiceStatusEx(schService, SC_STATUS_PROCESS_INFO,
                              (LPBYTE)&status, sizeof(status), &bytesNeeded)) {
        printf("QueryServiceStatusEx failed (error %d)\n", GetLastError());
        CloseServiceHandle(schService);
        CloseServiceHandle(schSCManager);
        return 1;
    }
    
    if (status.dwCurrentState != SERVICE_STOPPED && 
        status.dwCurrentState != SERVICE_STOP_PENDING) {
        printf("Service is already running.\n");
        CloseServiceHandle(schService);
        CloseServiceHandle(schSCManager);
        return 0;
    }
    
    // Wait for service to stop if pending
    while (status.dwCurrentState == SERVICE_STOP_PENDING) {
        Sleep(1000);
        if (!QueryServiceStatusEx(schService, SC_STATUS_PROCESS_INFO,
                                  (LPBYTE)&status, sizeof(status), &bytesNeeded)) {
            break;
        }
    }
    
    // Start the service
    if (!StartService(schService, 0, NULL)) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_ALREADY_RUNNING) {
            printf("Service is already running.\n");
        } else {
            printf("StartService failed (error %d)\n", err);
            CloseServiceHandle(schService);
            CloseServiceHandle(schSCManager);
            return 1;
        }
    } else {
        printf("Starting service...\n");
    }
    
    // Wait for service to start
    if (!QueryServiceStatusEx(schService, SC_STATUS_PROCESS_INFO,
                              (LPBYTE)&status, sizeof(status), &bytesNeeded)) {
        printf("QueryServiceStatusEx failed (error %d)\n", GetLastError());
        CloseServiceHandle(schService);
        CloseServiceHandle(schSCManager);
        return 1;
    }
    
    startTickCount = GetTickCount();
    oldCheckPoint = status.dwCheckPoint;
    
    while (status.dwCurrentState == SERVICE_START_PENDING) {
        waitTime = status.dwWaitHint / 10;
        if (waitTime < 1000) waitTime = 1000;
        if (waitTime > 10000) waitTime = 10000;
        
        Sleep(waitTime);
        
        if (!QueryServiceStatusEx(schService, SC_STATUS_PROCESS_INFO,
                                  (LPBYTE)&status, sizeof(status), &bytesNeeded)) {
            printf("QueryServiceStatusEx failed (error %d)\n", GetLastError());
            break;
        }
        
        if (status.dwCheckPoint > oldCheckPoint) {
            startTickCount = GetTickCount();
            oldCheckPoint = status.dwCheckPoint;
        } else {
            if (GetTickCount() - startTickCount > status.dwWaitHint) {
                printf("Timeout waiting for service to start.\n");
                break;
            }
        }
    }
    
    if (status.dwCurrentState == SERVICE_RUNNING) {
        printf("Service started successfully.\n");
        CloseServiceHandle(schService);
        CloseServiceHandle(schSCManager);
        return 0;
    } else {
        printf("Service failed to start.\n");
        CloseServiceHandle(schService);
        CloseServiceHandle(schSCManager);
        return 1;
    }
}

//------------------------------------------------------------------------------------
// Stop the service
//------------------------------------------------------------------------------------
int ServiceStop(void)
{
    SC_HANDLE schSCManager;
    SC_HANDLE schService;
    SERVICE_STATUS_PROCESS status;
    DWORD bytesNeeded;
    DWORD startTickCount;
    DWORD waitTime;
    
    schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!schSCManager) {
        DWORD err = GetLastError();
        if (err == ERROR_ACCESS_DENIED) {
            printf("Access denied. Please run as Administrator.\n");
        } else {
            printf("OpenSCManager failed (error %d)\n", err);
        }
        return 1;
    }
    
    schService = OpenService(schSCManager,
                             g_Config.serviceName[0] ? g_Config.serviceName : "ftpsmin",
                             SERVICE_STOP | SERVICE_QUERY_STATUS);
    
    if (!schService) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_DOES_NOT_EXIST) {
            printf("Service is not installed.\n");
        } else {
            printf("OpenService failed (error %d)\n", err);
        }
        CloseServiceHandle(schSCManager);
        return 1;
    }
    
    // Check current status
    if (!QueryServiceStatusEx(schService, SC_STATUS_PROCESS_INFO,
                              (LPBYTE)&status, sizeof(status), &bytesNeeded)) {
        printf("QueryServiceStatusEx failed (error %d)\n", GetLastError());
        CloseServiceHandle(schService);
        CloseServiceHandle(schSCManager);
        return 1;
    }
    
    if (status.dwCurrentState == SERVICE_STOPPED) {
        printf("Service is already stopped.\n");
        CloseServiceHandle(schService);
        CloseServiceHandle(schSCManager);
        return 0;
    }
    
    // Send stop control
    printf("Stopping service...\n");
    if (!ControlService(schService, SERVICE_CONTROL_STOP, (SERVICE_STATUS*)&status)) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_NOT_ACTIVE) {
            printf("Service is not running.\n");
            CloseServiceHandle(schService);
            CloseServiceHandle(schSCManager);
            return 0;
        }
        printf("ControlService failed (error %d)\n", err);
        CloseServiceHandle(schService);
        CloseServiceHandle(schSCManager);
        return 1;
    }
    
    // Wait for service to stop
    startTickCount = GetTickCount();
    
    while (status.dwCurrentState != SERVICE_STOPPED) {
        waitTime = status.dwWaitHint / 10;
        if (waitTime < 1000) waitTime = 1000;
        if (waitTime > 10000) waitTime = 10000;
        
        Sleep(waitTime);
        
        if (!QueryServiceStatusEx(schService, SC_STATUS_PROCESS_INFO,
                                  (LPBYTE)&status, sizeof(status), &bytesNeeded)) {
            printf("QueryServiceStatusEx failed (error %d)\n", GetLastError());
            break;
        }
        
        if (GetTickCount() - startTickCount > 30000) {
            printf("Timeout waiting for service to stop.\n");
            break;
        }
    }
    
    if (status.dwCurrentState == SERVICE_STOPPED) {
        printf("Service stopped successfully.\n");
        CloseServiceHandle(schService);
        CloseServiceHandle(schSCManager);
        return 0;
    } else {
        printf("Service did not stop.\n");
        CloseServiceHandle(schService);
        CloseServiceHandle(schSCManager);
        return 1;
    }
}