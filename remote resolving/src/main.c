#include <windows.h>
#include <stdio.h>

#include "remote.h"

int main(void) {
    LPCTSTR lpProcessName = "notepad.exe";
    LPCTSTR lpModuleName = "kernel32.dll";

    DWORD dwDesiredAccess = PROCESS_VM_READ | PROCESS_QUERY_INFORMATION;
    HANDLE hProcess = GetProccessHandle(lpProcessName, NULL, dwDesiredAccess);
    HMODULE hModule = GetRemoteModuleHandle(hProcess, lpModuleName);

    if (hProcess == NULL || hModule == NULL) {
        return 0;
    }

    FARPROC pLoadLibraryA = GetRemoteProcAddress(hProcess, hModule, "LoadLibraryA");
    FARPROC pGetProcAddress = GetRemoteProcAddress(hProcess, hModule, "GetProcAddress");

    printf("%p\n", pLoadLibraryA);
    printf("%p\n", pGetProcAddress);

    CloseHandle(hProcess);
    return 0;
}
