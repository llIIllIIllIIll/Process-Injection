#include <windows.h>
#include <stdio.h>

#include "../remote.h"

LPVOID GetFunctionVirtualAddress(HANDLE hProcess, HMODULE hModule, LPVOID lpFunction);

int main(void) {
    LPCSTR lpProcessName = "notepad.exe";
    DWORD dwDesiredAccess = PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION;
    HANDLE hProcess = GetProccessHandle(lpProcessName, NULL, dwDesiredAccess);

    if (hProcess == NULL) {
        return 0;
    }

    HMODULE hModule = GetRemoteModuleHandle(hProcess, lpProcessName);
    HMODULE hKernelbase = GetRemoteModuleHandle(hProcess, "kernelbase.dll");
    HMODULE hKernel32 = GetRemoteModuleHandle(hProcess, "kernel32.dll");

    LPVOID lpFormatMessageW = GetRemoteProcAddress(hProcess, hKernelbase, "FormatMessageW");
    LPVOID lpExitProcess = GetRemoteProcAddress(hProcess, hKernel32, "ExitProcess");

    LPVOID lpVirtualAddress = GetFunctionVirtualAddress(hProcess, hModule, lpFormatMessageW);

    DWORD dwOldProtection = 0;
    VirtualProtectEx(hProcess, lpVirtualAddress, sizeof(LPVOID), PAGE_EXECUTE_READWRITE, &dwOldProtection);
    NtWriteVirtualMemory(hProcess, lpVirtualAddress, &lpExitProcess, sizeof(LPVOID), NULL);
    VirtualProtectEx(hProcess, lpVirtualAddress, sizeof(LPVOID), dwOldProtection, &dwOldProtection);

    CloseHandle(hProcess);
    return 0;
}

LPVOID GetFunctionVirtualAddress(HANDLE hProcess, HMODULE hModule, LPVOID lpFunction) {
    HANDLE hHeap = GetProcessHeap();

    BYTE *lpData = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, 0x1000);
    NtReadVirtualMemory(hProcess, hModule, lpData, 0x1000, NULL);

    IMAGE_DOS_HEADER *lpDosHeader = (IMAGE_DOS_HEADER *)lpData;
    IMAGE_NT_HEADERS *lpNtHeaders = (IMAGE_NT_HEADERS *)(lpData + lpDosHeader->e_lfanew);

    DWORD dwIatSize = lpNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
    DWORD dwIatRva = lpNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

    IMAGE_IMPORT_DESCRIPTOR descriptor = {0};

    for (int i = 0; i < dwIatSize / sizeof(IMAGE_IMPORT_DESCRIPTOR); i++) {
        NtReadVirtualMemory(
            hProcess, (BYTE *)hModule + dwIatRva + sizeof(IMAGE_IMPORT_DESCRIPTOR) * i,
            &descriptor,
            sizeof(IMAGE_IMPORT_DESCRIPTOR),
            NULL
        );

        if (descriptor.Name != 0) {
            LPVOID lpFirstThunk = (BYTE *)hModule + descriptor.FirstThunk;

            DWORD dwFunctionOffset = 0;
            LPVOID lpResolvedFunction = 0;

            while (1) {
                NtReadVirtualMemory(
                    hProcess, (BYTE *)lpFirstThunk + dwFunctionOffset * sizeof(LPVOID),
                    &lpResolvedFunction,
                    sizeof(LPVOID),
                    NULL
                );

                if (lpResolvedFunction == NULL) {
                    break;
                } else if (lpFunction == lpResolvedFunction) {
                    HeapFree(hHeap, 0, lpData);
                    return (BYTE *)lpFirstThunk + dwFunctionOffset * sizeof(LPVOID);
                }

                dwFunctionOffset++;
            }
        } else {
            break;
        }
    }

    HeapFree(hHeap, 0, lpData);
    return NULL;
}
