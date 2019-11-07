#include "remote.h"

LPVOID GetRemotePeb(HANDLE hProcess, PEB *lpProcessEnvironmentBlock) {
    PROCESS_BASIC_INFORMATION pbInfo = {0};

    NtQueryInformationProcess(
        hProcess,
        ProcessBasicInformation,
        &pbInfo,
        sizeof(PROCESS_BASIC_INFORMATION),
        NULL
    );

    NtReadVirtualMemory(
        hProcess,
        pbInfo.PebBaseAddress,
        lpProcessEnvironmentBlock,
        sizeof(PEB),
        NULL
    );

    return pbInfo.PebBaseAddress;
}

/*
DWORD GetNamedProcessId(LPCTSTR lpProcessName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 procEntry = {0};
    procEntry.dwSize = sizeof(PROCESSENTRY32);

    while (Process32Next(hSnapshot, &procEntry)) {
        if (!lstrcmpi(procEntry.szExeFile, lpProcessName)) {
            CloseHandle(hSnapshot);
            return procEntry.th32ProcessID;
        }
    }

    CloseHandle(hSnapshot);
    return 0;
}
*/

DWORD GetNamedProcessId(LPCSTR lpProcessName) {
    DWORD dwPid = 0;
    DWORD dwSize = 0;
    HANDLE hHeap = GetProcessHeap();

    ANSI_STRING ansiProcessName = {0};
    UNICODE_STRING unicodeProcessName = {0};
    RtlInitAnsiString(&ansiProcessName, lpProcessName);
    RtlAnsiStringToUnicodeString(&unicodeProcessName, &ansiProcessName, TRUE);

    NtQuerySystemInformation(SystemProcessInformation, NULL, 0, &dwSize);
    SYSTEM_PROCESS_INFORMATION *lpSystemProcessInfo = HeapAlloc(hHeap, 0, dwSize * 2);
    NtQuerySystemInformation(SystemProcessInformation, (LPVOID)lpSystemProcessInfo, dwSize, NULL);

    SYSTEM_PROCESS_INFORMATION *lpProcess = lpSystemProcessInfo;

    while (lpProcess->NextEntryOffset) {
        if (RtlEqualUnicodeString(&lpProcess->ImageName, &unicodeProcessName, TRUE) == TRUE) {
            dwPid = HandleToUlong(lpProcess->UniqueProcessId);
            break;
        }

        lpProcess = (SYSTEM_PROCESS_INFORMATION *)((BYTE *)lpProcess + lpProcess->NextEntryOffset);
    }

    HeapFree(hHeap, 0, lpSystemProcessInfo);
    HeapFree(hHeap, 0, unicodeProcessName.Buffer);
    return dwPid;
}

HANDLE GetProccessHandle(LPCTSTR lpProcessName, DWORD *lpPid, DWORD dwDesiredAccess) {
    DWORD dwPid = GetNamedProcessId(lpProcessName);

    if (lpPid != NULL) {
        *lpPid = dwPid;
    }

    return OpenProcess(dwDesiredAccess, 0, dwPid);
}

/*
HMODULE GetRemoteModuleHandle(DWORD dwPid, LPCTSTR lpModuleName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, dwPid);
    MODULEENTRY32 modEntry = {0};
    modEntry.dwSize = sizeof(MODULEENTRY32);

    while (Module32Next(hSnapshot, &modEntry)) {
        if (!lstrcmpi(modEntry.szModule, lpModuleName)) {
            CloseHandle(hSnapshot);
            return (HMODULE)modEntry.modBaseAddr;
        }
    }

    CloseHandle(hSnapshot);
    return 0;
}
*/

HMODULE GetRemoteModuleHandle(HANDLE hProcess, LPCTSTR lpModuleName) {
    ANSI_STRING ansiModuleName = {0};
    UNICODE_STRING unicodeModuleName = {0};
    RtlInitAnsiString(&ansiModuleName, lpModuleName);
    RtlAnsiStringToUnicodeString(&unicodeModuleName, &ansiModuleName, TRUE);

    PEB processEnvironmentBlock = {0};
    GetRemotePeb(hProcess, &processEnvironmentBlock);
    LPVOID lpInMemoryOrderModuleList = NULL;
    HANDLE hHeap = GetProcessHeap();

    NtReadVirtualMemory(
        hProcess,
        (BYTE *)processEnvironmentBlock.Ldr + sizeof(LPVOID) * 4,
        &lpInMemoryOrderModuleList,
        sizeof(LPVOID),
        NULL
    );

    LIST_ENTRY link = {0};
    link.Flink = lpInMemoryOrderModuleList;

    while (1) {
        LDR_DATA_TABLE_ENTRY entry = {0};

        NtReadVirtualMemory(
            hProcess,
            (BYTE *)link.Flink - sizeof(LIST_ENTRY),
            &entry,
            sizeof(LDR_DATA_TABLE_ENTRY),
            NULL
        );

        UNICODE_STRING *unicodeTmp = (UNICODE_STRING *)&entry.Reserved4[0];
        LPVOID lpStringAdress = unicodeTmp->Buffer;
        unicodeTmp->Buffer = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, unicodeTmp->MaximumLength);

        NtReadVirtualMemory(
            hProcess,
            lpStringAdress,
            unicodeTmp->Buffer,
            unicodeTmp->Length,
            NULL
        );

        if (RtlEqualUnicodeString(unicodeTmp, &unicodeModuleName, TRUE) == TRUE) {
            HeapFree(hHeap, 0, unicodeModuleName.Buffer);
            HeapFree(hHeap, HEAP_ZERO_MEMORY, unicodeTmp->Buffer);
            return entry.DllBase;
        }

        HeapFree(hHeap, HEAP_ZERO_MEMORY, unicodeTmp->Buffer);

        NtReadVirtualMemory(
            hProcess,
            link.Flink,
            &link,
            sizeof(LIST_ENTRY),
            NULL
        );

        if (link.Flink == lpInMemoryOrderModuleList) {
            break;
        }
    }

    HeapFree(hHeap, 0, unicodeModuleName.Buffer);
    return NULL;
}

FARPROC GetRemoteProcAddress(HANDLE hProcess, HMODULE hModule, LPCSTR lpProcName) {
    DWORD e_lfanew = 0;

    NtReadVirtualMemory(
        hProcess,
        (BYTE *)hModule + offsetof(IMAGE_DOS_HEADER, e_lfanew),
        &e_lfanew,
        sizeof(DWORD),
        NULL
    );

    if (e_lfanew == 0) {
        return NULL;
    }

    IMAGE_OPTIONAL_HEADER optionalHeader = {0};
    IMAGE_EXPORT_DIRECTORY exportDirectory = {0};

    NtReadVirtualMemory(
        hProcess,
        (BYTE *)hModule + e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER),
        &optionalHeader,
        sizeof(IMAGE_OPTIONAL_HEADER),
        NULL
    );

    NtReadVirtualMemory(
        hProcess,
        (BYTE *)hModule + optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress,
        &exportDirectory,
        sizeof(IMAGE_EXPORT_DIRECTORY),
        NULL
    );

    DWORD dwFunctionRva = 0;
    DWORD dwFunctionNameRva = 0;
    DWORD dwFunctionNameLen = 0;
    WORD wOrdinal = 0;
    BYTE c = 0;

    int left = 0;
    int right = exportDirectory.NumberOfNames;
    int middle = 0;

    while (left <= right) {
        middle = left + (right - left) / 2;

        NtReadVirtualMemory(
            hProcess,
            (BYTE *)hModule + exportDirectory.AddressOfNames + sizeof(DWORD) * middle,
            &dwFunctionNameRva,
            sizeof(DWORD),
            NULL
        );

        NtReadVirtualMemory(
            hProcess,
            (BYTE *)hModule + dwFunctionNameRva,
            &c,
            sizeof(BYTE),
            NULL
        );

        if (c == *lpProcName) {
            break;
        } else if (c > *lpProcName) {
            right = middle++;
        } else {
            left = middle--;
        }
    }

    int index = middle;

    while (index >= 0 && index < exportDirectory.NumberOfNames) {
        dwFunctionNameLen = 0;

        NtReadVirtualMemory(
            hProcess,
            (BYTE *)hModule + exportDirectory.AddressOfNames + sizeof(DWORD) * index,
            &dwFunctionNameRva,
            sizeof(DWORD),
            NULL
        );

        while (1) {
            NtReadVirtualMemory(
                hProcess,
                (BYTE *)hModule + dwFunctionNameRva + dwFunctionNameLen,
                &c,
                sizeof(BYTE),
                NULL
            );

            if (c == '\x00') {
                NtReadVirtualMemory(
                    hProcess,
                    (BYTE *)hModule + exportDirectory.AddressOfNameOrdinals + sizeof(WORD) * index,
                    &wOrdinal,
                    sizeof(WORD),
                    NULL
                );

                NtReadVirtualMemory(
                    hProcess,
                    (BYTE *)hModule + exportDirectory.AddressOfFunctions + wOrdinal * sizeof(DWORD),
                    &dwFunctionRva,
                    sizeof(DWORD),
                    NULL
                );

                return (FARPROC)((BYTE *)hModule + dwFunctionRva);
            } else if (c != *(lpProcName + dwFunctionNameLen)) {
                if (c < *(lpProcName + dwFunctionNameLen)) {
                    index += 1;
                } else {
                    index -= 1;
                }

                break;
            }

            dwFunctionNameLen++;
        }
    }

    printf("failed to resolve %s.\n", lpProcName);
    return NULL;
}
