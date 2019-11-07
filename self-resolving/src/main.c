#include "resolve.h"

fnGetProcAddress lpGetProcAddress = NULL;
fnLoadLibrary lpLoadLibraryA = NULL;
fnExitProcess lpExitProcess = NULL;

void _start() {
    __asm (
        "call _main"
    );

    lpExitProcess(0);
}

int _main(void) {
    PEB *lpPeb = GetPEB();
    HMODULE hKernel32 = NULL;

    if ((hKernel32 = GetModule(lpPeb, 0x951960FD)) == NULL) {
        if ((hKernel32 = GetModule(lpPeb, 0x6674ACE1)) == NULL) {
            return -1;
        }
    }

    lpGetProcAddress = (fnGetProcAddress)ResolveFunction(hKernel32, 0x3683E000);
    lpLoadLibraryA = (fnLoadLibrary)ResolveFunction(hKernel32, 0xC03E4272);

    lpExitProcess = (fnExitProcess)lpGetProcAddress(hKernel32, "ExitProcess");

    return 0;
}

PEB * GetPEB(void) {
    register PEB *lpPeb __asm__ ("rax");

    __asm (
        "mov rax, qword ptr gs:[0x30];"
        "mov rax, qword ptr ds:[rax + 0x60]"
    );

    return lpPeb;
}

HMODULE GetModule(PEB *lpPeb, DWORD hash) {
    PEB_LDR_DATA *lpPebLdrData = (PEB_LDR_DATA *)lpPeb->Ldr;
    LIST_ENTRY moduleList = lpPebLdrData->InMemoryOrderModuleList;
    LIST_ENTRY *lpLink = moduleList.Flink;

    while (lpLink->Flink != moduleList.Flink) {
        LDR_DATA_TABLE_ENTRY *lpEntry = (LDR_DATA_TABLE_ENTRY *)(lpLink - 1);
        lpLink = lpLink->Flink;

        if (crc32((BYTE *)((UNICODE_STRING)lpEntry->BaseDllName).Buffer, 1) == hash) {
            return lpEntry->DllBase;
        }
    }

    return NULL;
}

FARPROC ResolveFunction(HMODULE hModule, DWORD hash) {
    IMAGE_DOS_HEADER *lpDosHeader = (IMAGE_DOS_HEADER *)hModule;
    IMAGE_NT_HEADERS *lpNtHeaders = (IMAGE_NT_HEADERS *)((BYTE *)hModule + lpDosHeader->e_lfanew);

    DWORD exportDirRva = (lpNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]).VirtualAddress;
    IMAGE_EXPORT_DIRECTORY *lpExportDir = (IMAGE_EXPORT_DIRECTORY *)((BYTE *)hModule + exportDirRva);

    for (int i = 0; i < lpExportDir->NumberOfNames; i++) {
        DWORD functionRva = 0;
        DWORD nameRva = 0;
        DWORD ordinal = 0;

        nameRva = *(DWORD *)((BYTE *)hModule + lpExportDir->AddressOfNames + sizeof(DWORD) * i);

        if (crc32((BYTE *)hModule + nameRva, 0) == hash) {
            ordinal = *(WORD *)((BYTE *)hModule + lpExportDir->AddressOfNameOrdinals + sizeof(WORD) * i);
            functionRva = *(DWORD *)((BYTE *)hModule + lpExportDir->AddressOfFunctions + ordinal * sizeof(DWORD));
            return (FARPROC)((BYTE *)hModule + functionRva);
        }
    }

    return NULL;
}

DWORD crc32(BYTE *lpData, BOOL bWide) {
    BYTE *ptr = lpData;
    DWORD crc = 0xFFFFFFFF;
    DWORD idx = sizeof(BYTE);

    if (bWide == 1) {
        idx = sizeof(WORD);
    }

    while (*ptr != '\x00') {
        crc = crc ^ *ptr;
        for (int j = 0; j < 8; j++) {
            crc = (crc >> 1) ^ (0xEDB88320 & ~((crc & 1) - 1));
        }
        ptr += idx;
    }

    return crc;
}
