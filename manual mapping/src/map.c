#include "map.h"

typedef unsigned __int64 QWORD;

typedef struct _IMAGE {
    BYTE *Data;
    DWORD Size;
    DWORD EntryPoint;
    IMAGE_DOS_HEADER *DosHeader;
    IMAGE_FILE_HEADER *FileHeader;
    IMAGE_OPTIONAL_HEADER *OptionalHeader;
    IMAGE_SECTION_HEADER *SectionHeader;
} IMAGE, *PIMAGE;

static IMAGE * PEInitialize(BYTE *lpData, DWORD dwSize) {
    IMAGE *lpImage = malloc(sizeof(IMAGE));

    lpImage->Data = lpData;
    lpImage->Size = dwSize;
    lpImage->DosHeader = (IMAGE_DOS_HEADER *)lpData;
    lpImage->FileHeader = (IMAGE_FILE_HEADER *)(lpData + lpImage->DosHeader->e_lfanew + sizeof(int));
    lpImage->OptionalHeader = (IMAGE_OPTIONAL_HEADER *)((BYTE *)lpImage->FileHeader + sizeof(IMAGE_FILE_HEADER));
    lpImage->SectionHeader = (IMAGE_SECTION_HEADER *)((BYTE *)lpImage->OptionalHeader + sizeof(IMAGE_OPTIONAL_HEADER));
    lpImage->EntryPoint = lpImage->OptionalHeader->AddressOfEntryPoint;

    return lpImage;
}

static DWORD RvaToOffset(IMAGE *lpImage, DWORD dwRva) {
    QWORD qwVirtualAddress = lpImage->OptionalHeader->ImageBase + dwRva;
    IMAGE_SECTION_HEADER *lpSectionHeader = lpImage->SectionHeader;

    for (int i = 0; i < lpImage->FileHeader->NumberOfSections; i++) {
        QWORD qwLow = lpSectionHeader->VirtualAddress + lpImage->OptionalHeader->ImageBase;
        QWORD qwHigh = qwLow + lpSectionHeader->Misc.VirtualSize;

        if (qwVirtualAddress <= qwHigh && qwVirtualAddress >= qwLow) {
            DWORD dwFileOffset = qwVirtualAddress - lpImage->OptionalHeader->ImageBase;
            dwFileOffset -= lpSectionHeader->VirtualAddress;
            dwFileOffset += lpSectionHeader->PointerToRawData;
            return dwFileOffset;
        }

        lpSectionHeader++;
    }

    return -1;
}

static void Relocate(HANDLE hProcess, BYTE *lpRemoteAlloc, IMAGE *lpImage) {
    DWORD dwRelocRva = lpImage->OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    DWORD dwRelocSize = lpImage->OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

    BYTE *lpDelta = lpRemoteAlloc - lpImage->OptionalHeader->ImageBase;

    if (dwRelocSize == 0 || lpDelta == 0) {
        return;
    }

    IMAGE_BASE_RELOCATION *lpBaseReloc = (IMAGE_BASE_RELOCATION *)(lpImage->Data + RvaToOffset(lpImage, dwRelocRva));

    while (lpBaseReloc->VirtualAddress != 0) {
        DWORD dwEntries = (lpBaseReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        WORD *lpEntry = (WORD *)((BYTE *)lpBaseReloc + sizeof(IMAGE_BASE_RELOCATION));

        for (int i = 0; i < dwEntries; i++) {
            if ((*(lpEntry + i) >> 0xC) == IMAGE_REL_BASED_DIR64) {
                DWORD dwEntryOffset = (*(lpEntry + i) & ~0xF000);
                DWORD dwEntryRva = lpBaseReloc->VirtualAddress + dwEntryOffset;
                BYTE *lpCorrectedVirtualAddress = lpRemoteAlloc + dwEntryRva;

                DWORD dwEntryFileOffset = RvaToOffset(lpImage, dwEntryRva);
                BYTE *lpCorrectedReloc = lpDelta + *(DWORD *)(lpImage->Data + dwEntryFileOffset);

                NtWriteVirtualMemory(hProcess, lpCorrectedVirtualAddress, &lpCorrectedReloc, sizeof(LPVOID), NULL);
            }
        }

        lpBaseReloc = (IMAGE_BASE_RELOCATION *)((BYTE *)lpBaseReloc + lpBaseReloc->SizeOfBlock);
    }
}

static void ResolveImports(HANDLE hProcess, BYTE *lpRemoteAlloc, IMAGE *lpImage) {
    DWORD dwImportRva = lpImage->OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    DWORD dwImportSize = lpImage->OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;

    if (dwImportSize == 0) {
        return;
    }

    IMAGE_IMPORT_DESCRIPTOR *lpDescriptor = (IMAGE_IMPORT_DESCRIPTOR *)(lpImage->Data + RvaToOffset(lpImage, dwImportRva));

    for (int i = 0; i < dwImportSize / sizeof(IMAGE_IMPORT_DESCRIPTOR) && lpDescriptor->Name != 0; i++) {
        HMODULE hDll = GetRemoteModuleHandle(GetProcessId(hProcess), (LPCTSTR)lpImage->Data + RvaToOffset(lpImage, lpDescriptor->Name));

        if (hDll == NULL) {
            lpDescriptor++;
            continue;
        }

        DWORD dwOftOffset = RvaToOffset(lpImage, lpDescriptor->OriginalFirstThunk);
        DWORD dwIndex = 0;

        IMAGE_THUNK_DATA *lpOft = (IMAGE_THUNK_DATA *)(lpImage->Data + dwOftOffset);

        while (lpOft->u1.AddressOfData != 0) {
            DWORD dwFunctionSymbolOffset = RvaToOffset(lpImage, lpOft->u1.AddressOfData);
            LPCTSTR szFunctionName = (LPCTSTR)lpImage->Data + dwFunctionSymbolOffset + sizeof(WORD);
            FARPROC lpFunction = GetRemoteProcAddress(hProcess, hDll, szFunctionName);

            if (lpFunction != NULL) {
                NtWriteVirtualMemory(
                    hProcess,
                    lpRemoteAlloc + lpDescriptor->FirstThunk + dwIndex * sizeof(LPVOID),
                    &lpFunction,
                    sizeof(LPVOID),
                    NULL
                );
            }

            dwIndex++;
            lpOft++;
        }

        lpDescriptor++;
    }
}

LPVOID ManuallyMapImage(HANDLE hProcess, BYTE *lpData, DWORD dwSize, LPVOID lpAddress, DWORD *lpEntryPoint) {
    IMAGE *lpImage = PEInitialize(lpData, dwSize);

    LPVOID lpRemoteAlloc = VirtualAllocEx(
                            hProcess,
                            lpAddress,
                            lpImage->OptionalHeader->SizeOfImage,
                            MEM_COMMIT | MEM_RESERVE,
                            PAGE_EXECUTE_READWRITE
                        );

    NtWriteVirtualMemory(
        hProcess,
        lpRemoteAlloc,
        lpImage->Data,
        lpImage->OptionalHeader->SizeOfHeaders,
        NULL
    );

    IMAGE_SECTION_HEADER *lpSectionHeader = lpImage->SectionHeader;

    for (int i = 0; i < lpImage->FileHeader->NumberOfSections; i++) {
        if (lpSectionHeader->SizeOfRawData != 0) {
            NtWriteVirtualMemory(
                hProcess,
                (BYTE *)lpRemoteAlloc + lpSectionHeader->VirtualAddress,
                lpImage->Data + lpSectionHeader->PointerToRawData,
                lpSectionHeader->SizeOfRawData,
                NULL
            );
        }

        lpSectionHeader++;
    }

    Relocate(hProcess, lpRemoteAlloc, lpImage);
    ResolveImports(hProcess, lpRemoteAlloc, lpImage);

    if (lpEntryPoint != NULL) {
        *lpEntryPoint = lpImage->OptionalHeader->AddressOfEntryPoint;
    }

    free(lpImage);
    return lpRemoteAlloc;
}
