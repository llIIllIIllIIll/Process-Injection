#include <windows.h>
#include <winternl.h>
#include <ntstatus.h>
#include <stdio.h>

typedef NTSTATUS (NTAPI *fnNtSetInformationThread)(HANDLE, THREADINFOCLASS, PVOID, ULONG);

NTSTATUS HookNtSetInformationThread (
    HANDLE ThreadHandle,
    THREADINFOCLASS ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength
);
