#include <windows.h>

#include "hook.h"

LPVOID CreateHook(HANDLE hProcess, FARPROC lpFunction, FARPROC lpHook);

int main(void) {
    HANDLE hProcess = GetCurrentProcess();
    HMODULE hModule = LoadLibrary("ntdll.dll");
    fnNtSetInformationThread lpNtSetInformationThread = (fnNtSetInformationThread)GetProcAddress(hModule, "NtSetInformationThread");

    HMODULE hHookDll = LoadLibrary("hook.dll");
    LPVOID lpHookNtSetInformationThread = GetProcAddress(hHookDll, "HookNtSetInformationThread");
    LPVOID lpHookReturn = GetProcAddress(hHookDll, "lpHookReturn");
    LPVOID lpTrampoline = CreateHook(hProcess, (LPVOID)lpNtSetInformationThread, lpHookNtSetInformationThread);

    WriteProcessMemory(hProcess, (LPVOID)lpHookReturn, &lpTrampoline, sizeof(FARPROC *), NULL);

    lpNtSetInformationThread(GetCurrentThread(), ThreadHideFromDebugger, NULL, 0);
    return 0;
}

LPVOID CreateHook(HANDLE hProcess, FARPROC lpFunction, FARPROC lpHook) {
    BYTE pivot[] = {0x90, 0x90, 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00};
    BYTE trampoline[(sizeof(pivot) + sizeof(FARPROC *)) * 2];

    LPVOID lpTrampoline = VirtualAllocEx(hProcess, NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    LPVOID lpDetour = (BYTE *)lpFunction + sizeof(pivot) + sizeof(FARPROC *);

    ReadProcessMemory(hProcess, (BYTE *)lpFunction, trampoline, sizeof(pivot) + sizeof(FARPROC *), NULL);

    memcpy(trampoline + sizeof(pivot) + sizeof(FARPROC *), pivot, sizeof(pivot));
    memcpy(trampoline + sizeof(pivot) * 2 + sizeof(FARPROC *), &lpDetour, sizeof(FARPROC *));

    WriteProcessMemory(hProcess, lpTrampoline, trampoline, sizeof(trampoline), NULL);
    WriteProcessMemory(hProcess, (BYTE *)lpFunction, pivot, sizeof(pivot), NULL);
    WriteProcessMemory(hProcess, (BYTE *)lpFunction + sizeof(pivot), &lpHook, sizeof(FARPROC *), NULL);

    return lpTrampoline;
}
