#include "hook.h"

fnNtSetInformationThread lpHookReturn = NULL;

NTSTATUS HookNtSetInformationThread(
    HANDLE ThreadHandle,
    THREADINFOCLASS ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength) {
    MessageBoxA(NULL, "function hooked.", NULL, 0);
    return lpHookReturn(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength);
}
