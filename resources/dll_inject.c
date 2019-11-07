#include <windows.h>

BOOL DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    MessageBoxA(NULL, "Process injected.", NULL, 0);
    return TRUE;
}
