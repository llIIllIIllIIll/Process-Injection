#pragma once

#include <windows.h>
#include <stdio.h>

#include "../remote.h"

LPVOID ManuallyMapImage(HANDLE hProcess, BYTE *lpData, DWORD dwSize, LPVOID lpAddress, DWORD *lpEntryPoint);
