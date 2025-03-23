#include <windows.h>
#include <stdio.h>

BOOL WINAPI DllMain(HINSTANCE hInstance, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        MessageBox(NULL, "Injected Hello World", "DLL Notification", MB_OK);
    }
    return TRUE;
}
