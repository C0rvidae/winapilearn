#include <windows.h>

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
// Perform actions based on the reason for calling.
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            // Initialize once for each new process.
            // Return FALSE to fail DLL load.
            MessageBoxW(NULL, L"DLLs!", L"I have been loaded!", MB_OK);
            break;
        case DLL_THREAD_ATTACH:
            // Do thread-specific initialization.
            break;
        case DLL_THREAD_DETACH:
            // Do thread-specific cleanup.
            break;
        case DLL_PROCESS_DETACH:
            if (lpvReserved != nullptr) {
                // do not do cleanup if process termination scenario
                break;
            }
            // Perform any necessary cleanup.
            break;
    }
    // Successful DLL_PROCESS_ATTACH.
    return TRUE;
}