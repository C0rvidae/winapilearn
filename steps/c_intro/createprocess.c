#include <stdio.h>
#include <windows.h>
#include <stringapiset.h>
#include <psapi.h>

#define MAXSIZE 100

void print_error(DWORD id) {
    DWORD size;
    wchar_t * msg;
    size = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
                          NULL,
                          id,
                          MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US),
                          (LPWSTR) &msg,
                          0,
                          NULL);
    printf("%lu\n", size);
    printf("%ls\n", msg);
    free(msg);
    msg = NULL;
}

DWORD new_process(STARTUPINFOW * si, PROCESS_INFORMATION * pi) {
    DWORD error;
    DWORD pid = 0;
    if (!CreateProcessW(L"C:\\Windows\\system32\\mspaint.exe", NULL, NULL, NULL,
                        FALSE, BELOW_NORMAL_PRIORITY_CLASS, NULL, NULL, si, pi)) {
        error = GetLastError();
        printf("[!] Failed to create process! error: %ld\n", error);
        print_error(error);
    } else {
        pid = pi->dwProcessId;
        printf("[+] Process started; PID: %ld\n", pid);
    }
    return pid;
}

HANDLE open_process(DWORD pid) {
    DWORD error;
    HANDLE h;
    h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (h == NULL) {
        error = GetLastError();
        printf("[!] Failed to open process! error: %ld\n", error);
        print_error(error);
    }
    return h;
}

void DisplayProcessName(HANDLE h) {
    LPWSTR name = malloc(sizeof *name * MAXSIZE);
    GetProcessImageFileNameW(h, name, MAXSIZE);
    printf("[i] Process file name: %ls\n", name);
    free(name);
    name = NULL;
}

int main(void) {
    // Vars
    STARTUPINFOW si = {0};
    PROCESS_INFORMATION pi = {0};
    HANDLE h, hThread, hProcess;
    DWORD pid, tid;
    // Create process
    pid = new_process(&si, &pi);
    tid = pi.dwThreadId;
    hThread = pi.hThread;
    hProcess = pi.hProcess;
    if (!pid) return EXIT_FAILURE;
    // Open process
    h = open_process(pid);
    if (h == NULL) return EXIT_FAILURE;
    DisplayProcessName(h);
    printf("[i] Process id: %ld | Process thread: 0x%x\n", pid, hProcess);
    printf("[i] Thread id: %ld | Handle thread: 0x%x\n", tid, hThread);
    printf("[-] Beginning to wait for process death...\n");
    WaitForSingleObject(hProcess, INFINITE);
    printf("[+] Process has died\n");
    CloseHandle(hThread);
    CloseHandle(hProcess);
    CloseHandle(h);
    return EXIT_SUCCESS;
}