#include "utils.h"
#include <psapi.h>
#include <cstdio>
#include <ranges>



void printError(DWORD id) {
    DWORD size;
    wchar_t *msg;
    size = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
                          nullptr,
                          id,
                          MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US),
                          (LPWSTR) &msg,
                          0,
                          nullptr);
    printf("[!] %ls\n", msg);
    free(msg);
    msg = nullptr;
}

BOOL CheckProcessNotepad(DWORD pid) {
    TCHAR szProcessName[MAX_PATH] = TEXT("<unknown>");
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (hProcess != nullptr) {
        HMODULE hMod = nullptr;
        DWORD cbNeeded = 0;
        if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded))
            GetModuleBaseName(hProcess, hMod, szProcessName, sizeof(szProcessName) / sizeof(TCHAR));
    }
    CloseHandle(hProcess);
    if (std::string_view(szProcessName).find("notepad.exe") != std::string::npos) return true;
    else return false;
}


DWORD FindFirstNotepad() {
    DWORD aProcesses[1024] = {0}, cbNeeded = 0, cProcesses = 0;
    if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded)) return 0;
    cProcesses = cbNeeded / sizeof(DWORD);
    printf("[+] %lu processes found\n", cProcesses);
    for (auto pid: aProcesses | std::views::take(cProcesses)) {
        if (pid) {
            if (CheckProcessNotepad(pid)) return pid;
        }
    }
    return 0;
}