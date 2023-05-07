#include <Windows.h>
#include <Psapi.h>
#include <stdio.h>
#include <stringapiset.h>

int main() {
    HANDLE h;
    DWORD priority, pid;
    int chk;
    LPWSTR name;
    char * name_s;
    name = malloc(sizeof *name * 64);
    name_s = malloc(sizeof *name_s * 128);
    char * token, * next_token, * old_token;
    char seps[] = "\\";
    h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, 968);
    if (h == NULL) printf("OpenProcess() failed with error: %ld\n", GetLastError());
    else {
        priority = GetPriorityClass(h);
        pid = GetProcessId(h);
        GetProcessImageFileNameW(h, name, 64);
        printf("Process priority: %ld\n", priority);
        printf("Process ID: %ld\n", pid);
        chk = WideCharToMultiByte(CP_UTF8, 0, name, 64, name_s, 128, NULL, NULL);
        if (chk == 0) printf("WideCharToMultiByte() failed with error: %ld\n", GetLastError());
        else {
            token = strtok_s(name_s, seps, &next_token);
            while (token != NULL) {
                old_token = token;
                token = strtok_s(NULL, seps, &next_token);
            }
            printf("Process name: %s\n", old_token);
        }
        CloseHandle(h);
    }
    return EXIT_SUCCESS;
}
