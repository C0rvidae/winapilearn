#include <Windows.h>
#include <stdlib.h>
#include <stdio.h>

int main() {
    STARTUPINFOW si = {0};
    PROCESS_INFORMATION pi = {0};
    if (!CreateProcessW(L"C:\\Windows\\system32\\mspaint.exe", NULL, NULL, NULL,
                        FALSE, BELOW_NORMAL_PRIORITY_CLASS, NULL, NULL, &si, &pi)) {
        printf("Failed to create process! error: %ld", GetLastError());
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}