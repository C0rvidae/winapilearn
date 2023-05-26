#include <stdio.h>
#include <windows.h>

int main() {
    int x =
        MessageBoxW(NULL, L"My first msg box!", L"Hello World", MB_YESNOCANCEL);
    printf("%d\n", x);
    return EXIT_SUCCESS;
}
