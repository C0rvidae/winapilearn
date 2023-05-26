#ifndef WINAPILEARN_UTILS_H
#define WINAPILEARN_UTILS_H

#include <windows.h>

void printError(DWORD id);
BOOL CheckProcessNotepad(DWORD pid);
DWORD FindFirstNotepad();

#endif //WINAPILEARN_UTILS_H
