#ifndef WINAPILEARN_NTDLLFUNC_H
#define WINAPILEARN_NTDLLFUNC_H

#include <windows.h>
#include <winternl.h>

typedef NTSTATUS (WINAPI *LPFUN_NtOpenProcess) (
    OUT PHANDLE ProcessHandle,
    IN ACCESS_MASK AccessMask,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN PCLIENT_ID ClientID
);

typedef NTSTATUS (WINAPI *LPFUN_NtCreateThreadEx) (
    OUT PHANDLE hThread,
    IN ACCESS_MASK DesiredAccess,
    IN LPVOID ObjectAttributes,
    IN HANDLE ProcessHandle,
    IN LPTHREAD_START_ROUTINE lpStartAddress,
    IN LPVOID lpParameter,
    IN BOOL CreateSuspended,
    IN ULONG StackZeroBits,
    IN ULONG SizeOfStackCommit,
    IN ULONG SizeOfStackReserve,
    OUT LPVOID lpBytesBuffer
);

typedef NTSTATUS (WINAPI *LPFUN_NtAllocateVirtualMemory) (
    IN HANDLE ProcessHandle,
    IN OUT PVOID *BaseAddress,
    IN ULONG ZeroBits,
    IN OUT PSIZE_T RegionSize,
    IN ULONG AllocationType,
    IN ULONG Protect
);

typedef LPFUN_NtOpenProcess LPFUN_NtOpenProcess;
typedef LPFUN_NtCreateThreadEx LPFUN_NtCreateThreadEx;
typedef LPFUN_NtAllocateVirtualMemory LPFUN_NtAllocateVirtualMemory;

#endif //WINAPILEARN_NTDLLFUNC_H
