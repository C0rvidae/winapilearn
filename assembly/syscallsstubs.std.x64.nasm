[SECTION .data]
currentHash:    dd  0

[SECTION .text]

BITS 64
DEFAULT REL

global NtOpenProcess
global NtAllocateVirtualMemory
global NtWriteVirtualMemory
global NtCreateThreadEx
global NtClose

global WhisperMain
extern SW2_GetSyscallNumber
    
WhisperMain:
    pop rax
    mov [rsp+ 8], rcx              ; Save registers.
    mov [rsp+16], rdx
    mov [rsp+24], r8
    mov [rsp+32], r9
    sub rsp, 28h
    mov ecx, dword [currentHash]
    call SW2_GetSyscallNumber
    add rsp, 28h
    mov rcx, [rsp+ 8]              ; Restore registers.
    mov rdx, [rsp+16]
    mov r8, [rsp+24]
    mov r9, [rsp+32]
    mov r10, rcx
    syscall                        ; Issue syscall
    ret

NtOpenProcess:
    mov dword [currentHash], 0F02E89C5h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtAllocateVirtualMemory:
    mov dword [currentHash], 00185170Bh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtWriteVirtualMemory:
    mov dword [currentHash], 005963529h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtCreateThreadEx:
    mov dword [currentHash], 0A4A5069Eh    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

NtClose:
    mov dword [currentHash], 0742C8C71h    ; Load function hash into global variable.
    call WhisperMain                       ; Resolve function hash into syscall number and make the call

