# BASICS
cmake_minimum_required(VERSION 3.18)
project(winapilearn C CXX)

# SET STANDARDS
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 20)
set(LIBRARY_OUTPUT_PATH C:\\Users\\Public\\dlls)

# ENABLE NASM
enable_language(ASM_NASM)
if(CMAKE_ASM_NASM_COMPILER_LOADED)
    set(CAN_USE_ASSEMBLER TRUE)
    file(GLOB_RECURSE ASM_FILES "assembly/*.nasm")
    set(ASM_SOURCES ${ASM_SOURCES} ${ASM_FILES})
endif(CMAKE_ASM_NASM_COMPILER_LOADED)

# EXECUTABLES
add_executable(msgbox steps/c_intro/msgbox.c)
add_executable(createprocess steps/c_intro/createprocess.c)
add_executable(openprocess steps/c_intro/openprocess.c)
add_executable(newprocess steps/c_intro/newprocess.c)
add_executable(createprocesscpp steps/cpp_intro/createprocess.cpp)
add_executable(shellcode_injection steps/cpp_process_injection/shellcode_injection.cpp include/utils.cpp)
add_executable(dllinjection steps/cpp_process_injection/DLLInjection.cpp include/utils.cpp)
add_executable(ntdllinjection steps/cpp_process_injection/NTDLLInjection.cpp include/utils.cpp include/ntdllfunc.h)
add_executable(directsyscalls ${ASM_SOURCES} include/syscalls.c include/utils.cpp steps/cpp_process_injection/direct_syscalls.cpp)

# LIBRARIES
add_library(basicdll SHARED steps/cpp_process_injection/BasicDLL.cpp)
