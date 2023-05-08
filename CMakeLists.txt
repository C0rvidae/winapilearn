cmake_minimum_required(VERSION 3.18)
project(winapilearn C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 20)
set(LIBRARY_OUTPUT_PATH C:\\Users\\Public\\dlls)

#add_executable(msgbox c_intro/msgbox.c)
#add_executable(createprocess c_intro/createprocess.c)
#add_executable(openprocess c_intro/openprocess.c)
#add_executable(newprocess c_intro/newprocess.c)
#add_executable(createprocesscpp cpp_intro/createprocess.cpp)

#add_executable(shellcode_injection cpp_process_injection/shellcode_injection.cpp utils.cpp)

add_library(basicdll SHARED cpp_process_injection/BasicDLL.cpp)
add_executable(dllinjection cpp_process_injection/DLLInjection.cpp utils.cpp)
