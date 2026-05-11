cmake_minimum_required(VERSION 3.28)
project(AegisGateAgent VERSION 1.0.0 LANGUAGES CXX ASM_NASM)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Windows Agent executable
add_executable(AegisGate WIN32
    src/main.cpp
    src/vmcall_direct.cpp
    src/vmcall_stub.asm
)

target_compile_definitions(AegisGate PRIVATE
    _AEGISGATE_WIN=1
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    UNICODE
    _UNICODE
)

target_include_directories(AegisGate PRIVATE
    ${CMAKE_SOURCE_DIR}/../common/include
)

# Link Windows libraries
target_link_libraries(AegisGate PRIVATE
    shell32
    user32
    kernel32
)

# NASM settings for Windows
set(CMAKE_ASM_NASM_OBJECT_FORMAT win64)

# Set output name
set_target_properties(AegisGate PROPERTIES
    OUTPUT_NAME "AegisGate"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)
