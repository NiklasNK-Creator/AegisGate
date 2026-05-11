cmake_minimum_required(VERSION 3.28)
project(AegisGateAgent VERSION 1.0.0 LANGUAGES CXX ASM_NASM)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ── Build Mode ──────────────────────────────────────────────────────────
# AEGIS_TEST_MODE: Build without ASM VMCALL (demo mode, no hypervisor needed)
# Set via: cmake -DAEGIS_TEST_MODE=ON
option(AEGIS_TEST_MODE "Build in test mode without VMCALL ASM" OFF)

# ── Source Files ────────────────────────────────────────────────────────
set(AGENT_SOURCES
    src/main.cpp
    src/vmcall_direct.cpp
)

# Only include ASM in production mode
if(NOT AEGIS_TEST_MODE)
    list(APPEND AGENT_SOURCES src/vmcall_stub.asm)
endif()

# Windows Agent executable
add_executable(AegisGate WIN32 ${AGENT_SOURCES})

target_compile_definitions(AegisGate PRIVATE
    _AEGISGATE_WIN=1
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    UNICODE
    _UNICODE
)

if(AEGIS_TEST_MODE)
    target_compile_definitions(AegisGate PRIVATE AEGIS_TEST_MODE=1)
endif()

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
if(NOT AEGIS_TEST_MODE)
    set(CMAKE_ASM_NASM_OBJECT_FORMAT win64)
endif()

# Set output name
set_target_properties(AegisGate PROPERTIES
    OUTPUT_NAME "AegisGate"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)
