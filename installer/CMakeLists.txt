cmake_minimum_required(VERSION 3.28)
project(AegisGateInstaller VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ── Full Installer ──────────────────────────────────────────────────────
add_executable(AegisGateSetup WIN32
    src/installer_main.cpp
    src/hardware_check.cpp
    src/system_config.cpp
    src/secure_boot.cpp
)

target_compile_definitions(AegisGateSetup PRIVATE
    WIN32_LEAN_AND_MEAN NOMINMAX UNICODE _UNICODE
)

target_link_libraries(AegisGateSetup PRIVATE
    shell32 user32 kernel32 advapi32 comctl32 crypt32 ole32
)

set_target_properties(AegisGateSetup PROPERTIES
    OUTPUT_NAME "AegisGate-Setup"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

# ── Tester (same binary, different default) ─────────────────────────────
add_executable(AegisGateTest WIN32
    src/installer_main.cpp
    src/hardware_check.cpp
    src/system_config.cpp
    src/secure_boot.cpp
)

target_compile_definitions(AegisGateTest PRIVATE
    WIN32_LEAN_AND_MEAN NOMINMAX UNICODE _UNICODE
    AEGIS_TESTER_DEFAULT=1
)

target_link_libraries(AegisGateTest PRIVATE
    shell32 user32 kernel32 advapi32 comctl32 crypt32 ole32
)

set_target_properties(AegisGateTest PROPERTIES
    OUTPUT_NAME "AegisGate-Test"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)
