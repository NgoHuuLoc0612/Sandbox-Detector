cmake_minimum_required(VERSION 3.20)

project(SandboxDetector
    VERSION 3.0.0
    DESCRIPTION "Plugin-based sandbox and virtualization detector for Windows"
    LANGUAGES CXX
)

# ============================================================
#  Global compiler settings
# ============================================================

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Common Windows definitions
add_compile_definitions(
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    UNICODE
    _UNICODE
    _WIN32_WINNT=0x0A00   # Windows 10+
    WINVER=0x0A00
)

if(MSVC)
    # ---- MSVC -------------------------------------------------------
    add_compile_options(
        /W4             # Warning level 4
        /WX             # Warnings as errors
        /MP             # Multi-processor compilation
        /EHa            # Enable C++ exceptions with SEH interop
        /GS             # Security check (stack canary)
        /sdl            # Additional SDL checks
        /guard:cf       # Control Flow Guard
        /Zi             # Debug info (all configs)
        /permissive-    # Strict conformance
        /Zc:__cplusplus # Correct __cplusplus macro
    )
    add_compile_options($<$<CONFIG:Release>:/O2>)
    add_compile_options($<$<CONFIG:Release>:/GL>)
    add_link_options($<$<CONFIG:Release>:/LTCG>)
    add_link_options($<$<CONFIG:Release>:/OPT:REF>)
    add_link_options($<$<CONFIG:Release>:/OPT:ICF>)
    add_compile_options($<$<CONFIG:Debug>:/Od>)
    add_compile_options($<$<CONFIG:Debug>:/RTC1>)
else()
    # ---- GCC / MinGW-w64 -------------------------------------------
    add_compile_options(
        -Wall
        -Wextra
        -Wno-unused-parameter
        -Wno-missing-field-initializers
    )
    add_compile_options($<$<CONFIG:Release>:-O2>)
    add_compile_options($<$<CONFIG:Debug>:-O0>)
    add_compile_options($<$<CONFIG:Debug>:-g>)

    # Link statically against libgcc / libstdc++ so the EXE is self-contained
    add_link_options(-static-libgcc -static-libstdc++)
endif()

# ============================================================
#  Include directories
# ============================================================

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

# ============================================================
#  Common Windows link libraries (used by all targets)
# ============================================================

set(SD_WIN_LIBS
    kernel32 user32 advapi32
    ntdll
    crypt32
    ole32 oleaut32 wbemuuid
    setupapi cfgmgr32 uuid
    dxgi
    iphlpapi ws2_32 wldap32
    psapi
    netapi32 secur32
    shlwapi shell32
    userenv
    version
)

# ============================================================
#  Core library  (PluginManager + IPlugin + WinApiUtils)
# ============================================================

add_library(sd_core STATIC
    src/core/IPlugin.cpp
    src/core/PluginManager.cpp
    src/core/PluginManagerSEH.cpp
    src/utils/WinApiUtils.cpp
)

# PluginManagerSEH.cpp: on MSVC compile without /EHa so __try works cleanly.
# On GCC the SEH blocks are guarded with #ifdef _MSC_VER, so normal flags apply.
if(MSVC)
    set_source_files_properties(src/core/PluginManagerSEH.cpp
        PROPERTIES COMPILE_FLAGS "/EHs-c-"
    )
endif()

target_include_directories(sd_core PUBLIC include)
target_link_libraries(sd_core PUBLIC ${SD_WIN_LIBS})

# ============================================================
#  Built-in plugins library
# ============================================================

add_library(sd_plugins STATIC
    src/plugins/TimingPlugin.cpp
    src/plugins/HypervisorPlugin.cpp
    src/plugins/RegistryPlugin.cpp
    src/plugins/ProcessPlugin.cpp
    src/plugins/AntiDebugPlugin.cpp
    src/plugins/HardwarePlugin.cpp
    src/plugins/WmiPlugin.cpp
    src/plugins/NetworkPlugin.cpp
    src/plugins/FileSystemPlugin.cpp
    src/plugins/EnvironmentPlugin.cpp
    src/plugins/MemoryPlugin.cpp
    src/plugins/NativeApiPlugin.cpp
    src/plugins/ExceptionPlugin.cpp
    src/plugins/TokenPrivilegePlugin.cpp
    src/plugins/ServicePlugin.cpp
)

target_include_directories(sd_plugins PUBLIC include)
target_link_libraries(sd_plugins PUBLIC sd_core)

# ============================================================
#  Main executable  (sandbox_detector)
# ============================================================

add_executable(sandbox_detector src/main.cpp)

target_link_libraries(sandbox_detector PRIVATE sd_core sd_plugins)

if(MSVC)
    set_target_properties(sandbox_detector PROPERTIES
        LINK_FLAGS "/SUBSYSTEM:CONSOLE"
    )
endif()

# ============================================================
#  Test harness  (plugin_test)
# ============================================================

add_executable(plugin_test test/plugin_test.cpp)
target_link_libraries(plugin_test PRIVATE sd_core sd_plugins)

# ============================================================
#  Example external plugin DLL
# ============================================================

add_library(sd_plugin_example SHARED examples/ExamplePlugin.cpp)

target_include_directories(sd_plugin_example PRIVATE include)
target_link_libraries(sd_plugin_example PRIVATE sd_core)

set_target_properties(sd_plugin_example PROPERTIES
    OUTPUT_NAME "sd_plugin_example"
    PREFIX ""
)

if(MSVC)
    set_target_properties(sd_plugin_example PROPERTIES
        LINK_FLAGS "/SUBSYSTEM:WINDOWS /DLL"
    )
endif()

# ============================================================
#  Install rules
# ============================================================

install(TARGETS sandbox_detector RUNTIME DESTINATION bin)
install(TARGETS sd_core sd_plugins ARCHIVE DESTINATION lib)
install(DIRECTORY include/
    DESTINATION include/sandbox_detector
    FILES_MATCHING PATTERN "*.hpp"
)

# ============================================================
#  Optional Catch2 tests
# ============================================================

option(BUILD_TESTS "Build unit tests (requires Catch2)" OFF)

if(BUILD_TESTS)
    find_package(Catch2 QUIET)
    if(Catch2_FOUND)
        enable_testing()
        add_executable(sd_tests
            tests/test_plugin_manager.cpp
            tests/test_timing_plugin.cpp
            tests/test_registry_plugin.cpp
        )
        target_link_libraries(sd_tests PRIVATE
            Catch2::Catch2WithMain
            sd_core
            sd_plugins
        )
        include(CTest)
        add_test(NAME SandboxDetectorTests COMMAND sd_tests)
    else()
        message(WARNING "Catch2 not found — skipping unit tests")
    endif()
endif()

# ============================================================
#  CPack packaging
# ============================================================

set(CPACK_PACKAGE_NAME             "SandboxDetector")
set(CPACK_PACKAGE_VERSION          "${PROJECT_VERSION}")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "${PROJECT_DESCRIPTION}")
set(CPACK_GENERATOR                "ZIP")
include(CPack)
