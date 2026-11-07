cmake_minimum_required(VERSION 3.20)

project(mftscan
    VERSION 0.1.0
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Static CRT for all configurations
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

add_compile_definitions(UNICODE _UNICODE)

if(MSVC)
    string(TOLOWER "${CMAKE_GENERATOR_PLATFORM}_${CMAKE_SYSTEM_PROCESSOR}_${CMAKE_VS_PLATFORM_NAME}" _arch_lower)
    if(_arch_lower MATCHES "arm64")
        set(IS_ARM64_TARGET TRUE)
    else()
        set(IS_ARM64_TARGET FALSE)
    endif()

    add_compile_options(
        /W4
        /WX
        /permissive-
        /utf-8
        /EHsc
        /GS
        /guard:cf
        $<$<CONFIG:Release>:/Qspectre>
    )

    add_link_options(
        /GUARD:CF
        /DYNAMICBASE
        /HIGHENTROPYVA
        /Brepro
    )

    if(NOT IS_ARM64_TARGET)
        add_link_options(/CETCOMPAT)
    endif()
endif()

# Core static library
add_library(mftscan_core STATIC
    include/mftscan/common.hpp
    include/mftscan/ntfs_defs.hpp
    include/mftscan/privileges.hpp
    include/mftscan/volume.hpp
    include/mftscan/record_parser.hpp
    include/mftscan/path_builder.hpp
    include/mftscan/query.hpp
    include/mftscan/disk_usage.hpp
    include/mftscan/scanner.hpp
    include/mftscan/formatter.hpp
    src/privileges.cpp
    src/volume.cpp
    src/record_parser.cpp
    src/path_builder.cpp
    src/query.cpp
    src/disk_usage.cpp
    src/scanner.cpp
    src/formatter.cpp
)

target_include_directories(mftscan_core PUBLIC include)

# Main CLI executable
add_executable(mftscan
    src/main.cpp
)

target_link_libraries(mftscan PRIVATE mftscan_core)

# Tests
enable_testing()

add_executable(mftscan_tests
    tests/test_main.cpp
)

target_link_libraries(mftscan_tests PRIVATE mftscan_core)

add_test(NAME unit_tests COMMAND mftscan_tests)
