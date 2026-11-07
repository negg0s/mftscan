cmake_minimum_required(VERSION 3.20)

project(mftscan
    VERSION 0.3.0
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
    include/mftscan/data_run.hpp
    include/mftscan/disk_usage.hpp
    include/mftscan/duplicate_detector.hpp
    include/mftscan/formatter.hpp
    include/mftscan/fragmentation_analyzer.hpp
    include/mftscan/inspector.hpp
    include/mftscan/ntfs_defs.hpp
    include/mftscan/path_builder.hpp
    include/mftscan/privileges.hpp
    include/mftscan/query.hpp
    include/mftscan/raw_streamer.hpp
    include/mftscan/record_parser.hpp
    include/mftscan/scanner.hpp
    include/mftscan/sparse_slack_analyzer.hpp
    include/mftscan/thread_pool.hpp
    include/mftscan/tui.hpp
    include/mftscan/usn_monitor.hpp
    include/mftscan/volume.hpp
    src/data_run.cpp
    src/disk_usage.cpp
    src/duplicate_detector.cpp
    src/formatter.cpp
    src/fragmentation_analyzer.cpp
    src/inspector.cpp
    src/path_builder.cpp
    src/privileges.cpp
    src/query.cpp
    src/raw_streamer.cpp
    src/record_parser.cpp
    src/scanner.cpp
    src/sparse_slack_analyzer.cpp
    src/thread_pool.cpp
    src/tui.cpp
    src/usn_monitor.cpp
    src/volume.cpp
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
