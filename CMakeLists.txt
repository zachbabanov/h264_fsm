cmake_minimum_required(VERSION 3.14)
project(h264_stream_server LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Include headers
include_directories(${CMAKE_SOURCE_DIR}/include)

include(FetchContent)

#
# Fetch rscoder (header-only Reed-Solomon implementation)
# Use the repository's default/main branch. Some repos use "main" instead of "master".
#
FetchContent_Declare(
        rscoder
        GIT_REPOSITORY https://github.com/zachbabanov/rscoder.git
        GIT_TAG        main
)
# Attempt to download/populate rscoder; if this fails, CMake will report the failure.
FetchContent_MakeAvailable(rscoder)

# Core sources (exclude mains)
set(PROJECT_SRC
        src/common.cpp
        src/player.cpp
        src/encoder.cpp
        src/server.cpp
        src/client.cpp
        src/logger.cpp
)

# Build a static library with core functionality so tests can link against it.
add_library(project_core STATIC ${PROJECT_SRC})
target_include_directories(project_core PUBLIC ${CMAKE_SOURCE_DIR}/include)

# Make rscoder headers available to the core library (FetchContent populates <name>_SOURCE_DIR)
if (DEFINED rscoder_SOURCE_DIR)
    target_include_directories(project_core PRIVATE ${rscoder_SOURCE_DIR})
else()
    message(WARNING "rscoder was not populated into rscoder_SOURCE_DIR. Ensure rs.hpp is available in include path.")
endif()

if (WIN32)
    target_compile_definitions(project_core PRIVATE -D_WIN32_WINNT=0x0601)
    target_link_libraries(project_core PRIVATE ws2_32)
endif()

# Executables: server and client (link to project_core)
add_executable(server main_server.cpp)
target_link_libraries(server PRIVATE project_core)
target_include_directories(server PRIVATE ${CMAKE_SOURCE_DIR}/include)

add_executable(client main_client.cpp)
target_link_libraries(client PRIVATE project_core)
target_include_directories(client PRIVATE ${CMAKE_SOURCE_DIR}/include)

# Tests: find all test sources in tests/
file(GLOB TEST_SOURCES "${CMAKE_SOURCE_DIR}/tests/*.cpp")

if (TEST_SOURCES)
    # Use Catch2 v2.13.10 (single header library via FetchContent). This will provide target Catch2::Catch2
    FetchContent_Declare(
            catch2
            GIT_REPOSITORY https://github.com/catchorg/Catch2.git
            GIT_TAG v2.13.10
    )
    FetchContent_MakeAvailable(catch2)

    # Build tests runner
    add_executable(tests_runner ${TEST_SOURCES})
    target_include_directories(tests_runner PRIVATE ${CMAKE_SOURCE_DIR}/include)
    target_link_libraries(tests_runner PRIVATE project_core Catch2::Catch2)
endif()

# Installation (optional)
install(TARGETS server client DESTINATION bin)
