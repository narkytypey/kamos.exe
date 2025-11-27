cmake_minimum_required(VERSION 3.15)
project(NCRT VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Set output directory for executables
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Add the executable
add_executable(NCRT
    cpps/main.cpp
    cpps/utils.cpp
    cpps/modules.cpp
)

# Include directories
target_include_directories(NCRT PRIVATE ${CMAKE_SOURCE_DIR}/headers)

# Link Windows libraries
target_link_libraries(NCRT PRIVATE
    ws2_32
    iphlpapi
    advapi32
    shlwapi
    netapi32
    shell32
)

# Enable optimization
if(MSVC)
    target_compile_options(NCRT PRIVATE /O2 /W4)
endif()
