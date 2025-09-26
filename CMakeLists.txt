cmake_minimum_required(VERSION 3.10)
project(cerberus VERSION 0.1.0 LANGUAGES C)

# Set C standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Set output directories
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Find required packages
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

# Add include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/core
    ${OPENSSL_INCLUDE_DIR}
)

# Add library
add_library(cerberus SHARED core/cerberus.c)

# Link libraries
target_link_libraries(cerberus
    PRIVATE
        OpenSSL::Crypto
        Threads::Threads
)

# Set output name and properties
set_target_properties(cerberus PROPERTIES
    OUTPUT_NAME "cerberus"
    PREFIX ""
    SUFFIX ".so"
)

# Install rules
install(TARGETS cerberus
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
)

# Install header files
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/core/cerberus.h DESTINATION include/cerberus/core)

# Optional tests (disabled by default)
option(BUILD_TESTS "Build tests" OFF)
if(BUILD_TESTS AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/CMakeLists.txt")
    enable_testing()
    add_subdirectory(tests)
endif()
