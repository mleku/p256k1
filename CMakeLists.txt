cmake_minimum_required(VERSION 3.13)
project(p256k1 VERSION 0.1.0 LANGUAGES C)

# Set C standard
set(CMAKE_C_STANDARD 90)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Configuration options
option(SECP256K1_ENABLE_MODULE_SCHNORRSIG "Enable schnorr signature module" ON)
option(SECP256K1_ENABLE_MODULE_EXTRAKEYS "Enable extrakeys module" ON)
option(SECP256K1_ENABLE_MODULE_ECDH "Enable ECDH module" ON)

# Compiler definitions
add_compile_definitions(
    SECP256K1_BUILD=1
    ENABLE_MODULE_SCHNORRSIG=1
    ENABLE_MODULE_EXTRAKEYS=1
    ENABLE_MODULE_ECDH=1
)

# Include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

# Source files
set(SECP256K1_SOURCES
    src/secp256k1.c
    src/precomputed_ecmult.c
    src/precomputed_ecmult_gen.c
)

# Create the library
add_library(p256k1 ${SECP256K1_SOURCES})

# Set target properties
set_target_properties(p256k1 PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
    PUBLIC_HEADER "include/secp256k1.h;include/secp256k1_extrakeys.h;include/secp256k1_schnorrsig.h;include/secp256k1_ecdh.h"
)

# Compiler flags
target_compile_options(p256k1 PRIVATE
    -Wall
    -Wextra
    -Wcast-align
    -Wnested-externs
    -Wshadow
    -Wstrict-prototypes
    -Wundef
    -Wno-unused-function
    -Wno-long-long
    -Wno-overlength-strings
    -std=c90
    -pedantic
)

# Install targets
install(TARGETS p256k1
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    PUBLIC_HEADER DESTINATION include
)

# Example programs
add_executable(schnorr_example examples/schnorr.c)
target_link_libraries(schnorr_example p256k1)

add_executable(ecdh_example examples/ecdh.c)
target_link_libraries(ecdh_example p256k1)
