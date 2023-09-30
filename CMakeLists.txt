cmake_minimum_required(VERSION 3.10)

# Default compiler
if(NOT CMAKE_C_COMPILER)
  set(CMAKE_C_COMPILER clang)
endif()
if(NOT CMAKE_CXX_COMPILER)
  set(CMAKE_CXX_COMPILER clang++)
endif()

project(nervcenter_project LANGUAGES C CXX)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

set(CMAKE_CXX_OUTPUT_EXTENSION_REPLACE ON)

# This file provides a custom build type, `CMAKE_BUILD_TYPE_ASAN`
set(CMAKE_C_FLAGS_ASAN "${CMAKE_C_FLAGS_RELWITHDEBINFO} -fsanitize=address -fno-omit-frame-pointer -fno-common" CACHE STRING "" FORCE)
set(CMAKE_CXX_FLAGS_ASAN "${CMAKE_CXX_FLAGS_RELWITHDEBINFO} -fsanitize=address -fno-omit-frame-pointer -fno-common" CACHE STRING "" FORCE)
set(CMAKE_EXE_LINKER_FLAGS_ASAN "${CMAKE_EXE_LINKER_FLAGS_RELWITHDEBINFO} -fsanitize=address" CACHE STRING "" FORCE)
set(CMAKE_SHARED_LINKER_FLAGS_ASAN "${CMAKE_SHARED_LINKER_FLAGS_RELWITHDEBINFO} -fsanitize=address" CACHE STRING "" FORCE)

# This file provides a custom build type, `CMAKE_BUILD_TYPE_UBSAN`
set(CMAKE_C_FLAGS_UBSAN "${CMAKE_C_FLAGS_RELWITHDEBINFO} -fsanitize=undefined -fno-omit-frame-pointer -fno-common" CACHE STRING "" FORCE)
set(CMAKE_CXX_FLAGS_UBSAN "${CMAKE_CXX_FLAGS_RELWITHDEBINFO} -fsanitize=undefined -fno-omit-frame-pointer -fno-common" CACHE STRING "" FORCE)
set(CMAKE_EXE_LINKER_FLAGS_UBSAN "${CMAKE_EXE_LINKER_FLAGS_RELWITHDEBINFO} -fsanitize=undefined" CACHE STRING "" FORCE)
set(CMAKE_SHARED_LINKER_FLAGS_UBSAN "${CMAKE_SHARED_LINKER_FLAGS_RELWITHDEBINFO} -fsanitize=undefined" CACHE STRING "" FORCE)

if(CMAKE_CXX_COMPILER_ID MATCHES "Clang" AND CMAKE_C_COMPILER_ID MATCHES "Clang")
    set(CMAKE_C_FLAGS_COVERAGE "${CMAKE_C_FLAGS} -fprofile-instr-generate -fcoverage-mapping")
    set(CMAKE_CXX_FLAGS_COVERAGE "${CMAKE_CXX_FLAGS} -fprofile-instr-generate -fcoverage-mapping")
    set(CMAKE_EXE_LINKER_FLAGS_COVERAGE "${CMAKE_EXE_LINKER_FLAGS} -fprofile-instr-generate -fcoverage-mapping")
endif()

set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release" "MinSizeRel" "RelWithDebInfo" "ASan" "UBSan")

# Get the current list of build types
get_property(current_build_types CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS)

# Conditionally append "Coverage" if the compiler is Clang
if(CMAKE_CXX_COMPILER_ID MATCHES "Clang" AND CMAKE_C_COMPILER_ID MATCHES "Clang")
    list(APPEND current_build_types "Coverage")
endif()

# Set the modified list back
set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS ${current_build_types})

# Set the C standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)

# Common Compiler Flags
add_compile_options(-pthread -D_GNU_SOURCE -Wall)

# OpenSSL
find_package(OpenSSL REQUIRED)

# zlib
find_package(ZLIB REQUIRED)

# libgmp for brent
find_package(GMP REQUIRED)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

# nervcenter executable
add_executable(nervcenter nervcenter.c rsautil.c base64.c parsers.c resources.c image.c generated/imgresource.c)
target_include_directories(nervcenter PRIVATE ${ZLIB_INCLUDE_DIRS} ${OPENSSL_INCLUDE_DIR})
target_link_libraries(nervcenter PRIVATE OpenSSL::Crypto pthread gcc_s ${ZLIB_LIBRARIES})

if(CMAKE_BUILD_TYPE MATCHES Debug)
    target_compile_definitions(nervcenter PRIVATE CHALDEBUG)
endif()

# helper function for fuzzer executables
function(add_fuzzer_target target_name)
    # All source files are taken after the target name
    set(sources ${ARGN})
    add_executable(${target_name} ${sources})
    target_compile_options(${target_name} PRIVATE -fsanitize=fuzzer,address)
    target_link_options(${target_name} PRIVATE -fsanitize=fuzzer,address)
    set_target_properties(${target_name} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/fuzzers"
    )
endfunction()

if(CMAKE_C_COMPILER_ID MATCHES "Clang")
    add_fuzzer_target(sensor_fuzzer fuzzers/sensor_fuzzer.c parsers.c)
    add_fuzzer_target(validate_challenge_fuzzer fuzzers/validate_challenge_fuzzer.cc rsautil.c base64.c)
    target_link_libraries(validate_challenge_fuzzer PRIVATE OpenSSL::Crypto)
    add_fuzzer_target(dump_pubkey_ssh_fuzzer fuzzers/dump_pubkey_ssh_fuzzer.cc rsautil.c base64.c)
    target_link_libraries(dump_pubkey_ssh_fuzzer PRIVATE OpenSSL::Crypto)
    add_fuzzer_target(encrypt_message_fuzzer fuzzers/encrypt_message_fuzzer.cc rsautil.c base64.c)
    target_link_libraries(encrypt_message_fuzzer PRIVATE OpenSSL::Crypto)
    add_fuzzer_target(decrypt_message_fuzzer fuzzers/encrypt_message_fuzzer.cc rsautil.c base64.c)
    target_link_libraries(decrypt_message_fuzzer PRIVATE OpenSSL::Crypto)
endif()

# brent executable
add_executable(brent solver/brent.c)
target_include_directories(brent PRIVATE ${GMP_INCLUDE_DIRS})
target_link_libraries(brent PRIVATE ${GMP_LIBRARIES})
set_target_properties(brent PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/solver"
)

# signmessage executable
add_executable(signmessage solver/signmessage.c)
target_link_libraries(signmessage PRIVATE OpenSSL::Crypto)
set_target_properties(signmessage PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/solver"
)

add_executable(decryptmessage solver/decryptmessage.c)
target_link_libraries(decryptmessage PRIVATE OpenSSL::Crypto)
set_target_properties(decryptmessage PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/solver"
)

# Enable testing
enable_testing()

# Add the tests subdirectory
add_subdirectory(tests)

# Add the util subdirectory
add_subdirectory(util)

add_custom_command(
  OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/generated/imgresource.c ${CMAKE_CURRENT_SOURCE_DIR}/generated/imgresource.h
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  COMMAND ${CMAKE_CURRENT_BINARY_DIR}/util/pack_images img ${CMAKE_CURRENT_SOURCE_DIR}/generated/imgresource image_blob
  DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/util/pack_images ${CMAKE_CURRENT_SOURCE_DIR}/img/credits/frame_00000001.txt
)
