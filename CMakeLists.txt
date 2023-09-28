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

set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release" "MinSizeRel" "RelWithDebInfo" "ASan" "UBSan")

# Set the C standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)

# Common Compiler Flags
add_compile_options(-pthread -D_GNU_SOURCE -Wall)

# Use FindOpenSSL to locate OpenSSL libraries
find_package(OpenSSL REQUIRED)

# libgmp for brent
find_package(GMP REQUIRED)

# nervcenter executable
add_executable(nervcenter nervcenter.c rsautil.c base64.c parsers.c)
target_compile_definitions(nervcenter PRIVATE -DIMGDIR="${CMAKE_SOURCE_DIR}/img")
target_link_libraries(nervcenter PRIVATE OpenSSL::SSL OpenSSL::Crypto pthread gcc_s)

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

# Custom command for credits unpacking
add_custom_command(
    OUTPUT img/credits/frame_00000001.txt
    COMMAND tar xf ${CMAKE_SOURCE_DIR}/img/credits.tar.xz
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)

add_custom_target(unpack_credits DEPENDS img/credits/frame_00000001.txt)

add_custom_target(repack_credits
    COMMAND rm -f ${CMAKE_SOURCE_DIR}/img/credits.tar.xz
    COMMAND tar cJf ${CMAKE_SOURCE_DIR}/img/credits.tar.xz ${CMAKE_SOURCE_DIR}/img/credits/frame_*.txt
)
