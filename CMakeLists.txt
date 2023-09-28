cmake_minimum_required(VERSION 3.10)

# Default compiler
if(NOT CMAKE_C_COMPILER)
  set(CMAKE_C_COMPILER clang)
endif()

project(nervcenter_project LANGUAGES C)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

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
target_link_libraries(nervcenter PRIVATE OpenSSL::SSL OpenSSL::Crypto pthread)

if(CMAKE_BUILD_TYPE MATCHES Debug)
    target_compile_definitions(nervcenter PRIVATE CHALDEBUG)
endif()

# client_fuzzer executable
if(CMAKE_C_COMPILER_ID MATCHES "Clang")
    add_executable(client_fuzzer fuzzers/client_fuzzer.c parsers.c)
    target_compile_options(client_fuzzer PRIVATE -fsanitize=fuzzer,address)
    target_link_options(client_fuzzer PRIVATE -fsanitize=fuzzer,address)
    set_target_properties(client_fuzzer PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/fuzzers"
    )
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
