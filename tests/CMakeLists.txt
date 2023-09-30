macro(add_test_program TESTNAME TESTSRCS_LIST TESTINCS_LIST TESTLIBS_LIST)
    message(STATUS "Adding test program ${TESTNAME}")
    message(STATUS "  Sources: ${TESTSRCS_LIST}")
    message(STATUS "  Includes: ${TESTINCS_LIST}")
    message(STATUS "  Libraries: ${TESTLIBS_LIST}")
    add_executable(${TESTNAME} ${TESTNAME}.c ${TESTSRCS_LIST})
    target_link_libraries(${TESTNAME} ${TESTLIBS_LIST})
    target_include_directories(${TESTNAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/.. ${TESTINCS_LIST})
    add_test(${TESTNAME} ${TESTNAME})
endmacro(add_test_program)

add_test_program(test_rsa_sig "../rsautil.c;../base64.c" "${OPENSSL_INCLUDE_DIR}" OpenSSL::Crypto)
add_test_program(test_pack ../resources.c "${ZLIB_INCLUDE_DIRS}" "${ZLIB_LIBRARIES}")