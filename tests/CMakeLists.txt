macro(add_test_program TESTNAME TESTSRCS TESTINCS TESTLIBS)
    add_executable(${TESTNAME} ${TESTNAME}.c ${TESTSRCS})
    target_link_libraries(${TESTNAME} ${TESTLIBS})
    target_include_directories(${TESTNAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/.. ${TESTINCS})
    add_test(${TESTNAME} ${TESTNAME})
endmacro(add_test_program)


add_test_program(test_pack ../resources.c ${ZLIB_INCLUDE_DIRS} ${ZLIB_LIBRARIES})
