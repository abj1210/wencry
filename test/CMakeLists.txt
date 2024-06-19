project(Test) 

find_package(GTest REQUIRED)

set(SUBNAME utest)

add_executable(${PROJECT_NAME}${SUBNAME} test${SUBNAME}.cpp testutil.cpp)

target_link_libraries(${PROJECT_NAME}${SUBNAME} GTest::GTest GTest::Main)

add_test(NAME ${PROJECT_NAME}${SUBNAME} COMMAND ${PROJECT_NAME}${SUBNAME})

set(SUBNAME sha1)

add_executable(${PROJECT_NAME}${SUBNAME} test${SUBNAME}.cpp testutil.cpp)

target_link_libraries(${PROJECT_NAME}${SUBNAME} GTest::GTest GTest::Main)
 
target_link_libraries(${PROJECT_NAME}${SUBNAME} Wenkernel)

add_test(NAME ${PROJECT_NAME}${SUBNAME} COMMAND ${PROJECT_NAME}${SUBNAME})

target_include_directories(${PROJECT_NAME}${SUBNAME} PUBLIC
                           ${PROJECT_BINARY_DIR}
                           ${PROJECT_SOURCE_DIR}/../kernel
                           )
                           
set(SUBNAME md5)

add_executable(${PROJECT_NAME}${SUBNAME} test${SUBNAME}.cpp testutil.cpp)

target_link_libraries(${PROJECT_NAME}${SUBNAME} GTest::GTest GTest::Main)
 
target_link_libraries(${PROJECT_NAME}${SUBNAME} Wenkernel)

add_test(NAME ${PROJECT_NAME}${SUBNAME} COMMAND ${PROJECT_NAME}${SUBNAME})

target_include_directories(${PROJECT_NAME}${SUBNAME} PUBLIC
                           ${PROJECT_BINARY_DIR}
                           ${PROJECT_SOURCE_DIR}/../kernel
                           )
set(SUBNAME sha256)

add_executable(${PROJECT_NAME}${SUBNAME} test${SUBNAME}.cpp testutil.cpp)

target_link_libraries(${PROJECT_NAME}${SUBNAME} GTest::GTest GTest::Main)

target_link_libraries(${PROJECT_NAME}${SUBNAME} Wenkernel)

add_test(NAME ${PROJECT_NAME}${SUBNAME} COMMAND ${PROJECT_NAME}${SUBNAME})

target_include_directories(${PROJECT_NAME}${SUBNAME} PUBLIC
                            ${PROJECT_BINARY_DIR}
                            ${PROJECT_SOURCE_DIR}/../kernel
                            )
set(SUBNAME aes)

add_executable(${PROJECT_NAME}${SUBNAME} test${SUBNAME}.cpp testutil.cpp)

target_link_libraries(${PROJECT_NAME}${SUBNAME} GTest::GTest GTest::Main)

target_link_libraries(${PROJECT_NAME}${SUBNAME} Wenkernel)

add_test(NAME ${PROJECT_NAME}${SUBNAME} COMMAND ${PROJECT_NAME}${SUBNAME})

target_include_directories(${PROJECT_NAME}${SUBNAME} PUBLIC
                            ${PROJECT_BINARY_DIR}
                            ${PROJECT_SOURCE_DIR}/../kernel
                            )

set(SUBNAME base64)

add_executable(${PROJECT_NAME}${SUBNAME} test${SUBNAME}.cpp testutil.cpp)

target_link_libraries(${PROJECT_NAME}${SUBNAME} GTest::GTest GTest::Main)

target_link_libraries(${PROJECT_NAME}${SUBNAME} CMDvals)

add_test(NAME ${PROJECT_NAME}${SUBNAME} COMMAND ${PROJECT_NAME}${SUBNAME})

target_include_directories(${PROJECT_NAME}${SUBNAME} PUBLIC
                            ${PROJECT_BINARY_DIR}
                            ${PROJECT_SOURCE_DIR}/../valget
                            )

set(SUBNAME hmac)

add_executable(${PROJECT_NAME}${SUBNAME} test${SUBNAME}.cpp testutil.cpp)

target_link_libraries(${PROJECT_NAME}${SUBNAME} GTest::GTest GTest::Main)

target_link_libraries(${PROJECT_NAME}${SUBNAME} Wenkernel)

add_test(NAME ${PROJECT_NAME}${SUBNAME} COMMAND ${PROJECT_NAME}${SUBNAME})

target_include_directories(${PROJECT_NAME}${SUBNAME} PUBLIC
                            ${PROJECT_BINARY_DIR}
                            ${PROJECT_SOURCE_DIR}/../kernel
                            )

set(SUBNAME ECB)

add_executable(${PROJECT_NAME}${SUBNAME} test${SUBNAME}.cpp testutil.cpp)

target_link_libraries(${PROJECT_NAME}${SUBNAME} GTest::GTest GTest::Main)

target_link_libraries(${PROJECT_NAME}${SUBNAME} Wenkernel)

add_test(NAME ${PROJECT_NAME}${SUBNAME} COMMAND ${PROJECT_NAME}${SUBNAME})

target_include_directories(${PROJECT_NAME}${SUBNAME} PUBLIC
                            ${PROJECT_BINARY_DIR}
                            ${PROJECT_SOURCE_DIR}/../kernel
                            )

set(SUBNAME CBC)

add_executable(${PROJECT_NAME}${SUBNAME} test${SUBNAME}.cpp testutil.cpp)

target_link_libraries(${PROJECT_NAME}${SUBNAME} GTest::GTest GTest::Main)

target_link_libraries(${PROJECT_NAME}${SUBNAME} Wenkernel)

add_test(NAME ${PROJECT_NAME}${SUBNAME} COMMAND ${PROJECT_NAME}${SUBNAME})

target_include_directories(${PROJECT_NAME}${SUBNAME} PUBLIC
                            ${PROJECT_BINARY_DIR}
                            ${PROJECT_SOURCE_DIR}/../kernel
                            )

set(SUBNAME CTR)

add_executable(${PROJECT_NAME}${SUBNAME} test${SUBNAME}.cpp testutil.cpp)

target_link_libraries(${PROJECT_NAME}${SUBNAME} GTest::GTest GTest::Main)

target_link_libraries(${PROJECT_NAME}${SUBNAME} Wenkernel)

add_test(NAME ${PROJECT_NAME}${SUBNAME} COMMAND ${PROJECT_NAME}${SUBNAME})

target_include_directories(${PROJECT_NAME}${SUBNAME} PUBLIC
                            ${PROJECT_BINARY_DIR}
                            ${PROJECT_SOURCE_DIR}/../kernel
                            )

set(SUBNAME CFB)

add_executable(${PROJECT_NAME}${SUBNAME} test${SUBNAME}.cpp testutil.cpp)

target_link_libraries(${PROJECT_NAME}${SUBNAME} GTest::GTest GTest::Main)

target_link_libraries(${PROJECT_NAME}${SUBNAME} Wenkernel)

add_test(NAME ${PROJECT_NAME}${SUBNAME} COMMAND ${PROJECT_NAME}${SUBNAME})

target_include_directories(${PROJECT_NAME}${SUBNAME} PUBLIC
                            ${PROJECT_BINARY_DIR}
                            ${PROJECT_SOURCE_DIR}/../kernel
                            )

set(SUBNAME OFB)

add_executable(${PROJECT_NAME}${SUBNAME} test${SUBNAME}.cpp testutil.cpp)

target_link_libraries(${PROJECT_NAME}${SUBNAME} GTest::GTest GTest::Main)

target_link_libraries(${PROJECT_NAME}${SUBNAME} Wenkernel)

add_test(NAME ${PROJECT_NAME}${SUBNAME} COMMAND ${PROJECT_NAME}${SUBNAME})

target_include_directories(${PROJECT_NAME}${SUBNAME} PUBLIC
                            ${PROJECT_BINARY_DIR}
                            ${PROJECT_SOURCE_DIR}/../kernel
                            )


set(SUBNAME small)

add_executable(${PROJECT_NAME}${SUBNAME} test${SUBNAME}.cpp test.cpp)

target_link_libraries(${PROJECT_NAME}${SUBNAME} GTest::GTest GTest::Main)
 
target_link_libraries(${PROJECT_NAME}${SUBNAME} Wenkernel CMDvals)

add_test(NAME ${PROJECT_NAME}${SUBNAME} COMMAND ${PROJECT_NAME}${SUBNAME})

target_include_directories(${PROJECT_NAME}${SUBNAME} PUBLIC
                           ${PROJECT_BINARY_DIR}
                           ${PROJECT_SOURCE_DIR}/../valget
                           )

target_include_directories(${PROJECT_NAME}${SUBNAME} PUBLIC
                           ${PROJECT_BINARY_DIR}
                           ${PROJECT_SOURCE_DIR}/../kernel
                           )

set(SUBNAME smode)

add_executable(${PROJECT_NAME}${SUBNAME} test${SUBNAME}.cpp test.cpp)

target_link_libraries(${PROJECT_NAME}${SUBNAME} GTest::GTest GTest::Main)

target_link_libraries(${PROJECT_NAME}${SUBNAME} Wenkernel CMDvals)

add_test(NAME ${PROJECT_NAME}${SUBNAME} COMMAND ${PROJECT_NAME}${SUBNAME})

target_include_directories(${PROJECT_NAME}${SUBNAME} PUBLIC
                            ${PROJECT_BINARY_DIR}
                            ${PROJECT_SOURCE_DIR}/../valget
                            )

target_include_directories(${PROJECT_NAME}${SUBNAME} PUBLIC
                            ${PROJECT_BINARY_DIR}
                            ${PROJECT_SOURCE_DIR}/../kernel
                            )

set(SUBNAME shash)

add_executable(${PROJECT_NAME}${SUBNAME} test${SUBNAME}.cpp test.cpp)

target_link_libraries(${PROJECT_NAME}${SUBNAME} GTest::GTest GTest::Main)

target_link_libraries(${PROJECT_NAME}${SUBNAME} Wenkernel CMDvals)

add_test(NAME ${PROJECT_NAME}${SUBNAME} COMMAND ${PROJECT_NAME}${SUBNAME})

target_include_directories(${PROJECT_NAME}${SUBNAME} PUBLIC
                            ${PROJECT_BINARY_DIR}
                            ${PROJECT_SOURCE_DIR}/../valget
                            )

target_include_directories(${PROJECT_NAME}${SUBNAME} PUBLIC
                            ${PROJECT_BINARY_DIR}
                            ${PROJECT_SOURCE_DIR}/../kernel
                            )

set(SUBNAME big)

add_executable(${PROJECT_NAME}${SUBNAME} test${SUBNAME}.cpp test.cpp)

target_link_libraries(${PROJECT_NAME}${SUBNAME} GTest::GTest GTest::Main)

target_link_libraries(${PROJECT_NAME}${SUBNAME} Wenkernel CMDvals)

add_test(NAME ${PROJECT_NAME}${SUBNAME} COMMAND ${PROJECT_NAME}${SUBNAME})

target_include_directories(${PROJECT_NAME}${SUBNAME} PUBLIC
                            ${PROJECT_BINARY_DIR}
                            ${PROJECT_SOURCE_DIR}/../valget
                            )

target_include_directories(${PROJECT_NAME}${SUBNAME} PUBLIC
                            ${PROJECT_BINARY_DIR}
                            ${PROJECT_SOURCE_DIR}/../kernel
                            )
                            
set(SUBNAME speed)

add_executable(${PROJECT_NAME}${SUBNAME} test${SUBNAME}.cpp test.cpp)

target_link_libraries(${PROJECT_NAME}${SUBNAME} GTest::GTest GTest::Main)
 
target_link_libraries(${PROJECT_NAME}${SUBNAME} Wenkernel CMDvals)

add_test(NAME ${PROJECT_NAME}${SUBNAME} COMMAND ${PROJECT_NAME}${SUBNAME})

target_include_directories(${PROJECT_NAME}${SUBNAME} PUBLIC
                           ${PROJECT_BINARY_DIR}
                           ${PROJECT_SOURCE_DIR}/../valget
                           )

target_include_directories(${PROJECT_NAME}${SUBNAME} PUBLIC
                           ${PROJECT_BINARY_DIR}
                           ${PROJECT_SOURCE_DIR}/../kernel
                           )