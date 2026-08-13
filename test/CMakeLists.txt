project(Test)

include(FetchContent)
if(CMAKE_VERSION VERSION_GREATER_EQUAL 3.24)
    set(GTEST_FETCH_EXTRACT_TS DOWNLOAD_EXTRACT_TIMESTAMP ON)
endif()
FetchContent_Declare(googletest
    URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.zip
    ${GTEST_FETCH_EXTRACT_TS}
)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

add_library(GTest::GTest ALIAS gtest)
add_library(GTest::Main ALIAS gtest_main)

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

add_executable(${PROJECT_NAME}${SUBNAME} test${SUBNAME}.cpp test.cpp testutil.cpp)

target_link_libraries(${PROJECT_NAME}${SUBNAME} GTest::GTest GTest::Main)
 
target_link_libraries(${PROJECT_NAME}${SUBNAME} Wenkernel Valhelper CMDvals)

add_test(NAME ${PROJECT_NAME}${SUBNAME} COMMAND ${PROJECT_NAME}${SUBNAME})

target_include_directories(${PROJECT_NAME}${SUBNAME} PUBLIC
                           ${PROJECT_BINARY_DIR}
                           ${PROJECT_SOURCE_DIR}/../valget
                           )
                        
target_include_directories(${PROJECT_NAME}${SUBNAME} PUBLIC
                           ${PROJECT_BINARY_DIR}
                           ${PROJECT_SOURCE_DIR}/../valhelper
                           )

target_include_directories(${PROJECT_NAME}${SUBNAME} PUBLIC
                           ${PROJECT_BINARY_DIR}
                           ${PROJECT_SOURCE_DIR}/../kernel
                           )

set(SUBNAME smode)

add_executable(${PROJECT_NAME}${SUBNAME} test${SUBNAME}.cpp test.cpp testutil.cpp)

target_link_libraries(${PROJECT_NAME}${SUBNAME} GTest::GTest GTest::Main)

target_link_libraries(${PROJECT_NAME}${SUBNAME} Wenkernel Valhelper CMDvals)

add_test(NAME ${PROJECT_NAME}${SUBNAME} COMMAND ${PROJECT_NAME}${SUBNAME})

target_include_directories(${PROJECT_NAME}${SUBNAME} PUBLIC
                           ${PROJECT_BINARY_DIR}
                           ${PROJECT_SOURCE_DIR}/../valget
                           )
                        
target_include_directories(${PROJECT_NAME}${SUBNAME} PUBLIC
                           ${PROJECT_BINARY_DIR}
                           ${PROJECT_SOURCE_DIR}/../valhelper
                           )

target_include_directories(${PROJECT_NAME}${SUBNAME} PUBLIC
                           ${PROJECT_BINARY_DIR}
                           ${PROJECT_SOURCE_DIR}/../kernel
                           )

set(SUBNAME shash)

add_executable(${PROJECT_NAME}${SUBNAME} test${SUBNAME}.cpp test.cpp testutil.cpp)

target_link_libraries(${PROJECT_NAME}${SUBNAME} GTest::GTest GTest::Main)

target_link_libraries(${PROJECT_NAME}${SUBNAME} Wenkernel Valhelper CMDvals)

add_test(NAME ${PROJECT_NAME}${SUBNAME} COMMAND ${PROJECT_NAME}${SUBNAME})

target_include_directories(${PROJECT_NAME}${SUBNAME} PUBLIC
                           ${PROJECT_BINARY_DIR}
                           ${PROJECT_SOURCE_DIR}/../valget
                           )
                        
target_include_directories(${PROJECT_NAME}${SUBNAME} PUBLIC
                           ${PROJECT_BINARY_DIR}
                           ${PROJECT_SOURCE_DIR}/../valhelper
                           )

target_include_directories(${PROJECT_NAME}${SUBNAME} PUBLIC
                           ${PROJECT_BINARY_DIR}
                           ${PROJECT_SOURCE_DIR}/../kernel
                           )

set(SUBNAME big)

add_executable(${PROJECT_NAME}${SUBNAME} test${SUBNAME}.cpp test.cpp testutil.cpp)

target_link_libraries(${PROJECT_NAME}${SUBNAME} GTest::GTest GTest::Main)

target_link_libraries(${PROJECT_NAME}${SUBNAME} Wenkernel Valhelper CMDvals)

add_test(NAME ${PROJECT_NAME}${SUBNAME} COMMAND ${PROJECT_NAME}${SUBNAME})

target_include_directories(${PROJECT_NAME}${SUBNAME} PUBLIC
                           ${PROJECT_BINARY_DIR}
                           ${PROJECT_SOURCE_DIR}/../valget
                           )
                        
target_include_directories(${PROJECT_NAME}${SUBNAME} PUBLIC
                           ${PROJECT_BINARY_DIR}
                           ${PROJECT_SOURCE_DIR}/../valhelper
                           )

target_include_directories(${PROJECT_NAME}${SUBNAME} PUBLIC
                           ${PROJECT_BINARY_DIR}
                           ${PROJECT_SOURCE_DIR}/../kernel
                           )
                            
set(SUBNAME speed)

add_executable(${PROJECT_NAME}${SUBNAME} test${SUBNAME}.cpp test.cpp testutil.cpp)

target_link_libraries(${PROJECT_NAME}${SUBNAME} GTest::GTest GTest::Main)
 
target_link_libraries(${PROJECT_NAME}${SUBNAME} Wenkernel Valhelper CMDvals)

add_test(NAME ${PROJECT_NAME}${SUBNAME} COMMAND ${PROJECT_NAME}${SUBNAME})

target_include_directories(${PROJECT_NAME}${SUBNAME} PUBLIC
                           ${PROJECT_BINARY_DIR}
                           ${PROJECT_SOURCE_DIR}/../valget
                           )
                        
target_include_directories(${PROJECT_NAME}${SUBNAME} PUBLIC
                           ${PROJECT_BINARY_DIR}
                           ${PROJECT_SOURCE_DIR}/../valhelper
                           )

target_include_directories(${PROJECT_NAME}${SUBNAME} PUBLIC
                           ${PROJECT_BINARY_DIR}
                           ${PROJECT_SOURCE_DIR}/../kernel
                           )

set(SUBNAME vectors)

add_executable(${PROJECT_NAME}${SUBNAME} test${SUBNAME}.cpp testutil.cpp)

target_link_libraries(${PROJECT_NAME}${SUBNAME} GTest::GTest GTest::Main)

target_link_libraries(${PROJECT_NAME}${SUBNAME} Wenkernel)

add_test(NAME ${PROJECT_NAME}${SUBNAME} COMMAND ${PROJECT_NAME}${SUBNAME})

target_include_directories(${PROJECT_NAME}${SUBNAME} PUBLIC
                           ${PROJECT_BINARY_DIR}
                           ${PROJECT_SOURCE_DIR}/../kernel
                           )

set(SUBNAME boundary)

add_executable(${PROJECT_NAME}${SUBNAME} test${SUBNAME}.cpp test.cpp testutil.cpp)

target_link_libraries(${PROJECT_NAME}${SUBNAME} GTest::GTest GTest::Main)

target_link_libraries(${PROJECT_NAME}${SUBNAME} Wenkernel Valhelper CMDvals)

add_test(NAME ${PROJECT_NAME}${SUBNAME} COMMAND ${PROJECT_NAME}${SUBNAME})

target_include_directories(${PROJECT_NAME}${SUBNAME} PUBLIC
                           ${PROJECT_BINARY_DIR}
                           ${PROJECT_SOURCE_DIR}/../kernel
                           ${PROJECT_SOURCE_DIR}/../valget
                           ${PROJECT_SOURCE_DIR}/../valhelper
                           )

set(SUBNAME interactive)

add_executable(${PROJECT_NAME}${SUBNAME} test${SUBNAME}.cpp test.cpp testutil.cpp)

target_link_libraries(${PROJECT_NAME}${SUBNAME} GTest::GTest GTest::Main)

target_link_libraries(${PROJECT_NAME}${SUBNAME} Wenkernel Valhelper CMDvals)

target_compile_definitions(${PROJECT_NAME}${SUBNAME} PRIVATE
                           WENCRY_BIN="$<TARGET_FILE:Wencry>")

add_test(NAME ${PROJECT_NAME}${SUBNAME} COMMAND ${PROJECT_NAME}${SUBNAME})

target_include_directories(${PROJECT_NAME}${SUBNAME} PUBLIC
                           ${PROJECT_BINARY_DIR}
                           ${PROJECT_SOURCE_DIR}/../kernel
                           ${PROJECT_SOURCE_DIR}/../valget
                           ${PROJECT_SOURCE_DIR}/../valhelper
                           )

# 为全部测试设置超时,避免并发回归(死锁/挂起)导致 ctest 无限阻塞。
get_property(_all_tests DIRECTORY PROPERTY TESTS)
foreach(_t IN LISTS _all_tests)
  set_tests_properties(${_t} PROPERTIES TIMEOUT 600)
endforeach()