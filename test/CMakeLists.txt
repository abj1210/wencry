project(Test) 

find_package(GTest REQUIRED)

set(SUBNAME small1)

add_executable(${PROJECT_NAME}${SUBNAME} testsmall1.cpp test.cpp)

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

set(SUBNAME small2)

add_executable(${PROJECT_NAME}${SUBNAME} testsmall2.cpp test.cpp)

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

add_executable(${PROJECT_NAME}${SUBNAME} testbig1.cpp test.cpp)

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

add_executable(${PROJECT_NAME}${SUBNAME} testspeed.cpp test.cpp)

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