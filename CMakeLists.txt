cmake_minimum_required(VERSION 3.22.1)

set(CMAKE_CXX_FLAGS "-std=c++14 -O3")

string(TIMESTAMP COMPILE_TIME %Y%m%d_%H%M%S)
set(build_time    ${COMPILE_TIME})

project(Wencry VERSION 2.8.2 LANGUAGES CXX)

configure_file(
  config.h.in
  generated/config.h
  @ONLY
  )


add_subdirectory(valget)

add_subdirectory(kernel)

option(BUILD_TEST "Whether or not to build the tests" ON)
if (${BUILD_TEST})
    message(STATUS "Building tests")
    enable_testing()  
    add_subdirectory(test)
endif ()

add_executable(${PROJECT_NAME}  main.cpp)

target_link_libraries(${PROJECT_NAME} PUBLIC Wenkernel)

target_include_directories(${PROJECT_NAME} PUBLIC
                           ${PROJECT_BINARY_DIR}
                           ${PROJECT_SOURCE_DIR}/kernel
                           )

target_link_libraries(${PROJECT_NAME} PUBLIC CMDvals)

target_include_directories(${PROJECT_NAME} PUBLIC
                            ${PROJECT_BINARY_DIR}
                            ${PROJECT_SOURCE_DIR}/valget
                            )
                            
target_include_directories(${PROJECT_NAME} PRIVATE
                            ${CMAKE_CURRENT_BINARY_DIR}/generated
                            )