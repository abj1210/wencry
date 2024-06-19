cmake_minimum_required(VERSION 3.22.1)


set(CMAKE_C_STANDARD 17)
IF("${CMAKE_BUILD_TYPE}" MATCHES "Debug")
    message(STATUS "building for: debugging")
    
    set(CXX_FORMAT_SIGNEDNESS "-Wformat-signedness")
    set(CXX_FORMAT_SECURITY "-Werror=format-security")
    set(CXX_STACK_PROTECTOR "-fstack-protector-all")
    set(CXX_FLAGS_DEBUG "-O0 -gp")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O1 -ggdb -Wall -Wextra -DNETDATA_INTERNAL_CHECKS=1 -DNETDATA_VERIFY_LOCKS=1 ${CXX_FORMAT_SIGNEDNESS} ${CXX_FORMAT_SECURITY} ${CXX_STACK_PROTECTOR} ${CXX_FLAGS_DEBUG}")
ELSE()
    message(STATUS "building for: release")
    cmake_policy(SET CMP0069 "NEW")
    include(CheckIPOSupported)
    check_ipo_supported(RESULT ipo_supported OUTPUT error)
    set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS} -O3")
    IF(${ipo_supported})
        message(STATUS "link time optimization: supported")
        set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)
    ELSE()
        message(STATUS "link time optimization: not supported")
    ENDIF()
ENDIF()



string(TIMESTAMP COMPILE_TIME %Y%m%d_%H%M%S)
set(build_time    ${COMPILE_TIME})

project(Wencry VERSION 3.6.1 LANGUAGES CXX)

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