cmake_minimum_required(VERSION 3.22.1)

set(CMAKE_C_STANDARD 17)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

project(Wencry VERSION 4.2.1 LANGUAGES CXX)

string(TIMESTAMP COMPILE_TIME %Y%m%d_%H%M%S)
set(build_time    ${COMPILE_TIME})

# Debug 配置下定义 DEBUG_ON(version()/verstring() 会在版本串后附加 " Debug" 后缀)。
# 用生成器表达式兼容单配置(make/ninja,依据 CMAKE_BUILD_TYPE)与多配置(VS)生成器。
add_compile_definitions($<$<CONFIG:Debug>:DEBUG_ON>)

# 线程事件日志(读/写/工作线程时间线写入 threads.csv),默认关闭。
option(PROFILE_THREADS "Enable per-thread event logging for pipeline analysis" OFF)
if (PROFILE_THREADS)
    add_compile_definitions(PROFILE_THREADS)
endif ()

IF(MSVC)
    message(STATUS "building for: MSVC")
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)
    # /utf-8: source files use UTF-8 (Chinese comments); /W3 for warnings.
    # AES-NI / SHA-NI / SSE4.1 intrinsics compile on x64 without extra /arch flags.
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W3 /utf-8")
ELSEIF(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    IF("${CMAKE_BUILD_TYPE}" MATCHES "Debug")
        message(STATUS "building for: debugging")
        set(CXX_FORMAT_SIGNEDNESS "-Wformat-signedness")
        set(CXX_FORMAT_SECURITY "-Werror=format-security")
        set(CXX_STACK_PROTECTOR "-fstack-protector-all")
        set(CXX_FLAGS_DEBUG "-O0")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -maes -msse2 -msse4.1 -msha -O2 -ggdb -Wall -Wextra -DNETDATA_INTERNAL_CHECKS=1 -DNETDATA_VERIFY_LOCKS=1 ${CXX_FORMAT_SIGNEDNESS} ${CXX_FORMAT_SECURITY} ${CXX_STACK_PROTECTOR} ${CXX_FLAGS_DEBUG}")
    ELSE()
        message(STATUS "building for: release")
        cmake_policy(SET CMP0069 "NEW")
        include(CheckIPOSupported)
        check_ipo_supported(RESULT ipo_supported OUTPUT error)
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -maes -msse2 -msse4.1 -msha -O3")
        IF(${ipo_supported})
            message(STATUS "link time optimization: supported")
            set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)
        ELSE()
            message(STATUS "link time optimization: not supported")
        ENDIF()
    ENDIF()
ENDIF()

configure_file(
  config.h.in
  generated/config.h
  @ONLY
  )

add_subdirectory(valget)

add_subdirectory(valhelper)

add_subdirectory(kernel)

add_executable(${PROJECT_NAME}  main.cpp)

target_link_libraries(${PROJECT_NAME} PUBLIC Wenkernel)

target_include_directories(${PROJECT_NAME} PUBLIC
                           ${PROJECT_BINARY_DIR}
                           ${PROJECT_SOURCE_DIR}/kernel
                           )

target_link_libraries(${PROJECT_NAME} PUBLIC Valhelper)

target_include_directories(${PROJECT_NAME} PUBLIC
                           ${PROJECT_BINARY_DIR}
                           ${PROJECT_SOURCE_DIR}/valhelper
                           )

target_link_libraries(${PROJECT_NAME} PUBLIC CMDvals)

target_include_directories(${PROJECT_NAME} PUBLIC
                            ${PROJECT_BINARY_DIR}
                            ${PROJECT_SOURCE_DIR}/valget
                            )

option(BUILD_TEST "Whether or not to build the tests" ON)
if (${BUILD_TEST})
    message(STATUS "Building tests")
    enable_testing()  
    add_subdirectory(test)
endif ()