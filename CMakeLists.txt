cmake_minimum_required(VERSION 3.22.1)

set(CMAKE_C_STANDARD 17)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)


project(Wencry VERSION 4.6.1 LANGUAGES CXX)

string(TIMESTAMP COMPILE_TIME %Y%m%d_%H%M%S)
set(build_time    ${COMPILE_TIME})

# Debug 配置下定义 DEBUG_ON(version()/verstring() 会在版本串后附加 " Debug" 后缀)。
# 用生成器表达式兼容单配置(make/ninja,依据 CMAKE_BUILD_TYPE)与多配置(VS)生成器。
add_compile_definitions($<$<CONFIG:Debug>:DEBUG_ON>)

# 统一调度日志(线程时间线 + 缓冲区生成/销毁、状态迁移与池大小,写入 sched_log.csv),默认关闭。
option(LOG_SCHED "Enable unified scheduling/buffer/thread-timeline logging" OFF)
if (LOG_SCHED)
    add_compile_definitions(LOG_SCHED)
endif ()

# 缓冲池容量(配置时可用 -DWORK_PROCESSED_MAX=... -DIDLE_POOL_MAX=... 覆盖):
#   WORK_PROCESSED_MAX = 工作池与已处理池共用的总在途 buffer 数(每个 16MB)
#   IDLE_POOL_MAX      = 空闲池可复用 buffer 数
set(WORK_PROCESSED_MAX "12" CACHE STRING "Combined work+processed pool capacity (in-flight buffers)")
set(IDLE_POOL_MAX "4" CACHE STRING "Idle pool capacity (reusable buffers)")
set(THREAD_NUM "4" CACHE STRING "Default worker thread count")
add_compile_definitions(WORK_PROCESSED_MAX=${WORK_PROCESSED_MAX} IDLE_POOL_MAX=${IDLE_POOL_MAX})
add_compile_definitions(THREAD_NUM=${THREAD_NUM})

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
