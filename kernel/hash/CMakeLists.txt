project(Hash)

add_library(${PROJECT_NAME} sha1.cpp md5.cpp sha256.cpp sha_ni.cpp hashmaster.cpp)

# 共享类型枚举(见 valhelper/modes.h)
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../valhelper)