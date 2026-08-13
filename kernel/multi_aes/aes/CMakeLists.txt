project(Aes)

add_library(${PROJECT_NAME} aes_ni.cpp aesmode.cpp)

# 共享类型枚举(见 valhelper/modes.h)
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../../valhelper)


