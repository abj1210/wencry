project(CMDvals)

add_library(${PROJECT_NAME} getval.cpp base64.cpp)

target_include_directories(${PROJECT_NAME} PUBLIC
                           ${PROJECT_BINARY_DIR}
                           ${PROJECT_SOURCE_DIR}/../
                           )