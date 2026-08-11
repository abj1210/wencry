project(Valhelper)

add_library(${PROJECT_NAME} base64.cpp information.cpp valhelper.cpp)

target_include_directories(${PROJECT_NAME} PRIVATE
                           ${CMAKE_CURRENT_BINARY_DIR}/../generated
                           )