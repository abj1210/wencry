project(Valhelper)

add_library(${PROJECT_NAME} base64.cpp information.cpp valhelper.cpp display/console_display.cpp)

target_include_directories(${PROJECT_NAME} PUBLIC
                           ${CMAKE_CURRENT_SOURCE_DIR}
                           )

target_include_directories(${PROJECT_NAME} PRIVATE
                           ${CMAKE_CURRENT_BINARY_DIR}/../generated
                           )