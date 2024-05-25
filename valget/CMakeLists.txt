project(CMDvals)

add_subdirectory(base64)

add_library(${PROJECT_NAME} getval1.cpp getopts.cpp information.cpp)

target_link_libraries(${PROJECT_NAME} PUBLIC Base64)

target_include_directories(${PROJECT_NAME} PUBLIC
                           ${PROJECT_BINARY_DIR}
                           ${PROJECT_SOURCE_DIR}/base64
                           )

target_include_directories(${PROJECT_NAME} PRIVATE
                           ${CMAKE_CURRENT_BINARY_DIR}/../generated
                           )