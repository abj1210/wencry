project(Wenkernel)

add_subdirectory(cryptfile)

add_subdirectory(resprint)

add_library(${PROJECT_NAME} execval.cpp)

target_link_libraries(${PROJECT_NAME} PUBLIC Cryptfile)

target_include_directories(${PROJECT_NAME} PUBLIC
                           ${PROJECT_BINARY_DIR}
                           ${PROJECT_SOURCE_DIR}/cryptfile
                           )

target_link_libraries(${PROJECT_NAME} PUBLIC Resprint)

target_include_directories(${PROJECT_NAME} PUBLIC
                           ${PROJECT_BINARY_DIR}
                           ${PROJECT_SOURCE_DIR}/resprint
                           )