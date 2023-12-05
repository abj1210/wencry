project(Wenkernel)

add_subdirectory(src)

add_library(${PROJECT_NAME} execval.cpp)

target_link_libraries(${PROJECT_NAME} PUBLIC Wensrc)

target_include_directories(${PROJECT_NAME} PUBLIC
                           ${PROJECT_BINARY_DIR}
                           ${PROJECT_SOURCE_DIR}/src
                           )