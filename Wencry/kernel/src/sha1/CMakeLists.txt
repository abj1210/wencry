project(Sha1)

add_library(${PROJECT_NAME} sha1.cpp shabuffer.cpp)

target_link_libraries(${PROJECT_NAME} PUBLIC Sutils)

target_include_directories(${PROJECT_NAME} PUBLIC
                            ${PROJECT_BINARY_DIR}
                            ${PROJECT_SOURCE_DIR}/../util
                            )