project(Sha1)

add_subdirectory(shabuf)

add_library(${PROJECT_NAME} sha1.cpp sha1subclass.cpp)

target_link_libraries(${PROJECT_NAME} PUBLIC Shabuf)

target_include_directories(${PROJECT_NAME} PUBLIC
                           ${PROJECT_BINARY_DIR}
                           ${PROJECT_SOURCE_DIR}/shabuf
                           )