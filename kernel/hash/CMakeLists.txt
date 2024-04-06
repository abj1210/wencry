project(Hash)

add_subdirectory(hashbuf)

add_library(${PROJECT_NAME} sha1.cpp md5.cpp hashmaster.cpp)

target_link_libraries(${PROJECT_NAME} PUBLIC Hashbuf)

target_include_directories(${PROJECT_NAME} PUBLIC
                           ${PROJECT_BINARY_DIR}
                           ${PROJECT_SOURCE_DIR}/hashbuf
                           )