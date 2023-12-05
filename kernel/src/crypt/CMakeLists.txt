project(Crypt)

add_library(${PROJECT_NAME} iobuffer.cpp key.cpp en_aes.cpp de_aes.cpp multi_buffergroup.cpp multicry.cpp)

target_link_libraries(${PROJECT_NAME} PUBLIC Sutils)

target_include_directories(${PROJECT_NAME} PUBLIC
                            ${PROJECT_BINARY_DIR}
                            ${PROJECT_SOURCE_DIR}/../util
                            )