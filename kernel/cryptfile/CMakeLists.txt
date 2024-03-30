project(Cryptfile)

add_subdirectory(multi_aes)

add_subdirectory(hash)

add_library(${PROJECT_NAME} cry.cpp)

target_link_libraries(${PROJECT_NAME} PUBLIC Hash)

target_include_directories(${PROJECT_NAME} PUBLIC
                           ${PROJECT_BINARY_DIR}
                           ${PROJECT_SOURCE_DIR}/hash
                           )

target_link_libraries(${PROJECT_NAME} PUBLIC Multiaes)

target_include_directories(${PROJECT_NAME} PUBLIC
                            ${PROJECT_BINARY_DIR}
                            ${PROJECT_SOURCE_DIR}/multi_aes
                            )