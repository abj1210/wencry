project(Wensrc)

add_subdirectory(crypt)

add_subdirectory(sha1)

add_library(${PROJECT_NAME} decry.cpp encry.cpp)

target_link_libraries(${PROJECT_NAME} PUBLIC Sha1)

target_include_directories(${PROJECT_NAME} PUBLIC
                           ${PROJECT_BINARY_DIR}
                           ${PROJECT_SOURCE_DIR}/sha1
                           )

target_link_libraries(${PROJECT_NAME} PUBLIC Crypt)

target_include_directories(${PROJECT_NAME} PUBLIC
                            ${PROJECT_BINARY_DIR}
                            ${PROJECT_SOURCE_DIR}/crypt
                            )