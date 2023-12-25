project(Cryptfile)

add_subdirectory(multicrypt)

add_subdirectory(sha1)

add_library(${PROJECT_NAME} decry.cpp encry.cpp hmac.cpp)

target_link_libraries(${PROJECT_NAME} PUBLIC Sha1)

target_include_directories(${PROJECT_NAME} PUBLIC
                           ${PROJECT_BINARY_DIR}
                           ${PROJECT_SOURCE_DIR}/sha1
                           )

target_link_libraries(${PROJECT_NAME} PUBLIC Multicry)

target_include_directories(${PROJECT_NAME} PUBLIC
                            ${PROJECT_BINARY_DIR}
                            ${PROJECT_SOURCE_DIR}/multicrypt
                            )