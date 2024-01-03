project(Cryptfile)

add_subdirectory(mcry)

add_subdirectory(hash)

add_library(${PROJECT_NAME} decry.cpp encry.cpp hmac.cpp)

target_link_libraries(${PROJECT_NAME} PUBLIC Hash)

target_include_directories(${PROJECT_NAME} PUBLIC
                           ${PROJECT_BINARY_DIR}
                           ${PROJECT_SOURCE_DIR}/hash
                           )

target_link_libraries(${PROJECT_NAME} PUBLIC Multicry)

target_include_directories(${PROJECT_NAME} PUBLIC
                            ${PROJECT_BINARY_DIR}
                            ${PROJECT_SOURCE_DIR}/mcry
                            )