project(Crypt)

add_subdirectory(MBG)

add_subdirectory(aeskey)

add_library(${PROJECT_NAME} multicry.cpp)

target_link_libraries(${PROJECT_NAME} PUBLIC MBG)

target_include_directories(${PROJECT_NAME} PUBLIC
                            ${PROJECT_BINARY_DIR}
                            ${PROJECT_SOURCE_DIR}/MBG
                            )
                
target_link_libraries(${PROJECT_NAME} PUBLIC Aeskey)

target_include_directories(${PROJECT_NAME} PUBLIC
                            ${PROJECT_BINARY_DIR}
                            ${PROJECT_SOURCE_DIR}/aeskey
                            )