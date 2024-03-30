project(Multiaes)

add_subdirectory(aes)

add_library(${PROJECT_NAME} multicry.cpp multi_buffergroup.cpp)
                
target_link_libraries(${PROJECT_NAME} PUBLIC Aes)

target_include_directories(${PROJECT_NAME} PUBLIC
                            ${PROJECT_BINARY_DIR}
                            ${PROJECT_SOURCE_DIR}/aes
                            )