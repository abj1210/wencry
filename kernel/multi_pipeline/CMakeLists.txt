project(MultiPipeline)

add_subdirectory(buffergroup)

add_library(${PROJECT_NAME} multicry.cpp)
                
target_link_libraries(${PROJECT_NAME} PUBLIC MBG)

target_include_directories(${PROJECT_NAME} PUBLIC
                            ${PROJECT_BINARY_DIR}
                            ${PROJECT_SOURCE_DIR}/buffergroup
                            )
