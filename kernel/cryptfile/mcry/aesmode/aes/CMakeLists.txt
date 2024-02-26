project(Aes)

add_library(${PROJECT_NAME} aes.cpp)

include_directories(${PROJECT_NAME} PUBLIC
                            ${PROJECT_BINARY_DIR}
                            ${PROJECT_SOURCE_DIR}/utils
                            ) 