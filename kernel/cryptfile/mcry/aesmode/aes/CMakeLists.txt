project(Aes)

add_library(${PROJECT_NAME} en_aes.cpp de_aes.cpp key.cpp)

include_directories(${PROJECT_NAME} PUBLIC
                            ${PROJECT_BINARY_DIR}
                            ${PROJECT_SOURCE_DIR}/utils
                            ) 