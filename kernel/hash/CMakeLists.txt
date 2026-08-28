project(MerkleTree)

add_subdirectory(hashmaster)

add_library(${PROJECT_NAME} merkletreemaster.cpp hmac.cpp)
                
target_link_libraries(${PROJECT_NAME} PUBLIC Hash)

target_include_directories(${PROJECT_NAME} PUBLIC
                            ${PROJECT_BINARY_DIR}
                            ${PROJECT_SOURCE_DIR}/hashmaster
                            )

target_link_libraries(${PROJECT_NAME} PUBLIC Valhelper)