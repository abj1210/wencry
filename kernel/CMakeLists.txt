project(Wenkernel)

option(GUI_OPT "Whether or not to build GUI" OFF)
if (GUI_OPT)
    add_definitions(-DGUI_ON)
endif ()

add_subdirectory(multi_pipeline)
add_subdirectory(aes)
add_subdirectory(hash)

add_library(${PROJECT_NAME} fheader.cpp cry.cpp)

target_link_libraries(${PROJECT_NAME} PUBLIC Aes)

target_include_directories(${PROJECT_NAME} PUBLIC
                            ${PROJECT_BINARY_DIR}
                            ${PROJECT_SOURCE_DIR}/aes
                            )
                            

target_link_libraries(${PROJECT_NAME} PUBLIC Hash)

target_include_directories(${PROJECT_NAME} PUBLIC
                            ${PROJECT_BINARY_DIR}
                            ${PROJECT_SOURCE_DIR}/hash
                            )

target_link_libraries(${PROJECT_NAME} PUBLIC MultiPipeline)

target_include_directories(${PROJECT_NAME} PUBLIC
                            ${PROJECT_BINARY_DIR}
                            ${PROJECT_SOURCE_DIR}/multi_pipeline
                            )



target_link_libraries(${PROJECT_NAME} PUBLIC Valhelper)