project(Multiaes)

option(GUI_OPT "Whether or not to build GUI" OFF)
if (GUI_OPT)
    add_definitions(-DGUI_ON)
endif ()

add_subdirectory(aes)

add_library(${PROJECT_NAME} multicry.cpp multi_buffergroup.cpp)
                
target_link_libraries(${PROJECT_NAME} PUBLIC Aes)

target_include_directories(${PROJECT_NAME} PUBLIC
                            ${PROJECT_BINARY_DIR}
                            ${PROJECT_SOURCE_DIR}/aes
                            )
                            
