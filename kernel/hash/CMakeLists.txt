project(Hash)

option(GUI_OPT "Whether or not to build GUI" OFF)
if (GUI_OPT)
    add_definitions(-DGUI_ON)
endif ()

add_library(${PROJECT_NAME} hashbuffer.cpp sha1.cpp md5.cpp sha256.cpp hashmaster.cpp)