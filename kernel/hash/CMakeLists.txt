project(Hash)

add_library(${PROJECT_NAME} hashbuffer.cpp sha1.cpp md5.cpp sha256.cpp sha_ni.cpp hashmaster.cpp)