project(CMDvals)

add_library(${PROJECT_NAME} getval1.cpp getopts.cpp getopt_port.cpp)

target_link_libraries(${PROJECT_NAME} PUBLIC Valhelper)


target_include_directories(${PROJECT_NAME} PUBLIC
                           ${PROJECT_BINARY_DIR}
                           ${PROJECT_SOURCE_DIR}/../valhelper
                           )

