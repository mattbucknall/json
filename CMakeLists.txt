cmake_minimum_required(VERSION 2.8)

project(json C)

set(CMAKE_C_STANDARD 99)

add_library(json STATIC json.c)
target_include_directories(json PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(test main.c)
target_link_libraries(test PUBLIC json)

add_subdirectory(tests)
