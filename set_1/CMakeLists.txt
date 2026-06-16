cmake_minimum_required(VERSION 3.20)

project(cryptopal_set1 LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

add_library(base64 src/base64.c)
target_include_directories(base64 PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)

add_executable(challenge1 src/challenge1.c)
target_link_libraries(challenge1 PRIVATE base64)

enable_testing()
add_subdirectory(tests)
