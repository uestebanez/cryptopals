cmake_minimum_required(VERSION 3.20)

project(cryptopal_set1 LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

add_library(base64 src/base64.c)
add_library(fixed_xor src/fixed_xor.c)
add_library(repeating_xor src/repeating_xor.c)
add_library(convert src/convert.c)
target_include_directories(base64 PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_include_directories(fixed_xor PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_include_directories(repeating_xor PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_include_directories(convert PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)

add_executable(challenge1 src/challenge1.c)
add_executable(challenge3 src/challenge3.c)
add_executable(challenge4 src/challenge4.c)
target_link_libraries(challenge1 PRIVATE base64 convert)
target_link_libraries(challenge3 PRIVATE fixed_xor base64 convert)
target_link_libraries(challenge4 PRIVATE fixed_xor base64 convert)

enable_testing()
add_subdirectory(tests)
