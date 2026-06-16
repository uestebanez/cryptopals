find_package(GTest REQUIRED)

add_executable(Challenge1Tests challenge1_tests.cpp)
target_link_libraries(Challenge1Tests PRIVATE base64 GTest::gtest_main)

include(GoogleTest)
gtest_discover_tests(Challenge1Tests)
