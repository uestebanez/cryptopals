find_package(GTest REQUIRED)

add_executable(Challenge1Tests challenge1_tests.cpp)
add_executable(Challenge2Tests challenge2_tests.cpp)
add_executable(Challenge5Tests challenge5_tests.cpp)
target_link_libraries(Challenge1Tests PRIVATE base64 GTest::gtest_main)
target_link_libraries(Challenge2Tests PRIVATE fixed_xor base64 GTest::gtest_main)
target_link_libraries(Challenge5Tests PRIVATE repeating_xor base64 convert GTest::gtest_main)

include(GoogleTest)
gtest_discover_tests(Challenge1Tests)
gtest_discover_tests(Challenge2Tests)
gtest_discover_tests(Challenge5Tests)
