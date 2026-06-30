find_package(GTest REQUIRED)

add_executable(Challenge1Tests challenge1_tests.cpp)
add_executable(Challenge2Tests challenge2_tests.cpp)
add_executable(Challenge5Tests challenge5_tests.cpp)
add_executable(Challenge6Tests challenge6_tests.cpp)
add_executable(Challenge9Tests challenge9_tests.cpp)
add_executable(Challenge18Tests challenge18_tests.cpp)
add_executable(Challenge21Tests challenge21_tests.cpp)

target_link_libraries(Challenge1Tests PRIVATE base64 convert GTest::gtest_main)
target_link_libraries(Challenge2Tests PRIVATE 
  fixed_xor base64 convert score GTest::gtest_main)
target_link_libraries(Challenge5Tests PRIVATE 
  repeating_xor base64 convert GTest::gtest_main)
target_link_libraries(Challenge6Tests PRIVATE hamming GTest::gtest_main)
target_link_libraries(Challenge9Tests PRIVATE pkcs7 GTest::gtest_main)
target_link_libraries(Challenge18Tests PRIVATE aes128 print base64 GTest::gtest_main)
target_link_libraries(Challenge21Tests PRIVATE mt19937 GTest::gtest_main)

include(GoogleTest)
gtest_discover_tests(Challenge1Tests)
gtest_discover_tests(Challenge2Tests)
gtest_discover_tests(Challenge5Tests)
gtest_discover_tests(Challenge6Tests)
gtest_discover_tests(Challenge9Tests)
gtest_discover_tests(Challenge18Tests)
gtest_discover_tests(Challenge21Tests)
