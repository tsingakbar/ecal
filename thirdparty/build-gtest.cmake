# Googletest automatically forces MT instead of MD if we do not set this option.
add_subdirectory(thirdparty/googletest EXCLUDE_FROM_ALL)
if(NOT TARGET GTest::gtest)
  add_library(GTest::gtest ALIAS gtest)
endif()
if(NOT TARGET GTest::gtest_main)
  add_library(GTest::gtest_main ALIAS gtest_main)
endif()