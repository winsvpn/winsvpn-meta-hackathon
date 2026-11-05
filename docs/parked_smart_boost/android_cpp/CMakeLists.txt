cmake_minimum_required(VERSION 3.22.1)

project(winsboostnative LANGUAGES CXX)

add_library(winsboostnative SHARED smart_boost_native.cpp)

target_compile_features(winsboostnative PRIVATE cxx_std_17)
target_compile_options(winsboostnative PRIVATE -Wall -Wextra -Werror)

find_library(log-lib log)
find_library(android-lib android)
target_link_libraries(winsboostnative ${log-lib} ${android-lib})
