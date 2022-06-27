cmake_minimum_required(VERSION 3.16)
project(cpp_symbol_sampletransaction CXX)

set(CMAKE_CXX_STANDARD 20)
set(CONAN_CMAKE_CXX_STANDARD 20)

include(${CMAKE_BINARY_DIR}/conanbuildinfo.cmake)
conan_basic_setup()

add_executable(cpp_symbol_sampletransaction main.cpp)
target_link_libraries(cpp_symbol_sampletransaction ${CONAN_LIBS})
