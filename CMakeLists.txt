cmake_minimum_required(VERSION 3.31)
project(sm3_cpp_new)

set(CMAKE_CXX_STANDARD 20)

add_executable(sm3_cpp_new main.cpp)

target_link_libraries(
        sm3_cpp_new
        #for link cryptopp
        cryptopp
        #for link openssl
        ssl
        crypto
)
