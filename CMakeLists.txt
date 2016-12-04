cmake_minimum_required(VERSION 3.6)
project(multyEnc)
include_directories(/usr/local/lib/)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

set(SOURCE_FILES main.cpp multyEnc.h BaseEncryptor.h Fabric.h)
add_executable(multyEnc ${SOURCE_FILES})
target_link_libraries(multyEnc ${CMAKE_CURRENT_SOURCE_DIR}/libencFabric.a crypto)
