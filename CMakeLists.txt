cmake_minimum_required(VERSION 3.19)
project(domos_twamp_light)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
set(CMAKE_CXX_STANDARD 14)
set(
        SOURCES
        include/twamp_light.h
        src/utils.cpp)
add_executable(client src/client.cpp ${SOURCES})
add_executable(server src/server.cpp ${SOURCES})