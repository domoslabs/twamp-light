cmake_minimum_required(VERSION 3.0)
project(domos_twamp_light)
set(CMAKE_CXX_STANDARD 11)
set(
        SOURCES
        include/twamp_light.h
        src/utils.cpp
)
set(
        CLIENT_TARGET
        twamp-light-client
)
set(
        SERVER_TARGET
        twamp-light-server
)


include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

add_executable(${CLIENT_TARGET} src/client.cpp ${SOURCES})
add_executable(${SERVER_TARGET} src/server.cpp ${SOURCES})

install(TARGETS twamp-light-client twamp-light-server)