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

# Disable building tests and examples in libfort project
set(FORT_ENABLE_TESTING OFF CACHE INTERNAL "")
add_subdirectory(third-party/libfort)
target_link_libraries(${CLIENT_TARGET} PRIVATE fort)
target_link_libraries(${SERVER_TARGET} PRIVATE fort)