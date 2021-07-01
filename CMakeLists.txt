cmake_minimum_required(VERSION 3.19)
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
# Downloads libfort and saves the source dir into the variable "libfort_SOURCE_DIR"
include(DownloadProject.cmake)
download_project(PROJ       libfort
        GIT_REPOSITORY      https://github.com/seleznevae/libfort.git
        GIT_TAG             master
        )

add_subdirectory(${libfort_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

add_executable(${CLIENT_TARGET} src/client.cpp ${SOURCES})
add_executable(${SERVER_TARGET} src/server.cpp ${SOURCES})

# Disable building tests and examples in libfort project
set(FORT_ENABLE_TESTING OFF CACHE INTERNAL "")


target_link_libraries(${CLIENT_TARGET} PRIVATE fort)
target_link_libraries(${SERVER_TARGET} PRIVATE fort)