cmake_minimum_required(VERSION 3.0)
project(twamp-light)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -Wextra -Wall")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -Wextra -Wall -O0 -g")
# set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wno-psabi" )
# set(CMAKE_CXX_FLAGS_RELEASE "-Werror -O2")

option(USE_ASAN         "Build with address-sanitizer" OFF)

if (USE_ASAN)
  string( TOLOWER "${CMAKE_BUILD_TYPE}" buildtype_lower)
  if (NOT buildtype_lower STREQUAL "debug" )
    message(FATAL_ERROR "USE_ASAN=ON and CMAKE_BUILD_TYPE != Debug")
  endif()
  add_definitions(-fsanitize=address -static-libasan -fno-omit-frame-pointer)
  set(EXTRA_LIBS ${EXTRA_LIBS} -fsanitize=address)
endif ()

add_subdirectory(qoo-c)

set(COMMON_SOURCES
        include/utils.hpp
        include/CLI11.hpp
        src/utils.cpp
        include/packets.h
        src/TimeSync.cpp
        include/TimeSync.h
        include/Counter.h
)

set(CLIENT_TARGET twamp-light-client)
set(SERVER_TARGET twamp-light-server)


include_directories(
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/qoo-c/src
        ${CMAKE_CURRENT_SOURCE_DIR}/qoo-c/t-digest-c/src
)

add_executable(${CLIENT_TARGET}
src/client/Client.cpp
include/Client.h
src/client/main_client.cpp
${COMMON_SOURCES}
)

add_executable(${SERVER_TARGET}
src/server/Server.cpp
include/Server.h
src/server/main_server.cpp
${COMMON_SOURCES}
)

target_link_libraries(${CLIENT_TARGET} PRIVATE qoo ${EXTRA_LIBS})
target_link_libraries(${SERVER_TARGET} PRIVATE ${EXTRA_LIBS})
target_include_directories(
        ${CLIENT_TARGET} PRIVATE
)

install(TARGETS ${CLIENT_TARGET} ${SERVER_TARGET} 
        RUNTIME DESTINATION bin)
