cmake_minimum_required(VERSION 3.11.2)
project(picoquic_test)

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wpedantic -Werr")

# find necessary libraries
find_package(OpenSSL REQUIRED)
if (OPENSSL_FOUND)
  include_directories(${OPENSSL_INCLUDE_DIR})
else ()
  message(FATAL_ERROR "could not find OpenSSL")
endif ()

find_package(PTLS REQUIRED)
if (PTLS_FOUND)
  include_directories(${PTLS_INCLUDE_DIRS})
  message(STATUS "PTLS_INCLUDE_DIRS: ${PTLS_INCLUDE_DIRS}")
  message(STATUS "PTLS_LIBRARIES: ${PTLS_LIBRARIES}")
endif ()

if (NOT QUICLY_ROOT_DIR)
  set(QUICLY_ROOT_DIR "${CMAKE_CURRENT_SOURCE_DIR}/quicly")
endif()
find_package(Quicly REQUIRED)
if (QUICLY_FOUND)
  include_directories(${QUICLY_INCLUDE_DIRS})
  message(STATUS "QUICLY_INCLUDE_DIRS: ${QUICLY_INCLUDE_DIRS}")
endif()

add_executable(
  quicly_client
  src/client.cpp
  src/client.hpp
  src/quicly_stuff.cpp
  src/quicly_stuff.hpp
)

add_executable(
  quicly_server
  src/server.cpp
  src/server.hpp
  src/quicly_stuff.cpp
  src/quicly_stuff.hpp
)

target_link_libraries(
  quicly_client
  ${QUICLY_LIBRARIES}
  ${PTLS_LIBRARIES}
  ${OPENSSL_LIBRARIES}
)

target_link_libraries(
  quicly_server
  ${QUICLY_LIBRARIES}
  ${PTLS_LIBRARIES}
  ${OPENSSL_LIBRARIES}
)