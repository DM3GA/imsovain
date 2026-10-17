cmake_minimum_required(VERSION 3.16)
project(pgpgen VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(FATAL_ERROR "pgpgen-accel uses Linux prctl")
endif()

find_package(OpenSSL REQUIRED)

add_executable(pgpgen-accel accel/accel_openssl.c)
target_link_libraries(pgpgen-accel PRIVATE OpenSSL::Crypto)
target_compile_definitions(pgpgen-accel PRIVATE _GNU_SOURCE)
target_compile_options(pgpgen-accel PRIVATE -Wall -Wextra -Werror)

install(TARGETS pgpgen-accel RUNTIME DESTINATION bin)
