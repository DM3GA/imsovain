cmake_minimum_required(VERSION 3.15...3.30)

if(NOT DEFINED SKBUILD_PROJECT_NAME)
    set(SKBUILD_PROJECT_NAME pgpgen)
endif()

project(${SKBUILD_PROJECT_NAME} LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

find_package(Python REQUIRED COMPONENTS Interpreter Development.Module)
find_package(OpenSSL REQUIRED)

Python_add_library(_accel MODULE accel/module.c accel/search.c accel/filter.c WITH_SOABI)
target_include_directories(_accel PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/accel)
target_link_libraries(_accel PRIVATE OpenSSL::Crypto)
target_compile_definitions(_accel PRIVATE _GNU_SOURCE)
target_compile_options(_accel PRIVATE -Wall -Wextra -Werror)

install(TARGETS _accel DESTINATION pgpgen)
