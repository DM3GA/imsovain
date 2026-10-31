# FindPython's Development.Module component needs CMake 3.18.
cmake_minimum_required(VERSION 3.18...3.30)

if(NOT DEFINED SKBUILD_PROJECT_NAME)
    set(SKBUILD_PROJECT_NAME imsovain)
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
find_package(Threads REQUIRED)

Python_add_library(_accel MODULE accel/module.c accel/search.c accel/filter.c accel/opencl.c WITH_SOABI)
target_include_directories(_accel PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/accel)
target_link_libraries(_accel PRIVATE OpenSSL::Crypto Threads::Threads ${CMAKE_DL_LIBS})
target_compile_definitions(_accel PRIVATE _GNU_SOURCE)
target_compile_options(_accel PRIVATE -Wall -Wextra)

# Off for installs, so a newer compiler's new warning does not break pip
# install. tests/check.py turns it on.
option(IMSOVAIN_WERROR "Treat compiler warnings as errors" OFF)
if(IMSOVAIN_WERROR)
    target_compile_options(_accel PRIVATE -Werror)
endif()

install(TARGETS _accel DESTINATION imsovain)
