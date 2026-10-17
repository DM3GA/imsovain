cmake_minimum_required(VERSION 3.24)
project(sha1cuda LANGUAGES CUDA CXX)

include(CheckLanguage)
check_language(CUDA)
enable_language(CUDA)

if(NOT DEFINED CMAKE_CUDA_STANDARD)
    set(CMAKE_CUDA_STANDARD 11)
    set(CMAKE_CUDA_STANDARD_REQUIRED ON)
endif()

add_library(sha1cuda sha1.cu)

set_target_properties(sha1cuda PROPERTIES
        CUDA_SEPARABLE_COMPILATION ON)


target_include_directories(sha1cuda PUBLIC .)
