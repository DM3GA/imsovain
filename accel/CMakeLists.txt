cmake_minimum_required(VERSION 3.15)
project(accel_cuda LANGUAGES C)

add_subdirectory(sha1cuda)

add_executable(accel_cuda accel_cuda.c)
target_link_libraries(accel_cuda PRIVATE sha1cuda)
