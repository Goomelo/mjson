cmake_minimum_required(VERSION 3.19)
project(mjson C)

set(CMAKE_C_STANDARD 11)

include_directories(.)

add_executable(mjson
        mjson.c
        mjson.h
        test.c)
