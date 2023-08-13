# FILEPATH: /home/hrpccs/workspace/io-tracer/CMakeLists.txt

cmake_minimum_required(VERSION 3.0)

project(top)

if(WITH_GRAFANA)
    add_subdirectory(grafana/src)
endif()

add_subdirectory(src)

# produce compile_commands.json
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)