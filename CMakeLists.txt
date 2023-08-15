# FILEPATH: /home/hrpccs/workspace/io-tracer/CMakeLists.txt

cmake_minimum_required(VERSION 3.0)

project(top)

add_subdirectory(src)

# produce compile_commands.json
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)