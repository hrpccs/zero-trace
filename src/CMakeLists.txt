# FILEPATH: /home/hrpccs/workspace/io-tracer/CMakeLists.txt
cmake_minimum_required(VERSION 3.10)

project(iotracer)
find_package(opentelemetry-cpp CONFIG REQUIRED)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_COMPILER "clang")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_COMPILER "clang++")
add_compile_options(-g -O2 -static)

find_package(nlohmann_json QUIET)
find_package(Protobuf REQUIRED)
find_package(CURL REQUIRED)

include_directories(${CMAKE_BINARY_DIR})
file(GLOB_RECURSE CPP_SOURCES "*.cpp")
add_executable(iotracer ${CPP_SOURCES})
set(QEMU_PATH ${CMAKE_SOURCE_DIR}/src/../qemu)

include_directories(
    ${CMAKE_SOURCE_DIR}/src/include 
    ${CMAKE_BINARY_DIR}/include 
    ${CMAKE_BINARY_DIR}/src/libbpf/include/uapi 
    /usr/include 
    ${OPENTELEMETRY_CPP_INCLUDE_DIRS})

add_dependencies(iotracer iotrace_skel)
add_dependencies(iotracer qemu_uprobe_skel)

# Create a library from iotrace.bpf.c
add_library(iotrace_bpf OBJECT ${CMAKE_SOURCE_DIR}/src/iotrace.bpf.c)
target_compile_options(iotrace_bpf PRIVATE -target bpf -D__TARGET_ARCH_x86)
set_target_properties(iotrace_bpf PROPERTIES COMPILE_FLAGS "-xc")
add_dependencies(iotrace_bpf libbpf vmlinux.h iotrace_bpf_program)

add_custom_target(iotrace_bpf_program DEPENDS ${CMAKE_SOURCE_DIR}/src/iotrace.bpf.c)

# Generate iotrace.skel.h from iotrace.bpf.o
add_custom_command(
    OUTPUT ${CMAKE_SOURCE_DIR}/src/include/iotrace.skel.h
    COMMAND cp $<TARGET_OBJECTS:iotrace_bpf> /tmp/iotrace.bpf.o
    COMMAND bpftool gen skeleton /tmp/iotrace.bpf.o > ${CMAKE_SOURCE_DIR}/src/include/iotrace.skel.h
    COMMAND rm /tmp/iotrace.bpf.o
    DEPENDS iotrace_bpf iotrace_bpf_program
)

target_link_libraries(
    iotracer 
    ${CMAKE_BINARY_DIR}/lib64/libbpf.a 
    elf 
    z 
    pthread 
    ${OPENTELEMETRY_CPP_LIBRARIES}   )

add_custom_target(iotrace_skel DEPENDS ${CMAKE_SOURCE_DIR}/src/include/iotrace.skel.h)

include_directories(${QEMU_PATH}/include ${QEMU_PATH}/build)
include_directories(/usr/include/x86_64-linux-gnu /usr/include/glib-2.0 /usr/lib/x86_64-linux-gnu/glib-2.0/include)

# compile qemu_uprobe.bpf.c the same process as iotrace.bpf.c
add_library(qemu_uprobe_bpf OBJECT ${CMAKE_SOURCE_DIR}/src/qemu_uprobe.bpf.c)
target_compile_options(qemu_uprobe_bpf PRIVATE -target bpf -D__TARGET_ARCH_x86)
set_target_properties(qemu_uprobe_bpf PROPERTIES COMPILE_FLAGS "-xc -I/usr/include/x86_64-linux-gnu")
add_dependencies(qemu_uprobe_bpf libbpf vmlinux.h qemu_uprobe_bpf_program)

add_custom_target(qemu_uprobe_bpf_program DEPENDS ${CMAKE_SOURCE_DIR}/src/qemu_uprobe.bpf.c)

# Generate qemu_uprobe.skel.h from qemu_uprobe.bpf.o
add_custom_command(
    OUTPUT ${CMAKE_SOURCE_DIR}/src/include/qemu_uprobe.skel.h
    COMMAND cp $<TARGET_OBJECTS:qemu_uprobe_bpf> /tmp/qemu_uprobe.bpf.o
    COMMAND bpftool gen skeleton /tmp/qemu_uprobe.bpf.o > ${CMAKE_SOURCE_DIR}/src/include/qemu_uprobe.skel.h
    COMMAND rm /tmp/qemu_uprobe.bpf.o
    DEPENDS qemu_uprobe_bpf qemu_uprobe_bpf_program
)

add_custom_target(qemu_uprobe_skel DEPENDS ${CMAKE_SOURCE_DIR}/src/include/qemu_uprobe.skel.h)

# Download and build libbpf
include(ExternalProject)
set(LIBBPF_ROOT ${CMAKE_BINARY_DIR}/src/libbpf)
set(LIBBPF_LIB_DIR ${LIBBPF_ROOT}/lib)
set(LIBBPF_INCLUDE_DIR ${LIBBPF_ROOT}/include)

set(LIBBPF_MAKE cd ${LIBBPF_ROOT}/src && make -j8 BUILD_STATIC_ONLY=1)
set(LIBBPF_INSTALL cd ${LIBBPF_ROOT}/src && make PREFIX=${CMAKE_BINARY_DIR} install)
ExternalProject_Add(libbpf
    GIT_REPOSITORY https://github.com/libbpf/libbpf.git
    GIT_TAG v1.2.0
    PREFIX ${CMAKE_BINARY_DIR}
    CONFIGURE_COMMAND ""
    BUILD_COMMAND ${LIBBPF_MAKE}
    INSTALL_COMMAND ${LIBBPF_INSTALL}
)
add_dependencies(iotracer libbpf)

include(ExternalProject)
set(CEREAL_ROOT ${CMAKE_BINARY_DIR}/src/cereal)
set(CEREAL_INCLUDE_DIR ${CEREAL_ROOT}/include)

set(CEREAL_INSTALL cp -r ${CEREAL_ROOT}/include/cereal ${CMAKE_SOURCE_DIR}/src/include)
ExternalProject_Add(cereal
    GIT_REPOSITORY https://github.com/USCiLab/cereal.git
    PREFIX ${CMAKE_BINARY_DIR}
    CONFIGURE_COMMAND ""
    BUILD_COMMAND ""
    INSTALL_COMMAND ${CEREAL_INSTALL}
)
add_dependencies(iotracer cereal)

include(ExternalProject)

add_custom_target(vmlinux.h DEPENDS ${CMAKE_SOURCE_DIR}/src/include/vmlinux.h)
add_custom_command(
    OUTPUT ${CMAKE_SOURCE_DIR}/src/include/vmlinux.h
    COMMAND bpftool btf dump file /sys/kernel/btf/vmlinux format c > ${CMAKE_SOURCE_DIR}/src/include/vmlinux.h
)

# set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
