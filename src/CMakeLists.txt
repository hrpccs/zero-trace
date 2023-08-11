# FILEPATH: /home/hrpccs/workspace/io-tracer/CMakeLists.txt
cmake_minimum_required(VERSION 3.10)

project(iotracer)

# Set the C standard to C11
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_COMPILER "clang")

# Set the C++ standard to C++17
set(CMAKE_CXX_STANDARD 17)

# Set the compiler for C++ files to clang++
set(CMAKE_CXX_COMPILER "clang++")
add_compile_options(-g -O2)

# Add all C++ files in the src directory to the project
file(GLOB_RECURSE CPP_SOURCES "*.cpp")

# Add the C and C++ sources to the project
add_executable(iotracer  ${CPP_SOURCES})
# include_directories( ${CMAKE_SOURCE_DIR}/include ${CMAKE_BINARY_DIR}/include /usr/include)
include_directories( ${CMAKE_SOURCE_DIR}/include ${CMAKE_BINARY_DIR}/include ${CMAKE_BINARY_DIR}/src/libbpf/include/uapi /usr/include)

add_dependencies(iotracer iotrace_skel)

# Create a library from iotrace.bpf.c
add_library(iotrace_bpf OBJECT ${CMAKE_SOURCE_DIR}/iotrace.bpf.c)
target_compile_options(iotrace_bpf PRIVATE  -target bpf -D__TARGET_ARCH_x86)
set_target_properties(iotrace_bpf PROPERTIES COMPILE_FLAGS "-xc")
add_dependencies(iotrace_bpf libbpf vmlinux.h iotrace_bpf_program)

add_custom_target(iotrace_bpf_program DEPENDS ${CMAKE_SOURCE_DIR}/iotrace.bpf.c)

# Generate iotrace.skel.h from iotrace.bpf.o
add_custom_command(
    OUTPUT ${CMAKE_SOURCE_DIR}/include/iotrace.skel.h
    COMMAND cp $<TARGET_OBJECTS:iotrace_bpf> /tmp/iotrace.bpf.o
    COMMAND bpftool gen skeleton  /tmp/iotrace.bpf.o  > ${CMAKE_SOURCE_DIR}/include/iotrace.skel.h 
    COMMAND rm /tmp/iotrace.bpf.o
    DEPENDS iotrace_bpf    iotrace_bpf_program 
)
# Add iotrace_bpf to the iotracer executable
target_link_libraries(iotracer ${CMAKE_BINARY_DIR}/lib64/libbpf.a elf z pthread)
add_custom_target(iotrace_skel DEPENDS ${CMAKE_SOURCE_DIR}/include/iotrace.skel.h)


# Download and build libbpf
include(ExternalProject)
set(LIBBPF_ROOT     ${CMAKE_BINARY_DIR}/src/libbpf)
set(LIBBPF_LIB_DIR   ${LIBBPF_ROOT}/lib)
set(LIBBPF_INCLUDE_DIR  ${LIBBPF_ROOT}/include)

set(LIBBPF_MAKE     cd ${LIBBPF_ROOT}/src && make  -j8 BUILD_STATIC_ONLY=1)
set(LIBBPF_INSTALL cd ${LIBBPF_ROOT}/src && make PREFIX=${CMAKE_BINARY_DIR} install)
ExternalProject_Add(libbpf
    GIT_REPOSITORY https://github.com/libbpf/libbpf.git
    GIT_TAG v1.2.0
    PREFIX                  ${CMAKE_BINARY_DIR}
    CONFIGURE_COMMAND ""
    BUILD_COMMAND  ${LIBBPF_MAKE}
    INSTALL_COMMAND  ${LIBBPF_INSTALL}
)
add_dependencies(iotracer libbpf)

add_custom_target(vmlinux.h DEPENDS ${CMAKE_SOURCE_DIR}/include/vmlinux.h)
add_custom_command(
    OUTPUT ${CMAKE_SOURCE_DIR}/include/vmlinux.h 
    COMMAND bpftool btf dump file /sys/kernel/btf/vmlinux format c > ${CMAKE_SOURCE_DIR}/include/vmlinux.h
)

# set(CMAKE_EXPORT_COMPILE_COMMANDS ON)


