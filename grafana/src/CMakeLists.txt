project(vis)
find_package(opentelemetry-cpp CONFIG REQUIRED)

set(CMAKE_C_COMPILER g++)

include_directories(${CMAKE_BINARY_DIR}  ${CMAKE_BINARY_DIR}/grafana/src )




find_package(nlohmann_json QUIET)
find_package(Protobuf REQUIRED)
find_package(CURL REQUIRED)


set(PROTO_FILES ${CMAKE_SOURCE_DIR}/grafana/src/message.proto)
protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS ${PROTO_FILES})

add_executable(server server.cc ${PROTO_SRCS} ${PROTO_HDRS} )

target_include_directories(server PRIVATE ${OPENTELEMETRY_CPP_INCLUDE_DIRS})
target_link_libraries(server PRIVATE ${OPENTELEMETRY_CPP_LIBRARIES})
