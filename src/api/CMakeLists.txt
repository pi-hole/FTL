set(sources
        api.c
        api.h
        msgpack.c
        request.c
        request.h
        socket.c
        socket.h
        )

add_library(api OBJECT ${sources})
add_dependencies(api gen_version)
target_compile_options(api PRIVATE ${EXTRAWARN})
target_include_directories(api PRIVATE ${PROJECT_SOURCE_DIR}/src)
