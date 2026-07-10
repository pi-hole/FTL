set(sources
    journal.c
    journal.h
    transport.c
    transport.h
    encode.c
    encode.h
    util.c
    util.h
    )

add_library(journal OBJECT ${sources})
target_include_directories(journal PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(journal PRIVATE pthread)
