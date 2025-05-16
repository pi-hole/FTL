# Pi-hole: A black hole for Internet advertisements
# (c) 2022 Pi-hole, LLC (https://pi-hole.net)
# Network-wide ad blocking via your own hardware.
#
# FTL Engine
# /src/lua/scripts/CMakeList.txt
#
# This file is copyright under the latest version of the EUPL.
# Please see LICENSE file for your rights under this license.

set(resources
        inspect.lua
        )

set(sources
        ${resources}
	scripts.h
        )

# Ensure target lua_scripts is build before target ftl_lua depending on it
add_dependencies(ftl_lua lua_scripts)

# Compile resources files from raw/ into hex/
find_program(RESOURCE_COMPILER xxd)
foreach(res_file ${resources})
    set(INPUT_FILE ${CMAKE_CURRENT_SOURCE_DIR}/${res_file})
    set(OUTPUT_FILE ${CMAKE_CURRENT_BINARY_DIR}/${res_file}.hex)
    add_custom_command(
        OUTPUT ${OUTPUT_FILE}
	SOURCES ${INPUT_FILE}
	COMMAND ${RESOURCE_COMPILER} -i < ${INPUT_FILE} > ${OUTPUT_FILE}
        COMMENT "Compiling ${INPUT_FILE}"
        VERBATIM)
    list(APPEND COMPILED_RESOURCES ${OUTPUT_FILE})
endforeach()

add_library(lua_scripts INTERFACE ${sources})
target_sources(
    lua_scripts
    PRIVATE FILE_SET HEADERS
            BASE_DIRS ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR}
            FILES ${sources} ${COMPILED_RESOURCES}
)
target_include_directories(
    ftl_lua
    PRIVATE src ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR}
)
