# Pi-hole: A black hole for Internet advertisements
# (c) 2022 Pi-hole, LLC (https://pi-hole.net)
# Network-wide ad blocking via your own hardware.
#
# FTL Engine
# /src/lua/scripts/CMakeList.txt
#
# This file is copyright under the latest version of the EUPL.
# Please see LICENSE file for your rights under this license.

set(sources
        inspect.lua.hex
        scripts.h
        )

# Compile files from raw/ into hex/
find_program(RESOURCE_COMPILER xxd)
file(GLOB_RECURSE COMPILED_RESOURCES RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}/" "./*.lua")
foreach(INPUT_FILE ${COMPILED_RESOURCES})
    set(IN ${CMAKE_CURRENT_SOURCE_DIR}/${INPUT_FILE})
    set(OUTPUT_FILE ${CMAKE_CURRENT_SOURCE_DIR}/${INPUT_FILE}.hex)
    add_custom_command(
        OUTPUT ${INPUT_FILE}.hex
        COMMAND ${RESOURCE_COMPILER} -i < ${IN} > ${OUTPUT_FILE}
        COMMENT "Compiling ${INPUT_FILE}"
        VERBATIM)
    list(APPEND COMPILED_RESOURCES ${OUTPUT_FILE})
endforeach()

# Ensure target lua_scripts is build before target lua
add_dependencies(lua lua_scripts)

add_library(lua_scripts OBJECT ${sources})
target_compile_options(lua_scripts PRIVATE ${EXTRAWARN})
target_include_directories(lua_scripts PRIVATE ${PROJECT_SOURCE_DIR}/src)
