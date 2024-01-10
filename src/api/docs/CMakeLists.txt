# Pi-hole: A black hole for Internet advertisements
# (c) 2021 Pi-hole, LLC (https://pi-hole.net)
# Network-wide ad blocking via your own hardware.
#
# FTL Engine
# /src/api/docs/CMakeList.txt
#
# This file is copyright under the latest version of the EUPL.
# Please see LICENSE file for your rights under this license.

set(sources
        hex/index.html
        hex/index.css
        hex/pi-hole.js
        hex/external/rapidoc-min.js
        hex/external/rapidoc-min.js.map
        hex/external/highlight.min.js
        hex/external/highlight-default.min.css
        hex/images/logo.svg
        hex/specs/action.yaml
        hex/specs/auth.yaml
        hex/specs/clients.yaml
        hex/specs/config.yaml
        hex/specs/common.yaml
        hex/specs/dhcp.yaml
        hex/specs/dns.yaml
        hex/specs/docs.yaml
        hex/specs/domains.yaml
        hex/specs/endpoints.yaml
        hex/specs/groups.yaml
        hex/specs/history.yaml
        hex/specs/info.yaml
        hex/specs/lists.yaml
        hex/specs/logs.yaml
        hex/specs/main.yaml
        hex/specs/network.yaml
        hex/specs/queries.yaml
        hex/specs/search.yaml
        hex/specs/stats.yaml
        hex/specs/teleporter.yaml
        docs.c
        )

# Create relevant directories for processed content
file(MAKE_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/hex)
file(MAKE_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/hex/specs)
file(MAKE_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/hex/images)
file(MAKE_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/hex/external)

# Compile files from content/ into hex/
find_program(RESOURCE_COMPILER xxd)
file(GLOB_RECURSE COMPILED_RESOURCES RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}/content" "content/*")
foreach(INPUT_FILE ${COMPILED_RESOURCES})
    set(IN ${CMAKE_CURRENT_SOURCE_DIR}/content/${INPUT_FILE})
    set(OUTPUT_FILE ${CMAKE_CURRENT_SOURCE_DIR}/hex/${INPUT_FILE})
    add_custom_command(
        OUTPUT hex/${INPUT_FILE}
        COMMAND ${RESOURCE_COMPILER} -i < ${IN} > ${OUTPUT_FILE}
        COMMENT "Compiling ${INPUT_FILE}"
        VERBATIM)
    list(APPEND COMPILED_RESOURCES ${OUTPUT_FILE})
endforeach()

add_library(api_docs OBJECT ${sources})
target_compile_options(api_docs PRIVATE ${EXTRAWARN})
target_include_directories(api_docs PRIVATE ${PROJECT_SOURCE_DIR}/src)
