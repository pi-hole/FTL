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
        hex/index_html.h
        hex/index_css.h
        hex/pi-hole_js.h
        hex/external/rapidoc-min_js.h
        hex/external/rapidoc-min_js_map.h
        hex/images/logo_svg.h
        hex/images/favicon_ico.h
        hex/specs/action_yaml.h
        hex/specs/auth_yaml.h
        hex/specs/clients_yaml.h
        hex/specs/config_yaml.h
        hex/specs/common_yaml.h
        hex/specs/dhcp_yaml.h
        hex/specs/dns_yaml.h
        hex/specs/docs_yaml.h
        hex/specs/domains_yaml.h
        hex/specs/endpoints_yaml.h
        hex/specs/groups_yaml.h
        hex/specs/history_yaml.h
        hex/specs/info_yaml.h
        hex/specs/lists_yaml.h
        hex/specs/logs_yaml.h
        hex/specs/main_yaml.h
        hex/specs/network_yaml.h
        hex/specs/padd_yaml.h
        hex/specs/queries_yaml.h
        hex/specs/search_yaml.h
        hex/specs/stats_yaml.h
        hex/specs/teleporter_yaml.h
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
    string(REPLACE "." "_" INPUT_FILE_MODIFIED ${INPUT_FILE})
    string(REPLACE "/" "_" VARIABLE_NAME ${INPUT_FILE})
    set(OUTPUT_FILE ${CMAKE_CURRENT_SOURCE_DIR}/hex/${INPUT_FILE_MODIFIED}.h)
    add_custom_command(
        OUTPUT hex/${INPUT_FILE_MODIFIED}.h
        COMMAND ${RESOURCE_COMPILER} -iC -n ${VARIABLE_NAME} - < ${IN} | sed "s/unsigned /static const unsigned /" > ${OUTPUT_FILE}
        COMMENT "Compiling ${INPUT_FILE}"
        VERBATIM)
    list(APPEND COMPILED_RESOURCES ${OUTPUT_FILE})
endforeach()

add_library(api_docs OBJECT ${sources})
target_compile_options(api_docs PRIVATE ${EXTRAWARN})
target_include_directories(api_docs PRIVATE ${PROJECT_SOURCE_DIR}/src)
