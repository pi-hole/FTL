# Pi-hole: A black hole for Internet advertisements
# (c) 2021 Pi-hole, LLC (https://pi-hole.net)
# Network-wide ad blocking via your own hardware.
#
# FTL Engine
# /src/config/CMakeList.txt
#
# This file is copyright under the latest version of the EUPL.
# Please see LICENSE file for your rights under this license.

set(sources
        cli.c
        cli.h
        config.c
        config.h
        dnsmasq_config.c
        dnsmasq_config.h
        env.c
        env.h
        inotify.c
        inotify.h
        legacy_reader.c
        legacy_reader.h
        password.c
        password.h
        suggest.c
        suggest.h
        setupVars.c
        setupVars.h
        toml_writer.c
        toml_writer.h
        toml_reader.c
        toml_reader.h
        toml_helper.c
        toml_helper.h
        validator.c
        validator.h
        )

add_library(config OBJECT ${sources})

target_compile_options(config PRIVATE ${EXTRAWARN})
target_include_directories(config PRIVATE ${PROJECT_SOURCE_DIR}/src)
add_subdirectory(tomlc99)
