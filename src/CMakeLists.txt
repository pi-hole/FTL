# Pi-hole: A black hole for Internet advertisements
# (c) 2020 Pi-hole, LLC (https://pi-hole.net)
# Network-wide ad blocking via your own hardware.
#
# FTL Engine
# /src/CMakeList.txt
#
# This file is copyright under the latest version of the EUPL.
# Please see LICENSE file for your rights under this license.

# Default to a release with debug info build
if (NOT EXISTS ${CMAKE_BINARY_DIR}/CMakeCache.txt)
    if (NOT CMAKE_BUILD_TYPE)
        set(CMAKE_BUILD_TYPE "RelWithDebInfo" CACHE STRING "" FORCE)
    endif()
endif()

# Do not add run time path information
# This ensures CMake does not add rpath information to the binary and
# subsequently strip it from the binary during install causing the binary
# validation to fail. RPATH is not needed for the FTL binary
SET(CMAKE_SKIP_RPATH TRUE)

# Put runtime output, i.e. pihole-FTL, in the root of the build dir
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR})

# SQLITE_OMIT_LOAD_EXTENSION: This option omits the entire extension loading mechanism from SQLite, including sqlite3_enable_load_extension() and sqlite3_load_extension() interfaces. (needs -ldl linking option, otherwise)
# SQLITE_DEFAULT_MEMSTATUS=0: This setting causes the sqlite3_status() interfaces that track memory usage to be disabled. This helps the sqlite3_malloc() routines run much faster, and since SQLite uses sqlite3_malloc() internally, this helps to make the entire library faster.
# SQLITE_OMIT_DEPRECATED: Omitting deprecated interfaces and features will not help SQLite to run any faster. It will reduce the library footprint, however. And it is the right thing to do.
# SQLITE_OMIT_PROGRESS_CALLBACK: The progress handler callback counter must be checked in the inner loop of the bytecode engine. By omitting this interface, a single conditional is removed from the inner loop of the bytecode engine, helping SQL statements to run slightly faster.
# SQLITE_OMIT_SHARED_CACHE: This option builds SQLite without support for shared cache mode. The sqlite3_enable_shared_cache() is omitted along with a fair amount of logic within the B-Tree subsystem associated with shared cache management. This compile-time option is recommended most applications as it results in improved performance and reduced library footprint.
# SQLITE_DEFAULT_FOREIGN_KEYS=1: This macro determines whether enforcement of foreign key constraints is enabled or disabled by default for new database connections.
# SQLITE_DQS=0: This setting disables the double-quoted string literal misfeature.
# SQLITE_ENABLE_DBPAGE_VTAB: Enables the SQLITE_DBPAGE virtual table. Warning: writing to the SQLITE_DBPAGE virtual table can very easily cause unrecoverably database corruption. It is needed for the .recover SQLite3 command.
# SQLITE_TEMP_STORE=1: This option sets the default value for the temp_store pragma to 1. This means that temporary tables and indices are always stored on disk. This is the default setting.
# SQLITE_DEFAULT_CACHE_SIZE=-16384: Allow up to 16 MiB of cache to be used by SQLite3 (default is 2000 kiB)
# SQLITE_DEFAULT_SYNCHRONOUS=1: Use normal synchronous mode (default is 2)
# SQLITE_LIKE_DOESNT_MATCH_BLOBS: This option causes the LIKE operator to only match BLOB values against BLOB values and TEXT values against TEXT values. This compile-time option makes SQLite run more efficiently when processing queries that use the LIKE operator.
# HAVE_MALLOC_H + HAVE_MALLOC_USABLE_SIZE: This option causes SQLite to try to use the malloc_usable_size() function to obtain the actual size of memory allocations from the underlying malloc() system interface. Applications are encouraged to use HAVE_MALLOC_USABLE_SIZE whenever possible.
# HAVE_FDATASYNC: This option causes SQLite to try to use the fdatasync() system call to sync the database file to disk when committing a transaction. Syncing using fdatasync() is faster than syncing using fsync() as fdatasync() does not wait for the file metadata to be written to disk.
# SQLITE_DEFAULT_WORKER_THREADS=0: This option sets the default number of worker threads to use when doing parallel sorting and indexing. The default is 0 which means to use a single thread. Do not increase this value as it, ironically, can cause performance degradation and definitely increases total memory usage.
# SQLITE_MAX_PREPARE_RETRY=200: This option sets the maximum number of automatic re-preparation attempts that can occur after encountering a schema change. This can be caused by running ANALYZE which is done periodically by FTL.
# SQLITE_ENABLE_CARRAY: Enable the carray virtual table module
# SQLITE_ENABLE_PERCENTILE: Enable the percentile aggregate function
set(SQLITE_DEFINES "-DSQLITE_OMIT_LOAD_EXTENSION -DSQLITE_DEFAULT_MEMSTATUS=0 -DSQLITE_OMIT_DEPRECATED -DSQLITE_OMIT_PROGRESS_CALLBACK -DSQLITE_OMIT_SHARED_CACHE -DSQLITE_DEFAULT_FOREIGN_KEYS=1 -DSQLITE_DQS=0 -DSQLITE_ENABLE_DBPAGE_VTAB -DSQLITE_TEMP_STORE=1 -DSQLITE_DEFAULT_CACHE_SIZE=16384 -DSQLITE_DEFAULT_SYNCHRONOUS=1 -DSQLITE_LIKE_DOESNT_MATCH_BLOBS -DHAVE_MALLOC_H -DHAVE_MALLOC_USABLE_SIZE -DHAVE_FDATASYNC -DSQLITE_DEFAULT_WORKER_THREADS=0 -DSQLITE_MAX_PREPARE_RETRY=200 -DSQLITE_ENABLE_CARRAY=1 -DSQLITE_ENABLE_PERCENTILE=1")

# Code hardening and debugging improvements
# -fstack-protector-strong: The program will be resistant to having its stack overflowed
# -Wp,-D_FORTIFY_SOURCE=3 and -O1 or higher: This causes certain unsafe glibc functions to be replaced with their safer counterparts. We may have to undefine _FORTIFY_SOURCE to avoid a warning about the redefinition of this macro
# -Wl,-z,relro: reduces the possible areas of memory in a program that can be used by an attacker that performs a successful memory corruption exploit
# -Wl,-z,now: When combined with RELRO above, this further reduces the regions of memory available to memory corruption attacks
# -g3: More debugging information
# -fno-omit-frame-pointer: get nicer stacktraces
# -funwind-tables: Generate static data for unwinding
# -fasynchronous-unwind-tables: Increased reliability of backtraces
# -fexceptions: Enable table-based thread cancellation
# -Wl,-z,defs: Detect and reject underlinking (phenomenon caused by missing shared library arguments when invoking the linked editor to produce another shared library)
# -Wl,-z,now: Disable lazy binding
# -Wl,-z,relro: Read-only segments after relocation
# -fno-common: Emit globals without explicit initializer from `.bss` to `.data`. This causes GCC to reject multiple definitions of global variables. This is the new default from GCC-10 on.
if (CMAKE_C_COMPILER_ID STREQUAL "GNU")
    set(HARDENING_FLAGS "-fstack-protector-strong -Wp,-U_FORTIFY_SOURCE -Wp,-D_FORTIFY_SOURCE=3 -Wl,-z,relro,-z,now -fexceptions -funwind-tables -fasynchronous-unwind-tables -Wl,-z,defs -Wl,-z,now -Wl,-z,relro -fno-common")
    set(DEBUG_FLAGS "-rdynamic -fno-omit-frame-pointer")
endif()

# -Wall: This enables all the warnings about constructions that some users consider questionable, and that are easy to avoid (or modify to prevent the warning), even in conjunction with macros. This also enables some language-specific warnings described in C++ Dialect Options and Objective-C and Objective-C++ Dialect Options.
# -Wextra: This enables some extra warning flags that are not enabled by -Wall.
# -Wno-unused-parameter: Disable warning for unused parameters. For threads that don't need arguments, we still have to provide a void* args which is then unused.
set(WARN_FLAGS "-Wall -Wextra -Wno-unused-parameter")

# Extra warning flags we apply only to the FTL part of the code (used not for foreign code such as dnsmasq and SQLite3)
set(EXTRAWARN_GCC6 "-Werror \
                    -Waddress \
                    -Wlogical-op \
                    -Wmissing-field-initializers \
                    -Woverlength-strings \
                    -Wformat=2 \
                    -Wformat-signedness \
                    -Wuninitialized \
                    -Wnull-dereference \
                    -Wshift-overflow=2 \
                    -Wunused-const-variable=2 \
                    -Wstrict-aliasing \
                    -Warray-bounds=2 \
                    -Wno-aggressive-loop-optimizations \
                    -Wswitch-enum \
                    -Wshadow \
                    -Wfloat-equal \
                    -Wbad-function-cast \
                    -Wwrite-strings \
                    -Wparentheses \
                    -Wlogical-op \
                    -Wstrict-prototypes \
                    -Wmissing-prototypes \
                    -Wredundant-decls \
                    -Wmissing-field-initializers \
                    -Wnormalized=nfkc \
                    -Woverride-init \
                    -Wpacked \
                    -Winline \
                    -Wpacked \
                    -Wredundant-decls \
                    -Wnested-externs \
                    -Wvla \
                    -Wvector-operation-performance \
                    -Wvolatile-register-var \
                    -Wdisabled-optimization \
                    -Wpointer-sign \
                    -Wstack-protector \
                    -Woverlength-strings")

# Extra warnings flags available only in GCC 7 and higher
if(CMAKE_C_COMPILER_VERSION VERSION_EQUAL 7 OR CMAKE_C_COMPILER_VERSION VERSION_GREATER 7)
    set(EXTRAWARN_GCC7 "-Wformat-overflow=2 \
                        -Wformat-truncation=2 \
                        -Wstringop-overflow=4 \
                        -Walloc-zero \
                        -Wint-in-bool-context")
else()
    set(EXTRAWARN_GCC7 "")
endif()

# Extra warnings flags available only in GCC 8 and higher
if(CMAKE_C_COMPILER_VERSION VERSION_EQUAL 8 OR CMAKE_C_COMPILER_VERSION VERSION_GREATER 8)
    set(EXTRAWARN_GCC8 "-Wduplicated-cond \
                        -Wduplicated-branches \
                        -Wcast-align=strict \
                        -Wlogical-not-parentheses \
                        -Wmultistatement-macros \
                        -Wmissing-attributes \
                        -Wsuggest-attribute=pure \
                        -Wsuggest-attribute=const \
                        -Wsuggest-attribute=malloc \
                        -Wsuggest-attribute=format \
                        -Wsuggest-attribute=cold")
else()
    set(EXTRAWARN_GCC8 "")
endif()

# Extra warnings flags available only in GCC 9 and higher
# The only new warning -Wabsolute-value is implied by -Wextra

# Extra warnings flags available only in GCC 10 and higher
# The new option -Wstring-compare is implied by -Wextra
# The new option -Wzero-length-bounds is implied by -Warray-bounds

# Extra warnings flags available only in GCC 11 and higher
# All new options are implied by either -Wall or -Wextra \

# Extra warnings flags available only in GCC 12 and higher
if(CMAKE_C_COMPILER_VERSION VERSION_EQUAL 12 OR CMAKE_C_COMPILER_VERSION VERSION_GREATER 12)
set(EXTRAWARN_GCC12 "-Wbidi-chars \
                     -Warray-compare")
else()
set(EXTRAWARN_GCC12 "")
endif()

# Extra warnings flags available only in GCC 13 and higher
if(CMAKE_C_COMPILER_VERSION VERSION_EQUAL 13 OR CMAKE_C_COMPILER_VERSION VERSION_GREATER 13)
set(EXTRAWARN_GCC13 "-Wenum-int-mismatch")
else()
set(EXTRAWARN_GCC13 "")
endif()

# Set extrawarn flags if CC is GCC
if (CMAKE_C_COMPILER_ID STREQUAL "GNU")
   set(EXTRAWARN "${EXTRAWARN_GCC6} \
                  ${EXTRAWARN_GCC7} \
                  ${EXTRAWARN_GCC8} \
                  ${EXTRAWARN_GCC12} \
                  ${EXTRAWARN_GCC13}")
elseif (CMAKE_C_COMPILER_ID STREQUAL "Clang")
    set(EXTRAWARN "
                   -Werror \
                   -Wnewline-eof \
                   -Wno-dangling-else \
                   -Wno-gnu-zero-variadic-macro-arguments \
                   -Wno-gnu-variable-sized-type-not-at-end \
                   -Wno-declaration-after-statement \
                   -Wno-reserved-identifier \
                   -Wno-reserved-macro-identifier")
else()
    message(WARNING "Unknown compiler, not setting warnings flags")
    set(EXTRAWARN "")
endif()

# Remove extra spaces from EXTRAWARN
string(REGEX REPLACE " +" " " EXTRAWARN "${EXTRAWARN}")

# Separate EXTRAWARN into a list of arguments
separate_arguments(EXTRAWARN)

# -Wxor-used-as-pow

# Do we want to compile a statically linked executable?
if(DEFINED ENV{STATIC})
    if($ENV{STATIC} STREQUAL "true")
        set(STATIC true)
    else()
        set(STATIC false)
    endif()
endif()
if(STATIC)
    message(STATUS "Compiling statically linked executable")
    SET(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
    SET(BUILD_SHARED_LIBS OFF)
else()
    message(STATUS "Compiling dynamically linked executable")
endif()
# -pie -fPIE: (Dynamic) position independent executable

if (CMAKE_C_COMPILER_ID STREQUAL "GNU")
    set(HARDENING_FLAGS "${HARDENING_FLAGS} -pie -fPIE")
endif()

# -FILE_OFFSET_BITS=64: used by stat(). Avoids problems with files > 2 GB on 32bit machines
# We define HAVE_POLL_H as this is needed for the musl builds to succeed
set(CMAKE_C_FLAGS "-std=c17 -pipe ${WARN_FLAGS} -D_FILE_OFFSET_BITS=64 ${HARDENING_FLAGS} ${DEBUG_FLAGS} ${CMAKE_C_FLAGS} -DHAVE_POLL_H ${SQLITE_DEFINES}")

set(CMAKE_C_FLAGS_DEBUG "-O0 -g3")
set(CMAKE_C_FLAGS_RELEASE "-O3 -DNDEBUG -funroll-loops")
set(CMAKE_C_FLAGS_RELWITHDEBINFO "${CMAKE_C_FLAGS_RELEASE} -g3")
set(CMAKE_C_FLAGS_MINSIZEREL "-Os -DNDEBUG")

set(sources
        args.c
        args.h
        capabilities.c
        capabilities.h
        daemon.c
        daemon.h
        datastructure.c
        datastructure.h
        dnsmasq_interface.c
        dnsmasq_interface.h
        edns0.c
        edns0.h
        enums.h
        events.c
        events.h
        files.c
        files.h
        FTL.h
        gc.c
        gc.h
        log.c
        log.h
        lookup-table.c
        lookup-table.h
        main.c
        main.h
        metrics.h
        overTime.c
        overTime.h
        procps.c
        procps.h
        regex.c
        regex_r.h
        resolve.c
        resolve.h
        shmem.c
        shmem.h
        signals.c
        signals.h
        timers.c
        timers.h
        vector.c
        vector.h
        version.c
        version.h
        )

# version.c is generated by gen_version.cmake
add_custom_target(
        gen_version ALL
        COMMAND ${CMAKE_COMMAND} -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER} -P ${CMAKE_CURRENT_SOURCE_DIR}/gen_version.cmake
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        BYPRODUCTS ${CMAKE_CURRENT_SOURCE_DIR}/version.c
        COMMENT "Generating version.c using gen_version.cmake")

add_library(core OBJECT ${sources})
target_compile_options(core PRIVATE ${EXTRAWARN})
target_compile_definitions(core PRIVATE DNSMASQ_VERSION=\"${DNSMASQ_VERSION}\")
target_include_directories(core PRIVATE ${PROJECT_SOURCE_DIR}/src)
add_dependencies(core gen_version)

add_executable(pihole-FTL
        $<TARGET_OBJECTS:core>
        $<TARGET_OBJECTS:api>
        $<TARGET_OBJECTS:api_docs>
        $<TARGET_OBJECTS:webserver>
        $<TARGET_OBJECTS:civetweb>
        $<TARGET_OBJECTS:cJSON>
        $<TARGET_OBJECTS:miniz>
        $<TARGET_OBJECTS:zip>
        $<TARGET_OBJECTS:database>
        $<TARGET_OBJECTS:dnsmasq>
        $<TARGET_OBJECTS:sqlite3>
        $<TARGET_OBJECTS:lua>
        $<TARGET_OBJECTS:ftl_lua>
        $<TARGET_OBJECTS:tre-regex>
        $<TARGET_OBJECTS:syscalls>
        $<TARGET_OBJECTS:tomlc17>
        $<TARGET_OBJECTS:config>
        $<TARGET_OBJECTS:tools>
        $<TARGET_OBJECTS:ntp>
        )
if(STATIC)
    set_target_properties(pihole-FTL PROPERTIES LINK_SEARCH_START_STATIC ON)
    set_target_properties(pihole-FTL PROPERTIES LINK_SEARCH_END_STATIC ON)
    target_link_libraries(pihole-FTL -static-libgcc -static)
    set(LIBRARY_SUFFIX "${CMAKE_STATIC_LIBRARY_SUFFIX}")
else()
    find_library(LIBMATH m)
    target_link_libraries(pihole-FTL ${LIBMATH})
    set(LIBRARY_SUFFIX "")
endif()
set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
set(THREADS_PREFER_PTHREAD_FLAG TRUE)
find_package(Threads REQUIRED)

# for DNSSEC we need the nettle (+ hogweed) crypto and the gmp math libraries
find_library(LIBHOGWEED NAMES libhogweed${LIBRARY_SUFFIX} hogweed HINTS /usr/local/lib64)
find_library(LIBGMP NAMES libgmp${LIBRARY_SUFFIX} gmp)
find_library(LIBNETTLE NAMES libnettle${LIBRARY_SUFFIX} nettle HINTS /usr/local/lib64)

# for IDN2 we need the idn2 library which in turn depends on the unistring library
find_library(LIBIDN2 NAMES libidn2${LIBRARY_SUFFIX} idn2)
find_library(LIBUNISTRING NAMES libunistring${LIBRARY_SUFFIX} unistring)

target_link_libraries(pihole-FTL rt Threads::Threads ${LIBHOGWEED} ${LIBGMP} ${LIBNETTLE} ${LIBIDN2} ${LIBUNISTRING})

if(LUA_DL STREQUAL "true")
    find_library(LIBDL dl)
    target_link_libraries(pihole-FTL ${LIBDL})
endif()

add_subdirectory(api)
add_subdirectory(webserver)
add_subdirectory(zip)
add_subdirectory(database)
add_subdirectory(dnsmasq)
add_subdirectory(lua)
add_subdirectory(lua/scripts)
add_subdirectory(tre-regex)
add_subdirectory(syscalls)
add_subdirectory(config)
add_subdirectory(tools)
add_subdirectory(ntp)

find_library(LIBREADLINE NAMES libreadline${LIBRARY_SUFFIX} readline)
find_library(LIBHISTORY NAMES libhistory${LIBRARY_SUFFIX} history)
find_library(LIBTERMCAP NAMES libtermcap${LIBRARY_SUFFIX} termcap)
if(LIBREADLINE AND LIBHISTORY AND LIBTERMCAP)
    message(STATUS "Building FTL with readline support: YES")
    target_compile_definitions(lua PRIVATE LUA_USE_READLINE)
    target_compile_definitions(sqlite3 PRIVATE HAVE_READLINE)
    target_link_libraries(pihole-FTL ${LIBREADLINE} ${LIBHISTORY} ${LIBTERMCAP})
else()
    message(STATUS "Building FTL with readline support: NO")
endif()

if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
    set(CMAKE_INSTALL_PREFIX "/usr" CACHE PATH "..." FORCE)
endif()

find_library(LIBMBEDCRYPTO NAMES lmbedcrypto${LIBRARY_SUFFIX} mbedcrypto)
find_library(LIBMBEDX509 NAMES lmbedx509${LIBRARY_SUFFIX} mbedx509)
find_library(LIBMBEDTLS NAMES lmbedtls${LIBRARY_SUFFIX} mbedtls)
if(LIBMBEDCRYPTO AND LIBMBEDX509 AND LIBMBEDTLS)
    # Enable TLS support in civetweb if mbedTLS is available
    message(STATUS "Building FTL with TLS support: YES")
    target_compile_definitions(core PRIVATE HAVE_MBEDTLS)
    target_compile_definitions(civetweb PRIVATE USE_MBEDTLS)
    target_compile_definitions(webserver PRIVATE HAVE_MBEDTLS)
    # Link against the mbedTLS libraries, the order is important (!)
    target_link_libraries(pihole-FTL ${LIBMBEDTLS} ${LIBMBEDX509} ${LIBMBEDCRYPTO})
else()
    # Disable TLS support in civetweb if mbedTLS is not available
    message(STATUS "Building FTL with TLS support: NO")
    target_compile_definitions(civetweb PRIVATE NO_SSL)
endif()

# After finishing building the FTL binary, we append the sha256sum of the binary
# in raw form to itself and print the checksum to the console
add_custom_command(TARGET pihole-FTL POST_BUILD COMMENT "Appending sha256sum to pihole-FTL"
        COMMAND echo -n "SHA256 checksum of pihole-FTL: " && sha256sum $<TARGET_FILE:pihole-FTL> | cut -d ' ' -f 1
        COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:pihole-FTL> $<TARGET_FILE_DIR:pihole-FTL>/pihole-FTL.tmp
        COMMAND echo -n "sha256sum" >> $<TARGET_FILE:pihole-FTL>.tmp
        COMMAND sha256sum $<TARGET_FILE:pihole-FTL>.tmp | cut -d ' ' -f 1 | xxd -r -p >> $<TARGET_FILE:pihole-FTL>.tmp
        COMMAND mv $<TARGET_FILE:pihole-FTL>.tmp $<TARGET_FILE:pihole-FTL>
        )

######### Installation target ############
# Install the binary
install(TARGETS pihole-FTL
        RUNTIME DESTINATION bin
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
find_program(SETCAP setcap)
# After installing the binary, we set the capabilities on the binary ...
install(CODE "execute_process(COMMAND ${SETCAP} CAP_NET_BIND_SERVICE,CAP_NET_RAW,CAP_NET_ADMIN,CAP_SYS_NICE,CAP_CHOWN,CAP_SYS_TIME+eip \${CMAKE_INSTALL_PREFIX}/bin/pihole-FTL)")
# ... and verify the binary integrity
install(CODE "execute_process(COMMAND \${CMAKE_INSTALL_PREFIX}/bin/pihole-FTL verify)")
