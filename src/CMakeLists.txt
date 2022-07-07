# Pi-hole: A black hole for Internet advertisements
# (c) 2020 Pi-hole, LLC (https://pi-hole.net)
# Network-wide ad blocking via your own hardware.
#
# FTL Engine
# /src/CMakeList.txt
#
# This file is copyright under the latest version of the EUPL.
# Please see LICENSE file for your rights under this license.

set(CMAKE_C_STANDARD 11)

# Default to a release with debug info build
if (NOT EXISTS ${CMAKE_BINARY_DIR}/CMakeCache.txt)
    if (NOT CMAKE_BUILD_TYPE)
        set(CMAKE_BUILD_TYPE "RelWithDebInfo" CACHE STRING "" FORCE)
    endif()
endif()

# Put runtime output, i.e. pihole-FTL, in the root of the build dir
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR})

# SQLITE_OMIT_LOAD_EXTENSION: This option omits the entire extension loading mechanism from SQLite, including sqlite3_enable_load_extension() and sqlite3_load_extension() interfaces. (needs -ldl linking option, otherwise)
# SQLITE_DEFAULT_MEMSTATUS=0: This setting causes the sqlite3_status() interfaces that track memory usage to be disabled. This helps the sqlite3_malloc() routines run much faster, and since SQLite uses sqlite3_malloc() internally, this helps to make the entire library faster.
# SQLITE_OMIT_DEPRECATED: Omitting deprecated interfaces and features will not help SQLite to run any faster. It will reduce the library footprint, however. And it is the right thing to do.
# SQLITE_OMIT_PROGRESS_CALLBACK: The progress handler callback counter must be checked in the inner loop of the bytecode engine. By omitting this interface, a single conditional is removed from the inner loop of the bytecode engine, helping SQL statements to run slightly faster.
# SQLITE_DEFAULT_FOREIGN_KEYS=1: This macro determines whether enforcement of foreign key constraints is enabled or disabled by default for new database connections.
# SQLITE_DQS=0: This setting disables the double-quoted string literal misfeature.
# SQLITE_ENABLE_DBPAGE_VTAB: Enables the SQLITE_DBPAGE virtual table. Warning: writing to the SQLITE_DBPAGE virtual table can very easily cause unrecoverably database corruption.
# SQLITE_OMIT_DESERIALIZE: This option causes the the sqlite3_serialize() and sqlite3_deserialize() interfaces to be omitted from the build (was the default before 3.36.0)
# HAVE_READLINE: Enable readline support to allow easy editing, history and auto-completion
set(SQLITE_DEFINES "-DSQLITE_OMIT_LOAD_EXTENSION -DSQLITE_DEFAULT_MEMSTATUS=0 -DSQLITE_OMIT_DEPRECATED -DSQLITE_OMIT_PROGRESS_CALLBACK -DSQLITE_DEFAULT_FOREIGN_KEYS=1 -DSQLITE_DQS=0 -DSQLITE_ENABLE_DBPAGE_VTAB -DSQLITE_OMIT_DESERIALIZE -DHAVE_READLINE")

# Code hardening and debugging improvements
# -fstack-protector-strong: The program will be resistant to having its stack overflowed
# -Wp,-D_FORTIFY_SOURCE=2 and -O1 or higher: This causes certain unsafe glibc functions to be replaced with their safer counterparts
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
set(HARDENING_FLAGS "-fstack-protector-strong -Wp,-D_FORTIFY_SOURCE=2 -Wl,-z,relro,-z,now -fexceptions -funwind-tables -fasynchronous-unwind-tables -Wl,-z,defs -Wl,-z,now -Wl,-z,relro -fno-common")
set(DEBUG_FLAGS "-rdynamic -fno-omit-frame-pointer")

# -Wall: This enables all the warnings about constructions that some users consider questionable, and that are easy to avoid (or modify to prevent the warning), even in conjunction with macros. This also enables some language-specific warnings described in C++ Dialect Options and Objective-C and Objective-C++ Dialect Options.
# -Wextra: This enables some extra warning flags that are not enabled by -Wall.
# -Wno-unused-parameter: Disable warning for unused parameters. For threads that don't need arguments, we still have to provide a void* args which is then unused.
set(WARN_FLAGS "-Wall -Wextra -Wno-unused-parameter")

# Extra warning flags we apply only to the FTL part of the code (used not for foreign code such as dnsmasq and SQLite3)
# -Werror: Halt on any warnings, useful for enforcing clean code without any warnings (we use it only for our code part)
# -Waddress: Warn about suspicious uses of memory addresses
# -Wlogical-op: Warn about suspicious uses of logical operators in expressions
# -Wmissing-field-initializers: Warn if a structure's initializer has some fields missing
# -Woverlength-strings: Warn about string constants that are longer than the "minimum maximum length specified in the C standard
# -Wformat: Check calls to printf and scanf, etc., to make sure that the arguments supplied have types appropriate to the format string specified, and that the conversions specified in the format string make sense.
# -Wformat-nonliteral: If -Wformat is specified, also warn if the format string is not a string literal and so cannot be checked, unless the format function takes its format arguments as a va_list.
# -Wuninitialized: Warn if an automatic variable is used without first being initialized
# -Wswitch-enum: Warn whenever a switch statement has an index of enumerated type and lacks a case for one or more of the named codes of that enumeration.
# -Wshadow: Warn whenever a local variable or type declaration shadows another variable, parameter, type, class member, or whenever a built-in function is shadowed.
# -Wfloat-equal: Warn if floating-point values are used in equality comparisons
# -Wpointer-arith: Warn about anything that depends on the "size of" a function type or of "void".  GNU C assigns these types a size of 1
# -Wundef: Warn if an undefined identifier is evaluated in an "#if" directive
# -Wbad-function-cast: Warn when a function call is cast to a non-matching type
# -Wwrite-strings: When compiling C, give string constants the type "const char[length]" so that copying the address of one into a non-"const" "char *" pointer produces a warning
# -Wparentheses: Warn if parentheses are omitted in certain contexts, such as when there is an assignment in a context where a truth value is expected, or when operators are nested whose precedence people often get confused about
# -Wlogical-op: Warn about suspicious uses of logical operators in expressions
# -Wstrict-prototypes: Warn if a function is declared or defined without specifying the argument types
# -Wmissing-prototypes: Warn if a global function is defined without a previous prototype declaration
# -Wredundant-decls: Warn if anything is declared more than once in the same scope
# -Winline: Warn if a function that is declared as inline cannot be inlined
if(CMAKE_C_COMPILER_VERSION VERSION_EQUAL 8 OR CMAKE_C_COMPILER_VERSION VERSION_GREATER 8)
    # -Wduplicated-cond: Warn about duplicated conditions in an if-else-if chain
    # -Wduplicated-branches: Warn when an if-else has identical branches
    # -Wcast-align=strict: Warn whenever a pointer is cast such that the required alignment of the target is increased. For example, warn if a "char *" is cast to an "int *" regardless of the target machine.
    # -Wlogical-not-parentheses: Warn about logical not used on the left hand side operand of a comparison
    set(EXTRAWARN_GCC8 "-Wduplicated-cond -Wduplicated-branches -Wcast-align=strict -Wlogical-not-parentheses -Wsuggest-attribute=pure -Wsuggest-attribute=const -Wsuggest-attribute=malloc -Wsuggest-attribute=format -Wsuggest-attribute=cold")
else()
    set(EXTRAWARN_GCC8 "")
endif()
set(EXTRAWARN "-Werror -Waddress -Wlogical-op -Wmissing-field-initializers -Woverlength-strings -Wformat -Wformat-nonliteral -Wuninitialized -Wswitch-enum -Wshadow -Wfloat-equal -Wbad-function-cast -Wwrite-strings -Wparentheses -Wlogical-op -Wstrict-prototypes -Wmissing-prototypes -Wredundant-decls -Winline ${EXTRAWARN_GCC8}")
separate_arguments(EXTRAWARN)

# Do we want to compile a statically linked musl executable?
if(STATIC STREQUAL "true")
    SET(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
    SET(BUILD_SHARED_LIBS OFF)
endif()
# -pie -fPIE: (Dynamic) position independent executable
set(HARDENING_FLAGS "${HARDENING_FLAGS} -pie -fPIE")

# -FILE_OFFSET_BITS=64: used by stat(). Avoids problems with files > 2 GB on 32bit machines
# We define HAVE_POLL_H as this is needed for the musl builds to succeed
set(CMAKE_C_FLAGS "-pipe ${WARN_FLAGS} -D_FILE_OFFSET_BITS=64 ${HARDENING_FLAGS} ${DEBUG_FLAGS} ${CMAKE_C_FLAGS} -DHAVE_POLL_H ${SQLITE_DEFINES}")

set(CMAKE_C_FLAGS_DEBUG "-O0 -g3")
set(CMAKE_C_FLAGS_RELEASE "-O3 -DNDEBUG")
set(CMAKE_C_FLAGS_RELWITHDEBINFO "${CMAKE_C_FLAGS_RELEASE} -g3")
set(CMAKE_C_FLAGS_MINSIZEREL "-Os -DNDEBUG")

set(sources
        args.c
        args.h
        capabilities.c
        capabilities.h
        config.c
        config.h
        daemon.c
        daemon.h
        datastructure.c
        datastructure.h
        dhcp-discover.c
        dhcp-discover.h
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
        main.c
        main.h
        overTime.c
        overTime.h
        procps.c
        procps.h
        regex.c
        regex_r.h
        resolve.c
        resolve.h
        setupVars.c
        setupVars.h
        shmem.c
        shmem.h
        signals.c
        signals.h
        struct_size.c
        struct_size.h
        timers.c
        timers.h
        vector.c
        vector.h
        version.h
        )

set_source_files_properties(version.h PROPERTIES GENERATED TRUE)

add_custom_target(
        gen_version ALL
        COMMAND ${CMAKE_COMMAND} -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER} -P ${CMAKE_CURRENT_SOURCE_DIR}/gen_version.cmake
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

add_library(FTL OBJECT ${sources})
target_compile_options(FTL PRIVATE ${EXTRAWARN})
target_compile_definitions(FTL PRIVATE DNSMASQ_VERSION=\"${DNSMASQ_VERSION}\")
target_include_directories(FTL PRIVATE ${PROJECT_SOURCE_DIR}/src)
add_dependencies(FTL gen_version)


add_executable(pihole-FTL
        $<TARGET_OBJECTS:FTL>
        $<TARGET_OBJECTS:api>
        $<TARGET_OBJECTS:database>
        $<TARGET_OBJECTS:dnsmasq>
        $<TARGET_OBJECTS:sqlite3>
        $<TARGET_OBJECTS:lua>
        $<TARGET_OBJECTS:tre-regex>
        $<TARGET_OBJECTS:syscalls>
        )
if(STATIC STREQUAL "true")
    set_target_properties(pihole-FTL PROPERTIES LINK_SEARCH_START_STATIC ON)
    set_target_properties(pihole-FTL PROPERTIES LINK_SEARCH_END_STATIC ON)
    target_link_libraries(pihole-FTL -static-libgcc -static -pie)
else()
    find_library(LIBMATH m)
    target_link_libraries(pihole-FTL ${LIBMATH})
endif()
set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
set(THREADS_PREFER_PTHREAD_FLAG TRUE)
find_package(Threads REQUIRED)

# for DNSSEC we need the nettle (+ hogweed) crypto and the gmp math libraries
find_library(LIBHOGWEED NAMES libhogweed${CMAKE_STATIC_LIBRARY_SUFFIX} hogweed)
find_library(LIBGMP NAMES libgmp${CMAKE_STATIC_LIBRARY_SUFFIX} gmp)
find_library(LIBNETTLE NAMES libnettle${CMAKE_STATIC_LIBRARY_SUFFIX} nettle)
find_library(LIBIDN NAMES libidn${CMAKE_STATIC_LIBRARY_SUFFIX} idn)

target_link_libraries(pihole-FTL rt Threads::Threads ${LIBHOGWEED} ${LIBGMP} ${LIBNETTLE} ${LIBIDN})

if(LUA_DL STREQUAL "true")
    find_library(LIBDL dl)
    target_link_libraries(pihole-FTL ${LIBDL})
endif()

find_library(LIBREADLINE NAMES libreadline${CMAKE_STATIC_LIBRARY_SUFFIX} readline)
find_library(LIBHISTORY NAMES libhistory${CMAKE_STATIC_LIBRARY_SUFFIX} history)
find_library(LIBTERMCAP NAMES libtermcap${CMAKE_STATIC_LIBRARY_SUFFIX} termcap)
if(LIBREADLINE AND LIBHISTORY AND LIBTERMCAP)
    message(STATUS "Building FTL with readline support: YES")
    target_compile_definitions(FTL PRIVATE LUA_USE_READLINE)
    target_compile_definitions(pihole-FTL PRIVATE LUA_USE_READLINE)
    target_link_libraries(pihole-FTL ${LIBREADLINE} ${LIBHISTORY} ${LIBTERMCAP})
else()
    message(STATUS "Building FTL with readline support: NO")
endif()

if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
    set(CMAKE_INSTALL_PREFIX "/usr" CACHE PATH "..." FORCE)
endif()

find_program(SETCAP setcap)
install(TARGETS pihole-FTL
        RUNTIME DESTINATION bin
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
install(CODE "execute_process(COMMAND ${SETCAP} CAP_NET_BIND_SERVICE,CAP_NET_RAW,CAP_NET_ADMIN,CAP_SYS_NICE+eip \$ENV{DESTDIR}\${CMAKE_INSTALL_PREFIX}/bin/pihole-FTL)")

add_subdirectory(api)
add_subdirectory(database)
add_subdirectory(dnsmasq)
add_subdirectory(lua)
add_subdirectory(tre-regex)
add_subdirectory(syscalls)
