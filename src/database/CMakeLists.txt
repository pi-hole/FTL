# SQLITE_OMIT_LOAD_EXTENSION: This option omits the entire extension loading mechanism from SQLite, including sqlite3_enable_load_extension() and sqlite3_load_extension() interfaces. (needs -ldl linking option, otherwise)
# SQLITE_DEFAULT_MEMSTATUS=0: This setting causes the sqlite3_status() interfaces that track memory usage to be disabled. This helps the sqlite3_malloc() routines run much faster, and since SQLite uses sqlite3_malloc() internally, this helps to make the entire library faster.
# SQLITE_OMIT_DEPRECATED: Omitting deprecated interfaces and features will not help SQLite to run any faster. It will reduce the library footprint, however. And it is the right thing to do.
# SQLITE_OMIT_PROGRESS_CALLBACK: The progress handler callback counter must be checked in the inner loop of the bytecode engine. By omitting this interface, a single conditional is removed from the inner loop of the bytecode engine, helping SQL statements to run slightly faster.
# SQLITE_DEFAULT_FOREIGN_KEYS=1: This macro determines whether enforcement of foreign key constraints is enabled or disabled by default for new database connections.
# SQLITE_DQS=0: This setting disables the double-quoted string literal misfeature.
set(SQLITE_DEFINES
        SQLITE_OMIT_LOAD_EXTENSION
        SQLITE_DEFAULT_MEMSTATUS=0
        SQLITE_OMIT_DEPRECATED
        SQLITE_OMIT_PROGRESS_CALLBACK
        SQLITE_OMIT_MEMORYDB
        SQLITE_DEFAULT_FOREIGN_KEYS=1
        SQLITE_DQS=0
        )

set(sqlite3_sources
        sqlite3.c
        sqlite3.h
        )

add_library(sqlite3 OBJECT ${sqlite3_sources})
target_compile_definitions(sqlite3 PRIVATE ${SQLITE_DEFINES})
target_compile_options(sqlite3 PRIVATE -Wno-implicit-fallthrough -Wno-cast-function-type)

set(database_sources
        common.c
        common.h
        database-thread.c
        database-thread.h
        gravity-db.c
        gravity-db.h
        message-table.c
        message-table.h
        network-table.c
        network-table.h
        query-table.c
        query-table.h
        sqlite3-ext.c
        sqlite3-ext.h
        )

add_library(database OBJECT ${database_sources})
target_compile_options(database PRIVATE "${EXTRAWARN}")
