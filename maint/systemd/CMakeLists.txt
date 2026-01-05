# Systemd service unit installation
# Note: We use paths relative to CMAKE_INSTALL_PREFIX to support
# cross-compilation and packaging systems (Yocto, Debian, etc.)

find_package(PkgConfig)

# Try to get systemd unit directory from pkg-config
if(PKG_CONFIG_FOUND)
    pkg_check_modules(LIBSYSTEMD QUIET libsystemd)
    if(LIBSYSTEMD_FOUND)
        pkg_get_variable(SYSTEMD_UNIT_DIR_PKGCONFIG systemd systemdsystemunitdir)
    endif()
endif()

# Determine systemd unit installation directory
# Logic follows FHS 3.0 and systemd conventions:
# - /opt prefix (legacy/manual install) → /etc/systemd/system/ (local admin config)
# - /usr prefix (package install) → ${PREFIX}/lib/systemd/system/ (vendor units)
if(NOT DEFINED SYSTEMD_UNIT_DIR)
    if(CMAKE_INSTALL_PREFIX MATCHES "^/opt/")
        # Legacy installation: use /etc/systemd/system/ for local admin control
        set(SYSTEMD_UNIT_DIR "${CMAKE_INSTALL_SYSCONFDIR}/systemd/system")
    elseif(SYSTEMD_UNIT_DIR_PKGCONFIG)
        # Use pkg-config detected path for FHS installations
        set(SYSTEMD_UNIT_DIR "${SYSTEMD_UNIT_DIR_PKGCONFIG}")
    else()
        # Fallback: PREFIX-relative path for cross-compile/packaging
        set(SYSTEMD_UNIT_DIR "${CMAKE_INSTALL_PREFIX}/lib/systemd/system")
    endif()
endif()

# Allow override
set(SYSTEMD_UNIT_DIR "${SYSTEMD_UNIT_DIR}" CACHE PATH "Systemd unit directory")

# Configure systemd service file
# IMPORTANT: Use CMAKE_INSTALL_FULL_* and PIHOLE_INSTALL_FULL_* variables in the
# template, as systemd Exec* directives require absolute paths. These expand at
# configure-time with CMAKE_INSTALL_PREFIX, and install() respects DESTDIR for staging.
# See: https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html#ExecStart=
configure_file(
    pihole-FTL.service.in
    pihole-FTL.service
    @ONLY
)

# Install systemd service unit
install(
    FILES ${CMAKE_CURRENT_BINARY_DIR}/pihole-FTL.service
    DESTINATION ${SYSTEMD_UNIT_DIR}
    COMPONENT systemd
)

if(CMAKE_INSTALL_PREFIX MATCHES "^/opt/")
    message(STATUS "Systemd unit (legacy install) will be installed to: ${SYSTEMD_UNIT_DIR}")
else()
    message(STATUS "Systemd unit will be installed to: ${SYSTEMD_UNIT_DIR}")
endif()
