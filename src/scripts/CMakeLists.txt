# Pi-hole FTL shell scripts
# These scripts are used by various init systems (systemd, openrc, runit, etc.)
# Note: These scripts use CMAKE_INSTALL_FULL_* variables for absolute paths,
# as required for runtime execution context (systemd ExecStartPre/ExecStopPost).

# Configure utility functions script
configure_file(pihole-FTL-utils.sh.in pihole-FTL-utils.sh @ONLY)

# Configure prestart script (permissions, log setup)
configure_file(pihole-FTL-prestart.sh.in pihole-FTL-prestart.sh @ONLY)

# Configure poststop script (cleanup)
configure_file(pihole-FTL-poststop.sh.in pihole-FTL-poststop.sh @ONLY)

# Install all scripts
install(PROGRAMS
                ${CMAKE_CURRENT_BINARY_DIR}/pihole-FTL-utils.sh
                ${CMAKE_CURRENT_BINARY_DIR}/pihole-FTL-prestart.sh
                ${CMAKE_CURRENT_BINARY_DIR}/pihole-FTL-poststop.sh
        DESTINATION ${PIHOLE_INSTALL_SCRIPTDIR}
        COMPONENT scripts
)

message(STATUS "FTL helper scripts will be installed to: ${PIHOLE_INSTALL_SCRIPTDIR}")
