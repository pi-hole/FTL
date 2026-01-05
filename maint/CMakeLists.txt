# Maintenance files installation (systemd, etc.)

# Add systemd support conditionally
if(INSTALL_SYSTEMD)
    add_subdirectory(systemd)
endif()
