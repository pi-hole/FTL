# Building Pi-hole FTL

## Build Requirements

### Tools
- CMake >= 3.21
- C17 compiler (GCC >= 8.1.0 or Clang >= 7.0.0)
- pkg-config

### Required Dependencies
- **nettle, hogweed, gmp** - DNSSEC support
- **libidn2, libunistring** - Internationalized Domain Names
- **mbedtls >= 4.0** - TLS support

### Optional Dependencies
- **readline, libhistory, libtermcap** - Enhanced CLI
- **systemd** - Service unit directory detection

## Build

```bash
cmake -S . -B build
cmake --build build
cmake --install build
```

## CMake Options

- `CMAKE_INSTALL_PREFIX:PATH=/path` - Installation prefix (default: `/opt/pihole`)
- `BUILD_STATIC=ON` - Static linking (default: OFF, also via env `STATIC=true`)
- `CMAKE_BUILD_TYPE=<type>` - Debug, Release, RelWithDebInfo (default), MinSizeRel
- `INSTALL_SYSTEMD=OFF` - Skip systemd unit (default: ON)

## Installation Paths

The build system uses [GNUInstallDirs](https://cmake.org/cmake/help/latest/module/GNUInstallDirs.html) for FHS 3.0 compliance. Installation paths differ based on the prefix:

### `/opt/pihole` (Default - Legacy)
- Binaries: `/opt/pihole/bin`
- Scripts: `/opt/pihole/libexec`
- Config: `/etc/pihole`
- Logs: `/var/log/pihole`
- systemd unit: `/etc/systemd/system`

### `/usr` (Package Installation)
- Binaries: `/usr/bin`
- Scripts: `/usr/lib/pihole`
- Config: `/etc/pihole`
- Logs: `/var/log/pihole`
- systemd unit: `/usr/lib/systemd/system`

### Important for Packagers

Configuration files (systemd units, shell scripts, pkg-config) use `CMAKE_INSTALL_FULL_*` variables to embed absolute paths at configure-time. This is required because:
- systemd `Exec*` directives require absolute paths ([systemd.service(5)](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html#ExecStart=))
- Shell scripts need reliable paths for sourcing utilities
- pkg-config spec requires absolute directory paths

These variables respect `DESTDIR` during installation, making them safe for staging in packaging systems (Yocto, Debian, RPM):

```bash
# Yocto/Packaging example
cmake -DCMAKE_INSTALL_PREFIX:PATH=/usr ...
DESTDIR=${WORKDIR}/image cmake --install build --prefix /usr
# Result: Files in ${WORKDIR}/image/usr/bin, service has ExecStart=/usr/bin/pihole-FTL
```

## Notes

- SQLite3 and Lua are embedded - no external installation needed
- Package names vary by distribution (e.g., `gmp-devel`, `libgmp-dev`, `gmp-dev`)
- For Yocto: Use library names directly in `DEPENDS`
- Cross-compilation: Configure pkg-config for target sysroot
