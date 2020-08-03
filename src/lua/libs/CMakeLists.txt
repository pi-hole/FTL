set(libs
        inspect.lua
        )

set(desti /etc/pihole/lua-libs)
# Alternative location
# set(desti /usr/local/lib/pihole-lua/)

install(FILES ${libs}
        DESTINATION ${desti}
        PERMISSIONS OWNER_READ GROUP_READ WORLD_READ)