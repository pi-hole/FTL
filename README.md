## Pi-hole FTL

(c) 2017 Pi-hole, LLC (https://pi-hole.net)

![](https://i1.wp.com/pi-hole.net/wp-content/uploads/2017/01/dominik.gif?w=128&ssl=1)

This project is copyright under the latest version of the EUPL.

Please see `LICENSE` file for your rights under this license.

[![Codacy Badge](https://api.codacy.com/project/badge/Grade/4ed93e1a06fe4600ba991ef33078973c)](https://www.codacy.com/app/Pi-hole/FTL?utm_source=github.com&utm_medium=referral&utm_content=pi-hole/FTL&utm_campaign=badger)

---

### Compatibility list

| Board | Tested OS | CPU architecture | Suitable binaries | Tested by |
|---|---|---|---|---|
| VirtualBox | Ubuntu 16.10 | amd64 | `linux-x86_64` | [@DL6ER](https://github.com/dl6er) |
| Raspberry Pi Zero | Raspbian Jessie | armv6l | `arm-linux-gnueabi` | [@DanSchaper](https://github.com/dschaper) |
| Raspberry Pi 1 | Raspbian Jessie | armv6 | `arm-linux-gnueabi` | [@DL6ER](https://github.com/dl6er) |
| Raspberry Pi 2 | Raspbian Jessie | armv7l | `arm-linux-gnueabihf` and `arm-linux-gnuabi` | [@TechnicalPyro](https://github.com/technicalpyro) |
| Raspberry Pi 3 | Raspbian Jessie | armv7l | `arm-linux-gnuabi` and `arm-linux-gnueabihf` | [@DL6ER](https://github.com/dl6er) |
| Raspberry Pi 3 | openSUSE | aarch64 | `aarch64-linux-gnu` | [@DL6ER](https://github.com/dl6er) |
| NanoPi NEO | armbian Ubuntu 16.04 | armv7l | `arm-linux-gnueabihf` | [@DL6ER](https://github.com/dl6er) |
| Odroid-C2 | Ubuntu 16.04 | aarch64 | `aarch64-linux-gnu` | [@DanSchaper](https://github.com/dschaper) |
| C.H.I.P | Debian | armv7l | `arm-linux-gnueabihf` | [@Promofaux](https://github.com/promofaux) |
| OrangePi Zero | armbian Ubuntu 16.04 | armv7l | `arm-linux-gnueabihf` | [@DL6ER](https://github.com/dl6er) |
| BeagleBone Black| Debian Jessie | armv7l | `arm-linux-gnueabihf` | [@frosty5689](https://github.com/frosty5689) |
|  |  |  |  |  |

If your device is not listed you can get your CPU architecture by running `lscpu`. Download some binaries and try which one work. If you want to add a new device, open an issue or create a PR for the README.

---

### How to test FTL?

`FTL` is now part of the Pi-hole `development` branches.
If you want to test it, use `pihole checkout dev`

### How to compile FTL from source?

1. Clone the repo
2. `make`
3. `sudo make install`
4. `sudo service pihole-FTL start`

### Debugging `pihole-FTL`

#### Debugging instructions (when `FTL` is not starting reliably)

Once you are used to it, you can skip most of the steps and debugging is actually quite easy and gives you insights into how software (not limited to `pihole-FTL`) works.

1. Install `screen` and `gdb` (probably `sudo apt-get install screen gdb`)
2. Start a screen session (it will allow you to come back even if the SSH connection died)
  * If you don't know about `screen`, then read about it (you *will* love it!)
3. Start a screen session using `screen`
4. Ensure that `pihole-FTL` is terminated (e.g. `sudo killall pihole-FTL`)
5. Arrange file permissions to be able to start `FTL` as your current user (the following assumes you are logged in as user `pi`).
  * `sudo touch /var/log/pihole-FTL.log /run/pihole-FTL.pid /run/pihole-FTL.port`
  * `sudo chown pi:pi /var/log/pihole-FTL.log /run/pihole-FTL.pid /run/pihole-FTL.port`
  * `sudo chmod 0644 /var/log/pihole-FTL.log /run/pihole-FTL.pid /run/pihole-FTL.port`
6. Start `pihole-FTL` in the debugger: `gdb pihole-FTL`
7. Type `handle SIGHUP nostop SIGPIPE nostop` to instruct the debugger to don't stop on expected signals
8. Type `run debug` to start `FTL` (you should see some lines of text and `FTL` should start successfully)
9. You can now close the terminal (Ctrl+A and then D to detach) and come back later using (`screen -r`) when it has crashed
10. If it has crashed, copy&paste the terminal output, and
11. type also `backtrace` and post the output in a (new) issue
12. We might ask for additional information in order to isolate your particular issue

#### Simplified debugging instructions (when `FTL` is running)

`FTL` has been designed such that a debugger can be attached to an already running process to ease debugging. Use `sudo gdb -p $(pidof pihole-FTL)` to attach to an already running `pihole-FTL` process. You can leave off `sudo` if you are running `pihole-FTL` with the current user. Once loading of the symbols has finished (the `(gdb)` input prompt is shown), run `handle SIGHUP nostop SIGPIPE nostop` followed by `continue` to continue operation of `pihole-FTL` inside the debugger. All debugger features are now available.

If `pihole-FTL` has crashed, copy&paste the terminal output into a (new) issue. Also type `backtrace` and include its output. We might ask for additional information in order to isolate your particular issue.

When you want to detach the debugger from `FTL` without terminating the process, you can hit `Ctrl+C` and enter `detach` followed by `quit`.

### Command line arguments

- `debug` - Don't go into daemon mode (stay in foreground) + more verbose logging
- `test` - Start `FTL` and process everything, but shut down immediately afterwards
- `version` - Don't start `FTL`, show only version
- `tag` - Don't start `FTL`, show only git tag
- `branch` - Don't start `FTL`, show only git branch `FTL` was compiled from
- `no-daemon` or `-f` - Don't go into background (daemon mode)
- `help` or `-h` - Don't start `FTL`, show help

Command line arguments can be arbitrarily combined, e.g. `pihole-FTL debug test`

### File locations
- `/var/log/pihole-FTL.log` log file
- `/var/run/pihole-FTL.pid` PID file
- `/var/run/pihole-FTL.port` file containing port on which `FTL` is listening

### Socket connections

connect via e.g. `telnet 127.0.0.1 4711`
port may be automatically incremented if `4711` isn't available

### FTL's config file

You can create a file `/etc/pihole/pihole-FTL.conf` that will be read by `FTL` on startup.

Possible settings (**the option shown first is the default**):

- `SOCKET_LISTENING=localonly|all` (Listen only for local socket connections or permit all connections)
- `TIMEFRAME=rolling24h|yesterday|today` (Rolling data window, up to 48h (today + yesterday), or up to 24h (only today, as in Pi-hole `v2.x` ))
- `QUERY_DISPLAY=yes|no` (Display all queries? Set to `no` to hide query display)
- `AAAA_QUERY_ANALYSIS=yes|no` (Allow `FTL` to analyze AAAA queries from pihole.log?)
- `MAXDBDAYS=365` (How long should queries be stored in the database? Setting this to `0` disables the database altogether)
- `RESOLVE_IPV6=yes|no` (Should `FTL` try to resolve IPv6 addresses to host names?)
- `RESOLVE_IPV4=yes|no` (Should `FTL` try to resolve IPv4 addresses to host names?)
- `DBFILE=/etc/pihole/pihole-FTL.db` (Specify path and filename of FTL's SQLite long-term database. Setting this to `DBFILE=` disables the database altogether)

### Implemented keywords (starting with `>`, subject to change):

- `>quit`: Closes connection to client

- `>kill`: Terminates FTL

- `>stats` : Get current statistics
 ```
domains_being_blocked 19977
dns_queries_today 104749
ads_blocked_today 279
ads_percentage_today 1.396606
unique_domains 6
queries_forwarded 3
queries_cached 2
clients_ever_seen 3
unique_clients 3
```

- `>overTime` : over time data (10 min intervals)
 ```
0 163 0
1 154 1
2 164 0
3 167 0
4 151 0
5 143 0
6 171 0
7 147 0
[...]
```

- `>top-domains` : get top domains
 ```
0 8462 x.y.z.de
1 236 safebrowsing-cache.google.com
2 116 pi.hole
3 109 z.y.x.de
4 93 safebrowsing.google.com
5 96 plus.google.com
[...]
```
 Variant: `>top-domains (15)` to show (up to) 15 entries

- `>top-ads` : get top ad domains
 ```
0 8 googleads.g.doubleclick.net
1 6 www.googleadservices.com
2 1 cdn.mxpnl.com
3 1 collector.githubapp.com
4 1 www.googletagmanager.com
5 1 s.zkcdn.net
[...]
```
 Variant: `>top-ads (14)` to show (up to) 14 entries

- `top-clients` : get recently active top clients (IP addresses + host names (if available))
 ```
0 9373 192.168.2.1 router
1 484 192.168.2.2 work-machine
2 8 127.0.0.1 localhost
```
 Variant: `>top-clients (9)` to show (up to) 9 client entries

 Variant: `>top-clients withzero (15)` to show (up to) 15 clients even if they have not been active recently (see PR #124 for further details)

- `>forward-dest` : get forward destinations (IP addresses + host names (if available)) along with the percentage
 ```
0 80.0 ::1 local
1 10.0 1.2.3.4 some.dns.de
2 10.0 5.6.7.8 some.other.dns.com
```
 Variant: `>forward-dest unsorted` to show forward destinations in unsorted order (equivalent to using `>forward-names`)
```

- `>querytypes` : get collected query types percentage
 ```
A (IPv4): 60.5
AAAA (IPv6): 39.5
```

- `>getallqueries` : get all queries that FTL has in its database
 ```
1483964292 IPv4 apis.google.com 1.2.3.4 3
1483964293 IPv4 clients5.google.com 1.2.3.4 2
1483964294 IPv4 lh3.googleusercontent.com 1.2.3.4 2
1483964295 IPv4 ogs.google.com 1.2.3.4 2
1483964297 IPv4 plus.google.com 1.2.3.4 2
1483964299 IPv4 www.google.com 2.3.4.5 2
1483964302 IPv4 www.googleadservices.com 2.3.4.5 1
1483964312 IPv4 www.gstatic.com 2.3.4.5 2
1483964333 IPv4 www.linguee.de 2.3.4.5 2
```
 Variant: `>getallqueries (37)` show (up to) 37 latest entries


- `>getallqueries-time 1483964295 1483964312` : get all queries that FTL has in its database in a limited time interval
 ```
1483964295 IPv4 ogs.google.com 1.2.3.4 2
1483964297 IPv4 plus.google.com 1.2.3.4 2
1483964299 IPv4 www.google.com 2.3.4.5 2
1483964302 IPv4 www.googleadservices.com 2.3.4.5 1
1483964312 IPv4 www.gstatic.com 2.3.4.5 2
```
 Variant: `>getallqueries-time 1483964295 1483964312 (17)` show matches in the (up to) 17 latest entries. Note that this does not necessarily mean that 15 entries will be returned

- `>getallqueries-domain www.google.com` : get all queries that FTL has in its database for a specific domain name
 ```
1483964299 IPv4 www.google.com 2.3.4.5 2
```
 Variant: `>getallqueries-domain www.google.com (15)` (see notes above)

- `>getallqueries-client 2.3.4.5` : get all queries that FTL has in its database for a specific client name *or* IP
 ```
1483964299 IPv4 www.google.com 2.3.4.5 2
1483964302 IPv4 www.googleadservices.com 2.3.4.5 1
1483964312 IPv4 www.gstatic.com 2.3.4.5 2
1483964333 IPv4 www.linguee.de 2.3.4.5 2
```
 Variant: `>getallqueries-client 2.3.4.5 (12)` (see notes above)

- `>recentBlocked` : get most recently pi-holed domain name
 ```
www.googleadservices.com
```
 Variant: `>recentBlocked (4)` show the four most recent vlocked domains

- `>memory` : get information about `FTL`'s memory usage due to its internal data structure
 ```
memory allocated for internal data structure: 178688 bytes (178.69 KB)
dynamically allocated allocated memory used for strings: 15084 bytes (15.08 KB)
Sum: 193772 bytes (193.77 KB)
```

- `>clientID` : Get ID of currently connected client
 ```
6
```

- `>version` : Get version information of the currently running FTL instance
 ```
 version v1.6-3-g106498d-dirty
tag v1.6
branch master
date 2017-03-26 13:10:43 +0200
```

- `>dbstats` : Get some statistics about the FTL long-term storage database
 ```
 queries in database: 88387
SQLite version: 3.19.3
```
