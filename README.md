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
| Raspberry Pi Zero | Raspbian Jessie | armv6 | `arm-linux-gnueabi` | [@DanSchaper](https://github.com/dschaper) |
| Raspberry Pi 1 | Raspbian Jessie | armv6 | `arm-linux-gnueabi` | [@DL6ER](https://github.com/dl6er) |
| Raspberry Pi 2 | Raspbian Jessie | armv7l | `arm-linux-gnueabihf` and `arm-linux-gnuabi` | [@TechnicalPyro](https://github.com/technicalpyro) |
| Raspberry Pi 3 | Raspbian Jessie | armv7l | `arm-linux-gnuabi` and `arm-linux-gnueabihf` | [@DL6ER](https://github.com/dl6er) |
| NanoPi NEO | armbian Ubuntu 16.04 | armv7l | `arm-linux-gnueabihf` | [@DL6ER](https://github.com/dl6er) |
| Odroid-C2 | Ubuntu 16.04 | aarch64 | `aarch64-linux-gnu` | [@DanSchaper](https://github.com/dschaper) |
| C.H.I.P | Debian | armv7l | `arm-linux-gnueabihf` | [@Promofaux](https://github.com/promofaux) |
| OrangePi Zero | armbian Ubuntu 16.04 | ? | ? | ? |
|  |  |  |  |  |

If you want to add a new device, open an issue or create a PR for the README. You can get your CPU architecture by running `lscpu`.

---

### How to test FTL?

1. Clone the repo
2. `make`
3. `sudo make install`
4. start `pihole-FTL`

### Command line arguments

- `debug` - Don't go into daemon mode (stay in foreground) + more verbose logging
- `test` - Start `FTL` and process everything, but shut down immediately afterwards

Command line arguments can be arbitrarily combined, e.g. `pihole-FTL debug test`

### File locations
- `/var/log/pihole-FTL.log` log file
- `/var/run/pihole-FTL.pid` PID file
- `/var/run/pihole-FTL.port` file containing port on which `FTL` is listening

### Socket connections

connect via e.g. `telnet 127.0.0.1 4711`
port may be automatically incremented if `4711` isn't available

### Implemented keywords (starting with `>`, subject to change):

- `>quit`: Closes connection to client

- `>kill`: Terminates FTL

- `>stats` : Get current statistics
 ```
domains_being_blocked 19977
dns_queries_today 104749
ads_blocked_today 279
ads_percentage_today 1.396606
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

- `top-clients` : get top clients (IP addresses + host names (if available))
 ```
0 9373 192.168.2.1 router
1 484 192.168.2.2 work-machine
2 8 127.0.0.1 localhost
```

- `>forward-dest` : get forward destinations (IP addresses + host names (if available))
 ```
0 12940 1.2.3.4 some.dns.de
1 629 5.6.7.8 some.other.dns.com
```

- `>querytypes` : get query types
 ```
A (IPv4): 7729
AAAA (IPv6): 5880
PTR: 12
SRV: 0
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

- `>getallqueries-time 1483964295 1483964312` : get all queries that FTL has in its database in a limited time interval
 ```
1483964295 IPv4 ogs.google.com 1.2.3.4 2
1483964297 IPv4 plus.google.com 1.2.3.4 2
1483964299 IPv4 www.google.com 2.3.4.5 2
1483964302 IPv4 www.googleadservices.com 2.3.4.5 1
1483964312 IPv4 www.gstatic.com 2.3.4.5 2
```

- `>getallqueries-domain www.google.com` : get all queries that FTL has in its database for a specific domain name
 ```
1483964299 IPv4 www.google.com 2.3.4.5 2
```

- `>getallqueries-client 2.3.4.5` : get all queries that FTL has in its database for a specific client name *or* IP
 ```
1483964299 IPv4 www.google.com 2.3.4.5 2
1483964302 IPv4 www.googleadservices.com 2.3.4.5 1
1483964312 IPv4 www.gstatic.com 2.3.4.5 2
1483964333 IPv4 www.linguee.de 2.3.4.5 2
```

- `>recentBlocked` : get most recently pi-holed domain name
 ```
www.googleadservices.com
```
