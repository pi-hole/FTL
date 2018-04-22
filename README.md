<p align="center">
<a href="https://pi-hole.net"><img src="https://pi-hole.github.io/graphics/Vortex/Vortex_with_text.png" width="150" height="255" alt="Pi-hole"></a>
<br/><br/>
<b>Network-wide ad blocking via your own Linux hardware</b><br/>
<a href="https://pi-hole.net"><img src="https://pi-hole.net/wp-content/uploads/2018/03/ftldns-logo.png" alt="FTLDNS"></a><br/>
</p>

FTLDNS[™](https://pi-hole.net/trademark-rules-and-brand-guidelines/) (`pihole-FTL`) provides an interactive API and also generates statistics for Pi-hole[®](https://pi-hole.net/trademark-rules-and-brand-guidelines/)'s Web interface.

- **Fast**: stats are read directly from memory by coupling our codebase closely with `dnsmasq`
- **Versatile**: upstream changes to `dnsmasq` can quickly be merged in without much conflict
- **Lightweight**: runs smoothly with [minimal hardware and software requirements](https://discourse.pi-hole.net/t/hardware-software-requirements/273) such as Raspberry Pi Zero
- **Interactive**: our API can be used to interface with your projects
- **Insightful**: stats normally reserved inside of `dnsmasq` are made available so you can see what's really happening on your network

---
<a class="badge-align" href="https://www.codacy.com/app/Pi-hole/FTL?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=pi-hole/FTL&amp;utm_campaign=Badge_Grade"><img src="https://api.codacy.com/project/badge/Grade/2f36cd6b04694b42893335a6a656969b"/></a>

# Compatibility list

| Board | Tested OS | CPU architecture | Suitable binaries
|---|---|---|---
| VirtualBox | Ubuntu 16.10 | amd64 | `linux-x86_64`
| Raspberry Pi Zero | Raspbian Jessie, Stretch | armv6l | `arm-linux-gnueabi`
| Raspberry Pi 1 | Raspbian Jessie, Stretch | armv6 | `arm-linux-gnueabi`
| Raspberry Pi 2 | Raspbian Jessie, Stretch | armv7l | `arm-linux-gnueabihf` and `arm-linux-gnuabi`
| Raspberry Pi 3 | Raspbian Jessie, Stretch | armv7l | `arm-linux-gnuabi` and `arm-linux-gnueabihf`
| Raspberry Pi 3 | openSUSE | aarch64 | `aarch64-linux-gnu`
| NanoPi NEO | armbian Ubuntu 16.04 | armv7l | `arm-linux-gnueabihf`
| Odroid-C2 | Ubuntu 16.04 | aarch64 | `aarch64-linux-gnu`
| C.H.I.P | Debian | armv7l | `arm-linux-gnueabihf`
| OrangePi Zero | armbian Ubuntu 16.04 | armv7l | `arm-linux-gnueabihf`
| BeagleBone Black| Debian Jessie, Stretch | armv7l | `arm-linux-gnueabihf`
|  |  |  |  |  |

>If your device is not listed you can get your CPU architecture by running `lscpu`. Download some binaries and try which one work. If you want to add a new device, open an issue or create a PR for the README.

---

# Installation

FTLDNS (`pihole-FTL`) is installed by default when you choose to enable the Web interface when installing Pi-hole.

> IMPORTANT!

>FTLDNS will _disable_ any existing installations of `dnsmasq`.  This is because FTLDNS _is_ `dnsmasq` + Pi-hole's code, so both cannot run simultaneously.

## Compiling FTL from source

1. Install building dependencies (e.g. `libgmp-dev m4`)
3. Compile and install a recent version of `nettle` (see [here](https://www.lysator.liu.se/~nisse/nettle/))
3. Clone the repo
3. `make`
4. `sudo make install`
5. `sudo service pihole-FTL start`

## Post-install: Gain insight into your network's activity

As mentioned earlier, FTLDNS will be enabled by default when you install Pi-hole.  To access the Web interface, navigate to `http://pi.hole/admin` or `http://<IP OF YOUR PIHOLE>/admin`.

Once logged in, (or authenticated to the API) you can view your network stats to see things like:

- the domains being queried on your network
- the time the queries were initiated
- the amount of domains that were blocked
- the upstream server queries were sent to
- the type of queries (`A`, `AAAA`, `CNAME`, `SRV`, `TXT`, etc.)
---

## Pi-hole is free, but powered by your support
There are many reoccurring costs involved with maintaining free, open source, and privacy respecting software; expenses which [our volunteer developers](https://github.com/orgs/pi-hole/people) pitch in to cover out-of-pocket. This is just one example of how strongly we feel about our software, as well as the importance of keeping it maintained.

Make no mistake: **your support is absolutely vital to help keep us innovating!**

### Donations
Sending a donation using our links below is **extremely helpful** in offsetting a portion of our monthly expenses:

- <img src="https://pi-hole.github.io/graphics/Badges/paypal-badge-black.svg" width="24" height="24" alt="PP"/> <a href="https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=3J2L3Z4DHW9UY">Donate via PayPal</a><br/>
- <img src="https://pi-hole.github.io/graphics/Badges/bitcoin-badge-black.svg" width="24" height="24" alt="BTC"/> [Bitcoin](https://commerce.coinbase.com/checkout/fb7facaf-bebd-46be-bb77-b358f4546763): <code>1GKnevUnVaQM2pQieMyeHkpr8DXfkpfAtL</code></br>
- <img src="https://pi-hole.github.io/graphics/Badges/bitcoin-badge-black.svg" width="24" height="24" alt="BTC"/> [Bitcoin Cash](https://commerce.coinbase.com/checkout/fb7facaf-bebd-46be-bb77-b358f4546763): <code>qqh25hlmqaj99xraw00e47xmf8sysnyxhyww2d7dnh</code></br>
- <img src="https://pi-hole.github.io/graphics/Badges/ethereum-badge-black.svg" width="24" height="24" alt="BTC"/> [Ethereum](https://commerce.coinbase.com/checkout/fb7facaf-bebd-46be-bb77-b358f4546763): <code>0xF00aF43d2431BAD585056492b310e48eC40D87e8</code>

### Alternative support
If you'd rather not [donate](https://pi-hole.net/donate/) (_which is okay!_), there are other ways you can help support us:

- [Digital Ocean](http://www.digitalocean.com/?refcode=344d234950e1) _affiliate link_
- [UNIXstickers.com](http://unixstickers.refr.cc/jacobs) _save $5 when you spend $9 using our affiliate link_
- [Pi-hole Swag Store](https://pi-hole.net/shop/) _affiliate link_
- [Amazon](http://www.amazon.com/exec/obidos/redirect-home/pihole09-20) _affiliate link_
- [Ho-ost](https://clients.ho-ost.com/aff.php?aff=19) _save 50% with our affiliate link_
- [DNS Made Easy](https://cp.dnsmadeeasy.com/u/133706) _affiliate link_
- [Vultr](http://www.vultr.com/?ref=7190426) _affiliate link_
- Spreading the word about our software, and how you have benefited from it

### Contributing via GitHub
We welcome _everyone_ to contribute to issue reports, suggest new features, and create pull requests.

If you have something to add - anything from a typo through to a whole new feature, we're happy to check it out! Just make sure to fill out our template when submitting your request; the questions that it asks will help the volunteers quickly understand what you're aiming to achieve.

### Presentations about Pi-hole
Word-of-mouth continues to help our project grow immensely, and so we are helping make this easier for people.

If you are going to be presenting Pi-hole at a conference, meetup or even a school project, [get in touch with us](https://pi-hole.net/2017/05/17/giving-a-presentation-on-pi-hole-contact-us-first-for-some-goodies-and-support/) so we can hook you up with free swag to hand out to your audience!

-----

## Getting in touch with us
While we are primarily reachable on our <a href="https://discourse.pi-hole.net/">Discourse User Forum</a>, we can also be found on a variety of social media outlets. **Please be sure to check the FAQ's** before starting a new discussion, as we do not have the spare time to reply to every request for assistance.

<ul>
  <li><b><a href="https://discourse.pi-hole.net/c/faqs">Frequently Asked Questions</a></b></li>
  <li><b><a href="https://github.com/pi-hole/pi-hole/wiki">Pi-hole Wiki</a></b></li>
  <li><b><a href="https://discourse.pi-hole.net/c/feature-requests?order=votes">Feature Requests</a></b></li>
  <li><a href="https://discourse.pi-hole.net/">Discourse User Forum</a></li>
  <li><a href="https://www.reddit.com/r/pihole/">Reddit</a></li>
  <li><a href="https://twitter.com/The_Pi_Hole">Twitter</a></li>
  <li><a href="https://www.facebook.com/ThePiHole/">Facebook</a></li>
  <li><a href="https://gitter.im/pi-hole/pi-hole">Gitter</a> (Real-time chat)</li>
  <li><a href="https://www.youtube.com/channel/UCT5kq9w0wSjogzJb81C9U0w">YouTube</a></li>
</ul>

-----

# Config and Features

Pi-hole stats can be accessed via a standard Unix socket (`var/run/pihole/FTL.sock`), a telnet-like connection (TCP socket on port `4711`) as well as indirectly via the Web API (`admin/api.php`), and Command Line (`pihole -c -j`). You can out find more details below.

### Command line arguments

- `debug` - Don't go into daemon mode (stay in foreground) + more verbose logging
- `test` - Start `FTL` and process everything, but shut down immediately afterwards
- `version` - Don't start `FTL`, show only version
- `tag` - Don't start `FTL`, show only git tag
- `branch` - Don't start `FTL`, show only git branch `FTL` was compiled from
- `no-daemon` or `-f` - Don't go into background (daemon mode)
- `help` or `-h` - Don't start `FTL`, show help
- `dnsmasq-test` - Test resolver config file syntax
- `--` everything behind `--` will be passed as options to the internal resolver

Command line arguments can be arbitrarily combined, e.g. `pihole-FTL debug test`

### File locations
- `/var/log/pihole-FTL.log` log file
- `/var/run/pihole-FTL.pid` PID file
- `/var/run/pihole-FTL.port` file containing port on which `FTL` is listening
- `/var/run/pihole/FTL.sock` Unix socket

### Telnet-like socket connections

connect via e.g. `telnet 127.0.0.1 4711`
port may be automatically incremented if `4711` isn't available

### FTL's config file

You can create a file `/etc/pihole/pihole-FTL.conf` that will be read by `FTL` on startup.

Possible settings (**the option shown first is the default**):

- `SOCKET_LISTENING=localonly|all` (Listen only for local socket connections or permit all connections)
- `QUERY_DISPLAY=yes|no` (Display all queries? Set to `no` to hide query display)
- `AAAA_QUERY_ANALYSIS=yes|no` (Allow `FTL` to analyze AAAA queries from pihole.log?)
- `MAXDBDAYS=365` (How long should queries be stored in the database? Setting this to `0` disables the database altogether)
- `RESOLVE_IPV6=yes|no` (Should `FTL` try to resolve IPv6 addresses to host names?)
- `RESOLVE_IPV4=yes|no` (Should `FTL` try to resolve IPv4 addresses to host names?)
- `DBINTERVAL=1.0` (How often do we store queries in FTL's database [minutes]?)
- `DBFILE=/etc/pihole/pihole-FTL.db` (Specify path and filename of FTL's SQLite long-term database. Setting this to `DBFILE=` disables the database altogether)
- `MAXLOGAGE=24.0` (Up to how many hours of queries should be imported from the database and logs? Maximum is 744 (31 days))
- `FTLPORT=4711` (On which port should FTL be listening?)
- `PRIVACYLEVEL=0` (Which privacy level is used? Can be 0 (permissive) to 3 (very restrictive), see below)
- `IGNORE_LOCALHOST=no|yes` (Should `FTL` ignore queries coming from the local machine?)
- `BLOCKINGMODE=IP|NXDOMAIN` (Should `FTL` reply queries to blocked domains with IPs or NXDOMAIN?)

### Privacy levels
Specifies if we want to anonymize the DNS queries somehow, available options are:
- 0 = Don't hide anything
- 1 = Show and store all domains as "hidden", return nothing for Top Domains + Top Ads
- 2 = As 1 plus show all domains as "hidden" and all clients as "127.0.0.1" (or "::1"), return nothing for any Top Lists
- 3 = Disabled basically everything except the anonymous stastics, there will be no entries added to the database, no entries visible in the Query Log and no Top Item Lists

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
