<h1 align="center">

_______________________________________________________________________
 v6 pihole-FTL binaries just for armv5te
_______________________________________________________________________
</h1>
<p align="center">
  <a href="https://pi-hole.net">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="https://pi-hole.github.io/graphics/Vortex/Vortex_Vertical_wordmark_darkmode.png">
      <source media="(prefers-color-scheme: light)" srcset="https://pi-hole.github.io/graphics/Vortex/Vortex_Vertical_wordmark_lightmode.png">
      <img src="https://pi-hole.github.io/graphics/Vortex/Vortex_Vertical_wordmark_lightmode.png" width="80" alt="Pi-hole website">
    </picture>
  </a>
  <br/>
  <b>Network-wide ad blocking via your own Linux hardware</b><br/><br/>
  <a href="https://pi-hole.net">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="https://pi-hole.github.io/graphics/FTLDNS/FTLDNS_darkmode.png">
      <source media="(prefers-color-scheme: light)" srcset="https://pi-hole.github.io/graphics/FTLDNS/FTLDNS.png">
      <img src="https://pi-hole.github.io/graphics/FTLDNS/FTLDNS.png" alt="FTLDNS">
    </picture>
  </a>
  <br/>
</p>

FTLDNS (`pihole-FTL`) provides an interactive API and also generates statistics for Pi-hole[®](https://pi-hole.net/trademark-rules-and-brand-guidelines/)'s Web interface.

- **Fast**: stats are read directly from memory by coupling our codebase closely with `dnsmasq`
- **Versatile**: upstream changes to `dnsmasq` can quickly be merged in without much conflict
- **Lightweight**: runs smoothly with [minimal hardware and software requirements](https://discourse.pi-hole.net/t/hardware-software-requirements/273) such as Raspberry Pi Zero
- **Interactive**: our API can be used to interface with your projects
- **Insightful**: stats normally reserved inside of `dnsmasq` are made available so you can see what's really happening on your network

## Official documentation

The official status of these binaries is _unsupported_, so don't rely on or expect support from the Pi-hole developers (they have enough to do w/ just the supported architectures).  Official *FTL*DNS documentation can be found [here](https://docs.pi-hole.net/ftldns/).

## Installation

FTLDNS (`pihole-FTL`) should be installed manually when using the `unsupported/binary` branch. Consider something like `install -T -m 0755 <path-to-pihole-FTL-binary> /usr/bin/pihole-FTL`, for instance.

### IMPORTANT

>FTLDNS will *disable* any existing installations of `dnsmasq`.  This is because FTLDNS *is* `dnsmasq` + Pi-hole's code, so both cannot run simultaneously.

### Acknowledgements
>Thanks and gratitude to the developers at [Pi-hole.net](https://pi-hole.net) and denizens at [Pi-hole discourse](https://discourse.pi-hole.net/) that did the code, fixed the bugs, rattled the cages, and make it work.
