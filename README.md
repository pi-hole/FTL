<p align="center">
  <a href="https://pi-hole.net/">
    <img src="https://raw.githubusercontent.com/pi-hole/graphics/refs/heads/master/Vortex/vortex_with_text.svg" alt="Pi-hole logo" width="80" height="128">
  </a>
  <br>
  <strong>Network-wide ad blocking via your own Linux hardware</strong>
  <br>
  <br>
  <a href="https://pi-hole.net/">
    <img src="https://raw.githubusercontent.com/pi-hole/graphics/refs/heads/master/FTLDNS/FTLDNS.svg" alt="FTLDNS logo" width="500" height="128">
  </a>
</p>

FTLDNS (`pihole-FTL`) provides an interactive API and also generates statistics for Pi-hole[®](https://pi-hole.net/trademark-rules-and-brand-guidelines/)'s Web interface.

- **Fast**: stats are read directly from memory by coupling our codebase closely with `dnsmasq`
- **Versatile**: upstream changes to `dnsmasq` can quickly be merged in without much conflict
- **Lightweight**: runs smoothly with [minimal hardware and software requirements](https://discourse.pi-hole.net/t/hardware-software-requirements/273) such as Raspberry Pi Zero
- **Interactive**: our API can be used to interface with your projects
- **Insightful**: stats normally reserved inside of `dnsmasq` are made available so you can see what's really happening on your network

## Official documentation

The official *FTL*DNS documentation can be found [here](https://docs.pi-hole.net/ftldns/).

## Installation

FTLDNS (`pihole-FTL`) is automatically installed when installing Pi-hole.

### IMPORTANT

>FTLDNS will *disable* any existing installations of `dnsmasq`. This is because FTLDNS *is* `dnsmasq` + Pi-hole's code, so both cannot run simultaneously.
