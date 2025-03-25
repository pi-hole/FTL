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

Remember that this is not officially supported - self-sufficiency and reading can go a long way.  FTLDNS (`pihole-FTL`) should be installed manually when using the `unsupported/binary` branch.  You **may** be able to get help at the [Community Help](https://discourse.pi-hole.net/c/bugs-problems-issues/community-help/36) Category - filter by `unsupported\binary` or other tags; search strings like `pogoplug` or `ARMv5TE`.
- **switch** to `unsupported/binary` branch: after git-cloning the `pihole core` repo, switch to `unsupported/branch`
- **env flags**: you pass the env var _before_ the command
-    **`PIHOLE_SKIP_FTL_BINARY_CHECK=true`** : usage `PIHOLE_SKIP_FTL_BINARY_CHECK=true ./basic_installer.sh` , for instance. Facilitates `unsupported/binary` installs.
-    **`PIHOLE_SKIP_OS_CHECK=true`**:  usage `PIHOLE_SKIP_OS_CHECK=true pihole checkout core unsupported` .  Makes installs/maintenance easier on unsupported OS versions like Debian Unstable.
- **manual install**: `install -T -m 0755 <path-to-pihole-FTL-binary> /usr/bin/pihole-FTL`, for instance.

### IMPORTANT

>FTLDNS will *disable* any existing installations of `dnsmasq`.  This is because FTLDNS *is* `dnsmasq` + Pi-hole's code, so both cannot run simultaneously.

### Acknowledgements
>Thanks and gratitude to the developers at [Pi-hole.net](https://pi-hole.net) and denizens at [Pi-hole discourse](https://discourse.pi-hole.net/) that did the code, fixed the bugs, rattled the cages to shake out the problems, and make it work.
