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

---

# Official documentation

The official *FTL*DNS documentation can be found [here](https://docs.pi-hole.io/ftldns/).

# Installation

FTLDNS (`pihole-FTL`) is installed by default when you choose to enable the Web interface when installing Pi-hole.

> IMPORTANT!

>FTLDNS will _disable_ any existing installations of `dnsmasq`.  This is because FTLDNS _is_ `dnsmasq` + Pi-hole's code, so both cannot run simultaneously.

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

