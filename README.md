# ilnp-public-1
## [ILNP](https://ilnp.cs.st-andrews.ac.uk/) Software

This repository contains experimental, prototype software for the Identifier Locator Network Protocol (ILNP) project. The main web site for ILNP is at [https://ilnp.cs.st-andrews.ac.uk/](https://ilnp.cs.st-andrews.ac.uk/).

The intention of this software release is to support the results published in the following academic papers:

* R. Yanagida, S. N. Bhatti. [Seamless Internet connectivity for ubiquitous communication](http://dx.doi.org/10.1145/3341162.3349315). PURBA2019, Pervasive Urban Applications Workshop (UBICOMP 2019). London, UK. Sep 2019.
* D. Phoomikiattisak, S. N. Bhatti. [End-To-End Mobility for the Internet Using ILNP](https://doi.org/10.1155/2019/7464179), Wireless Communications and Mobile Computing (WCMC), vol. 2019, Article ID 7464179, pages 29. Apr 2019. 
* R. Yanagida, S. N. Bhatti. [End-to-end networking with ILNP in Linux](https://netdevconf.org/0x13/session.html?talk-ilnp). netdev0x13 Technical Conference on Linux Networking, Prague, Czech Republic. Mar 2019.
* S. N. Bhatti, D. Phoomikiattisak, B. Simpson. [IP without IP addresses](http://dx.doi.org/10.1145/3012695.3012701). AINTEC 2016 - 12th Asian Internet Engineering Conf.. Bangkok, Thailand. Nov/Dec 2016.

The code here is an up-to-date version of the code published in those papers.

All code contributed by the authors is Copyright (C) Saleem N. Bhatti, Ryo Yanagida, Khawar Shezhad, and Ditchaphong Phoomikiatissak.

This code was also demonstrated at [IETF104/Prague](https://blogs.cisco.com/developer/prague-ietf-hackathon) and [IETF105/Montreal](https://trac.ietf.org/trac/ietf/meeting/wiki/105hackathon). 

## Code

There are two parts to the software:

1. Extensions to the Linux kernel v4.9 LTS.
2. A modifictaion to glibc so that names for nodes in `/etc/hosts` can be mapped to ILNP Identifier-Locator Vector (I-IV) values, and passed up to applications in `struct addrinfo` via calls to `getaddrinfo(3)`.

Both are needed.
