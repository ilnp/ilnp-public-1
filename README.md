# ILNP software version: ilnp-public-1
### 06 September 2019

## The first [ILNP](https://ilnp.cs.st-andrews.ac.uk/) software release

This repository contains experimental software implementing a prototype of the Identifier Locator Network Protocol (ILNP). The main web site for ILNP is at [https://ilnp.cs.st-andrews.ac.uk/](https://ilnp.cs.st-andrews.ac.uk/).

The intention of this software release is to support the results published in the following academic papers:

* R. Yanagida, S. N. Bhatti. [Seamless Internet connectivity for ubiquitous communication](http://dx.doi.org/10.1145/3341162.3349315). PURBA2019, Pervasive Urban Applications Workshop (UBICOMP 2019). London, UK. Sep 2019.
* D. Phoomikiattisak, S. N. Bhatti. [End-To-End Mobility for the Internet Using ILNP](https://doi.org/10.1155/2019/7464179), Wireless Communications and Mobile Computing (WCMC), vol. 2019, Article ID 7464179, pages 29. Apr 2019. 
* R. Yanagida, S. N. Bhatti. [End-to-end networking with ILNP in Linux](https://netdevconf.org/0x13/session.html?talk-ilnp). netdev0x13 Technical Conference on Linux Networking, Prague, Czech Republic. Mar 2019.
* S. N. Bhatti, D. Phoomikiattisak, B. Simpson. [IP without IP addresses](https://doi.org/10.1145/3012695.3012701). AINTEC 2016 - 12th Asian Internet Engineering Conf.. Bangkok, Thailand. Nov/Dec 2016.
* D. Phoomikiatissak, S. N. Bhatti. [Mobility as a First Class Function](https://doi.org/10.1109/WiMOB.2015.7348051). WiMob 2015 - 11th IEEE Intl. Conf. Wireless and Mobile Computing, Networking and Communications. Abu Dhabi, UAE. Oct 2015.

The code here is an up-to-date version of the codebase used in the experiments documented in those papers.

This is the codebase that was also used for the work and demonstrations at [IETF104/Prague](https://blogs.cisco.com/developer/prague-ietf-hackathon) and [IETF105/Montreal](https://trac.ietf.org/trac/ietf/meeting/wiki/105hackathon). 

All code contributed by the authors is Copyright (C) Saleem N. Bhatti, Ryo Yanagida, Khawar Shezhad, and Ditchaphong Phoomikiatissak.

## Questionnaire

If you download the code, I will be grateful if you could complete [this questionnaire](https://standrews.eu.qualtrics.com/jfe/form/SV_eWiVRfNRBnqTBXL), please. The whole thing should take only ~5 minutes of your time. If you do not want to fill in all of it, please do give responses just to questions 2b and 2c. The data could be _extremely helpful_ to me when I apply for additional support for further development of ILNP. Thank you!

## This is not supported software

Alas and woe, I can not offer any support for this software. It is the output of ongoing work in PhD projects that I have supervised. Please be aware that you use this software at your own risk.

I continue to seek funding for progressing ILNP in various ways. So my intention is to improve and update this sofwtare, but I cannot  give any definite timescales and roadmaps at present.

## Code

There are two parts to the software:

1. A modifictaion to `glibc` ([here - ilnp-glibc-1](https://github.com/ilnp/ilnp-glibc-1)) so that names for nodes in `/etc/hosts` can be mapped to ILNP Identifier-Locator Vector (I-LV) values, and passed up to applications in `struct addrinfo` via calls to `getaddrinfo(3)`.
2. Extensions to the Linux kernel v4.9 LTS ([here - ilnp-public-1](https://github.com/ilnp/ilnp-public-1)) to implement the ILNP functionality.

Both are needed. First, get the modified version of `glibc` in ilnp-glibc-1, compile it, and install it. Then, build the kernel in ilnp-public-1, using the new version of `glibc`.

## Thank you

My thanks to you for your interest in [ILNP](https://ilnp.cs.st-andrews.ac.uk/)! I hope you enjoy trying it out.

_Saleem Bhatti, ILNP Project Lead_, ilnp-admin at st-andrews.ac.uk
