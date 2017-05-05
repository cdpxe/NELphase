# NEL: a Simple Implementation of a Network Environment Learning (NEL) Phase for Covert Channels (with a Feedback Channel).

In ``Network Steganography'', a covert channel is basically a stealthy communication channel. A covert channel that is capable of performing a *Network Environment Learning* (*NEL*) phase can determine which data can be exchanged between sender and receiver and which data will be blocked/modified by a active warden (e.g. a firewall or a traffic normalizer). For instance, certain packets may be blocked by an active warden because they set some reserved header bits that could be used by a covert channel to embed secret data.

Although the NEL phase was originally discussed in academic about ten years ago, no implementation was made available. With *NEL*, we provide the first public implementation of such a NEL phase on the basis of *scapy* and *libpcap*. NEL is written in C and runs best under Linux.

Please send requests and feedback to the author: Steffen Wendzel, [www.wendzel.de](http://www.wendzel.de) (wendzel (at) hs-worms (dot) de). Research on the NEL phase is currently performed by [Wojciech Mazurczyk, Steffen Wendzel, Jörg Keller](http://ih-patterns.blogspot.de/p/authorscontact.html).

