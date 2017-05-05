# NEL: a Simple Implementation of a Network Environment Learning (NEL) Phase for Covert Channels (with a Feedback Channel).

In *Network Steganography* research, a covert channel is a stealthy communication channel. Some covert channels are capable of performing a so-called **Network Environment Learning** phase (or: **NEL** phase). Such NEL-capable covert channels

- can determine how exactly data can be covertly exchanged between sender and receiver, and
- which types stealthy data transmissions will be blocked/modified by an active warden (e.g. a firewall or a traffic normalizer).

For instance, certain network packets of the covert channel may be blocked by an active warden as they set reserved header bits to '1' (a typical filter rule of an active warden could simply clear the bit to prevent a covert channel).

Although the NEL phase was originally discussed in academia about ten years ago, no implementation was made available. With *NEL*, we provide the first public implementation of such a NEL phase on the basis of *scapy* and *libpcap*. NEL is written in C and runs best under Linux.

Please send requests and feedback to the author: Steffen Wendzel, [www.wendzel.de](http://www.wendzel.de) (wendzel (at) hs-worms (dot) de). Research on the NEL phase is currently performed by Wojciech Mazurczyk, Steffen Wendzel, Jörg Keller and Mehdi Chourib, cf. [this website](http://ih-patterns.blogspot.de/p/authorscontact.html).
