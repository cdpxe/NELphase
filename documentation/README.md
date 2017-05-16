# NEL -- Tool for Researchers in Network Steganography to Simulate a Network Environment Learning Phase

Written by Steffen Wendzel, [www.wendzel.de](http://www.wendzel.de) (wendzel (at) hs-worms (dot) de). Research on the NEL phase is currently performed by Wojciech Mazurczyk, Steffen Wendzel, Jörg Keller and Mehdi Chourib, cf. [our project website](http://ih-patterns.blogspot.de/p/authorscontact.html).

## Introduction

In Network Steganography research, a covert channel is a stealthy communication channel (see (Mazurczyk et al., 2016) for an introduction). Some covert channels are capable of performing a so-called *Network Environment Learning* phase (or: NEL phase). Such NEL-capable covert channels

- can determine how exactly data can be covertly exchanged between sender and receiver, and
- which types stealthy data transmissions will be blocked/modified by an active warden (e.g. a firewall or a traffic normalizer).

For instance, certain network packets of the covert channel may be blocked by an active warden as they set reserved header bits to '1' (a typical filter rule of an active warden could simply clear the bit to prevent a covert channel).

Although the NEL phase was originally discussed in academia about ten years ago, no implementation was made available by other researchers. With NEL, we provide the first public implementation of a NEL phase on the basis of scapy and libpcap. NEL is written in C and runs best under Linux.

## How the NEL Phase Works

Regarding (Yarochkin et al., 2008), adaptive covert channels perform two different phases. In the so-called *Network Environment Learning* phase (NEL phase), peers (e.g. a covert sender and a receiver) try to determine which protocols can be used to covertly communicate and which protocols are blocked. This is done by sending test traffic from one peer to the other. After the NEL phase found suitable protocols, the *Communication* phase starts, in which actual covert traffic is exchanged. However, the NEL phase is continuously performed to update the list of non-blocked protocols from time to time. This approach was later extended by (Wendzel and Keller, 2011) and (Wendzel, 2012), i.e. made more fine-grained.

A countermeasure, such as a traffic normalizer, would then try to block the covert traffic of the NEL and Communication phases. However, the NEL phase can be improved so that it can be performed even in the presence of a traffic normalizer (or other forms of *active wardens*), see (Wendzel, 2012) for details.

## How the NEL Tool Works

The NEL tool implements a NEL phase as described in (Wendzel, 2012). In this scenario, Alice and Bob (NEL sender and NEL receiver) are separated by an active warden (e.g. a traffic normalizer). The active warden blocks covert traffic between the two. If Alice sends a covert channel test packet to Bob, he may receives it but his reply to Alice could be blocked. To solve this problem, (Wendzel, 2012) proposes to utilize a third (but temporary, e.g. less secure) participant (or more general: temporary/less secure non-blocked channel) between Alice and Bob (see figure below) to exchange information that

- announce test traffic and
- provide feedback (i.e. Bob tells Alice whether test traffic was received, or not).

```
       .-----------------Feedback Channel------------------------,
      \./                                                       \./
 ----------              ---------------------               -----------
 | Alice  |<----NEL----->| Traffic Normalizer|<----NEL----->|    Bob   |
 ----------              ---------------------               -----------
```
Such a scenario, in which Alice tries to perform the NEL phase with Bob and where both possess a feedback channel is implemented in this NEL tool. For instance, if Alice wants to test whether the traffic normalizer blocks IP packets in which the IPv4 *Don't Fragment* (DF) flag is set (it could be used to hide a covert bit), she first announces such a test packet via the feedback channel. Afterwards, Bob knows that he now must wait for such a packet (for a pre-defined time). Finally, Alice sends the test packet through the traffic normalizer and Bob reports back over the feedback channel whether the packet was received (in its desired form) or not.

The NEL tool allows measurements on the NEL performance (e.g. measuring how long it takes to successfully perform a NEL phase under different conditions). This can be used to test new forms of active wardens. For instance, if a *Snort*-based traffic normalizer is placed between NEL sender and NEL receiver, it can be configured with a different number of activated rules/time, influencing the time it takes to successfully perform a NEL phase.

*Please Note:* We describe details of the NEL tool-based experiments as well as our new strategy for an active warden in (Mazurczyk et al., under review). Additional information (including the extension of this documentation) will be provided as soon as our work has been presented to a scientific audience and passed an academic peer-review.

# References

- **under review**: W. Mazurczyk, S. Wendzel, M. Chourib, J. Keller: *You Shall Not Pass: Countering Network Covert Channels with Dynamic Wardens*

- W. Mazurczyk, S. Wendzel, S. Zander et al.: *Information Hiding in Communication Networks*, Wiley-IEEE press, 2016.

- S. Wendzel, J. Keller (2011): *[Low-attention Forwarding for Mobile Network Covert Channels](http://www.researchgate.net/profile/Steffen_Wendzel/publication/215661202_Low-attention_Forwarding_for_Mobile_Network_Covert_Channels/links/00b495349285e2ae43000000.pdf)*, in Proc. Communications and Multimedia Security (CMS 2011), LNCS vol. 7025, pp. 122-133, Springer, Ghent, Belgium, 2011.

- S. Wendzel (2012): *[The Problem of Traffic Normalization Within a Covert Channel's Network Environment Learning Phase](https://www.researchgate.net/publication/229091999_The_Problem_of_Traffic_Normalization_Within_a_Covert_Channel%27s_Network_Environment_Learning_Phase?ev=srch_pub&_sg=yiWm%2Fl1DEUeQDayeMTW0oEMG5Uyxo4zfcmAAOkr6NkJtTx6g7xucnaWMAIFkzvlq_n6tx%2Fpj8MwJkZ%2FDhSCYZtVcY3G8XFjtuD0wGGY97liDms58KUp77JmWf%2F2uLjaFg_9rtZQe80mfDWVt%2BOxdHhJvIgvvSP8%2FJUpvi9Tx32b%2BASAG60z5JBglEJw%2Fx0RbUK)*, Proc. Sicherheit 2012, LNI vol. 195, pp. 149-161, 2012.

- F. V. Yarochkin, S. Y. Dai et al. (2008): *Towards Adaptive Covert Communication System*, Proc. 2008 14th IEEE Pacific Rim International Symposium on Dependable Computing, pp. 153-159, IEEE, 2008.