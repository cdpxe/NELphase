# NEL – A Tool to Simulate a Network Environment Learning Phase in Network Steganography

Written by *Steffen Wendzel*, [www.wendzel.de](https://www.wendzel.de) (wendzel (at) hs-worms (dot) de). Research on the NEL phase is currently performed by multiple authors, cf. [our project website](https://ih-patterns.blogspot.de/p/authorscontact.html).

## Introduction

In *Network Steganography* research, a *covert channel* is a stealthy communication channel. Need some introduction into the topic? Here is some material for you:

* our [overview paper](https://cacm.acm.org/magazines/2018/1/223894/fulltext)
* [our short video](https://vimeo.com/245230404) (4min)
* [my overview video](http://ih-patterns.blogspot.de/2018/04/talk-on-information-hiding-and-hiding.html) (31min)
* my [MOOC (*massive open online class*) on Network Covert Channels](https://github.com/cdpxe/Network-Covert-Channels-A-University-level-Course)
* see (Mazurczyk et al., 2016) for detailled fundamentals

Some covert channels are capable of performing a so-called [**Network Environment Learning** phase](https://www.researchgate.net/publication/229091999_The_Problem_of_Traffic_Normalization_Within_a_Covert_Channel%27s_Network_Environment_Learning_Phase?ev=srch_pub&_sg=yiWm%2Fl1DEUeQDayeMTW0oEMG5Uyxo4zfcmAAOkr6NkJtTx6g7xucnaWMAIFkzvlq_n6tx%2Fpj8MwJkZ%2FDhSCYZtVcY3G8XFjtuD0wGGY97liDms58KUp77JmWf%2F2uLjaFg_9rtZQe80mfDWVt%2BOxdHhJvIgvvSP8%2FJUpvi9Tx32b%2BASAG60z5JBglEJw%2Fx0RbUK) (or: NEL phase). Such NEL-capable covert channels ...

- can determine how exactly data can be covertly exchanged between sender and receiver, and
- which types stealthy data transmissions will be blocked/modified by an active warden (e.g. a firewall or a traffic normalizer).

For instance, certain network packets of the covert channel may be blocked by an active warden if they set reserved header bits to '1' (a typical filter rule of an active warden could simply clear the bit to prevent a covert channel).

Although the NEL phase was originally discussed in academia around 2008/2009, no implementation was made available by any researchers. With NEL, we provide the first public implementation of an improved NEL phase as described by (Wendzel, 2012) on the basis of scapy and libpcap. NEL is written in C and runs best under Linux.

## How the NEL Phase Works

Regarding (Yarochkin et al., 2008), adaptive covert channels perform two different phases. In the so-called *Network Environment Learning* phase (NEL phase), peers (e.g. a covert sender and a receiver) try to determine which protocols can be used to communicate covertly and which protocols are blocked (and thus cannot be used for the covert communication). This is done by sending test traffic from one peer to the other. After the NEL phase found suitable non-blocked protocols, the *Communication* phase starts, in which actual covert traffic is exchanged. However, the NEL phase is continuously performed to update the list of non-blocked protocols from time to time. This approach was later extended by (Wendzel and Keller, 2011) and especially (Wendzel, 2012), i.e. the NEL phase was made more fine-grained and more robust. Our tool implements the sophisticated NEL phase of (Wendzel, 2021), i.e. a NEL phase with a feedback channel.

A countermeasure, such as a traffic normalizer, would then try to block the covert traffic of the NEL and Communication phases. However, the NEL phase can be improved so that it can be performed even in the presence of a traffic normalizer (or other forms of *active wardens*), see (Wendzel, 2012) for details. NEL-capable covert channels can be currently only efficiently combated by so-called *dynamic wardens* (and their derivate, the *adaptive wardens*) that modify their own filter behavior in a constant manner, cf. (Mazurczyk et al., 2019) and (Chourib et al., 2021).

## How the NEL Tool Works

The NEL tool implements a sophisticated NEL phase as described in (Wendzel, 2012). In this scenario, *Alice* (NEL sender) and *Bob* (NEL receiver) are separated by an active warden (e.g. a traffic normalizer). The active warden blocks covert traffic between the two. If Alice sends a covert channel test packet to Bob, he may receives it but his reply to Alice could be blocked. To solve this problem, (Wendzel, 2012) proposes to utilize a third (but temporary, e.g. less secure) participant (or more general: temporary/less secure non-blocked channel) between Alice and Bob (in the figure below called the **Feedback Channel**) to exchange information that

- announce test traffic and
- provide feedback (i.e. Bob tells Alice whether test traffic was received, or not).

```
       .---------------------Feedback Channel----------------------,
      \./                                                         \./
 ----------               ---------------------               ------------
 | Alice  |<-Warden Link->| Traffic Normalizer|<-Warden Link->|    Bob   |
 | (=NEL  |               | (e.g. Snort)      |               |   (=NEL  |
 | sender)|               |                   |               | receiver)|
 ----------               ---------------------               ------------
```
Such a scenario, in which Alice tries to perform the NEL phase with Bob and where both possess a feedback channel is implemented in this NEL tool. For instance, if Alice wants to test whether the traffic normalizer blocks IP packets in which the IPv4 *Don't Fragment* (DF) flag is set (it could be used to hide a covert bit), she first announces such a test packet via the feedback channel. Afterwards, Bob knows that he now must wait for such a packet (for a pre-defined time). Finally, Alice sends the test packet through the traffic normalizer and Bob reports back over the feedback channel whether the packet was received (in its desired form) or not.

The NEL tool allows measurements on the NEL performance (e.g. measuring how long it takes to successfully perform a NEL phase under different conditions). This can be used to test new forms of active wardens. For instance, if a *Snort*-based traffic normalizer is placed between NEL sender and NEL receiver, it can be configured with a different number of activated rules/time, influencing the time it takes to successfully perform a NEL phase.

## Using the NEL Tool

First, we explain an example testbed setup, then we show how to run the NEL tool, and finally explain what it does in detail.

### Example Testbed Setup

Let us asume we have the following setup for our testbed, using IPv4 addresses and Ethernet interfaces. We compile the NEL tool on both systems, Alice and Bob. First of all, we have a *Warden Link* between Alice and Bob (network *172.16*.2.x). This is the link that faces a traffic normalizer/active warden. In this case, Alice and Bob reside in the same subnet, i.e. the traffic normalizer may be a transparent gateway, however, it can also be two different subnets (this does not matter).

```
       .-----------------------Feedback Channel (NEL link)------------------,  IP: 192.168.2.103
      \./ 192.168.2.104                                                    \./ Interface: wlp4s0
 ----------                 ---------------------                      ------------
 | Alice  |<--Warden Link-->| Traffic Normalizer|<--Warden Link------->|    Bob   |
 | (NEL   |172.16.2.104     | (e.g. Snort with a|          172.16.2.103|   (NEL   |
 | sender)|                 | transparent setup)|                      | receiver)|
 ----------                 ---------------------                      ------------
```
Secondly, Alice and Bob have a temporarily used link to exchange meta information (test traffic announcements and feedback), called the NEL link (or: `Feedback Channel`, IP addresses *192.168*.2.x). This can be, for instance, realized over a separate Ethernet connection.

The following table summarizes our testbed setup again:

```
Example Setup:      NEL-IP                   CS/CR-WARDEN-LINK-IP      CS/CR-LINK-IFACE
                    ----------------         ---------------------     ------------------
          Sender:   192.168.2.104*           172.16.2.104              eth0
          Receiver: 192.168.2.103*           172.16.2.103*             wlp4s0*
             *=value actually used, other values are not provided as cmd-line parameters!
```

### Running the NEL Tool

The parameters that we use to run `nel` are as follows:

```
usage: nel  'sender'|'receiver'  <specific parameters, see below>:
       nel  sender   CR-NEL-link-IP CR-warden-link-IP
       nel  receiver CS-NEL-link-IP CR-warden-link-Interface
```

On the computer of Alice, we run `nel sender 192.168.2.103 172.16.2.103`. On Bob's computer, we start `nel receiver 192.168.2.104 wlp4s0`.

### What the Tool Does

Alice sends test packets to Bob, randomly utilizing the covert channel techniques she knows. She announces all the test traffic a priori to Bob. Bob will configure his `pcap` filter so that he catches exactly the packets announced by Alice.

After an initial time (~1 sec) that Alice waits for Bob to set-up his pcap filter, she sends a configurable number of test packets (by default: 3) to Bob. (Side note: technically, Alice runs `scapy` to send the test traffic.) If Bob receives one of the test packets during a configurable waiting time, he acknowledges (over the feedback channel) that he received the test traffic.

As soon as one test packet was successfully sent to Bob, Alice continuously uses the protocols known as non-blocked protocols to send data to Bob.

Once 200 packets were successfully transferred (either test traffic of the NEL phase or communication phase traffic), the NEL programs end and consider the data transfer as completed. Output will be provided that shows

- what traffic was sent and received and
- how long it took to complete the transfer (incl. NEL phase and successfully transferring the pre-defined number of packets from Alice to Bob).

# Fine-tuning

Some of the **NEL parameters can easily be changed** in the C header file `nel.h`:
```
#define CR_NEL_TESTPKT_WAITING_TIME	5 /* Waiting time of NEL receiver for packets from Alice (in seconds) */
#define NUM_COMM_PHASE_PKTS		3000  /* number of COMM phase packets to send; should be enough to succeed also under heavily-blocked circumstances */
#define NUM_OVERALL_REQ_PKTS		200   /* number of CC packets (overall) that must go through warden before we count NEL as completed */
#define NUM_COMM_PHASE_SND_PKTS_P_PROT	5 /* how many packets to send during the *COMM* phase per non-blocked protocol in a row */
#define NUM_NEL_TESTPKT_SND_PKTS_P_PROT 5 /* how many packets to be sent per CC type during *NEL* phase */
```

# Adding New Covert Channel Techniques

**Additional covert channels can be integrated** by adding new array elements to the global array `ruleset` in `cs.c`. However, **for each a new covert channel technique that is introduced, the value `ANNOUNCED_PROTO_NUMBERS` in `nel.h` must be incremented by 1**.

Each `ruleset` element consists of three elements that are added in the form `{element1, element2, element3}`:
- a title for the covert channel technique,
- a *scapy* command that must be in the form `a=...` (because later `send(a)` is called; the destination of the NEL receiver is automatically set), and
- a *pcap* filter rule that catches exactly this packet sent by the *scapy* command (used by the NEL receiver).

The following example illustrates this array's structure:
```
char *ruleset[ANNOUNCED_PROTO_NUMBERS+1][3] = {
        /* update ANNOUNCED_PROTO_NUMBERS after adding new proto here! */
        { "IPv4 w/ reserved flag set",
              "a=IP(flags=0x4)",
              "ip[6] = 0x80" },
        ...
        {NULL, NULL, NULL}
   };
```
If you update `ruleset`, make sure that you keep `{NULL, NULL, NULL}` at the end.

# Active Wardens Simulation

By default, the NEL tool simulates no warden. However, it can simulate a regular warden (static ruleset), a dynamic warden (see Mazurczyk et al., 2019) as well as a simplified version of the adaptive warden (see Chourib et al., 2021). The warden behavior can be turned on in `nel.h`. To active one of the wardens, simply use one of the specified macros for `WARDEN_MODE` in `nel.h`. For example, the following line turns on the *adaptive* warden:

```
#define WARDEN_MODE WARDEN_MODE_ADP_WARDEN
```

In `nel.h`, one can also configure warden-specific behavior, such as

- the fraction of filtered packets for regular wardens;
- the reload interval (corresponds to the reload frequency) for dynamic and adaptive wardens;
- the size of the inactive-checked rules that are moved to the active rules during the next time-slot (only adaptive warden).

Therefore, the following macros can be edited:

```
/* WARDEN_MODE_REG/DYN/ADP_WARDEN -> SIM_LIMIT_FOR_BLOCKED_SENDING -- NEW in v.0.2.6:
 * Simulate a WARDEN already in this tool w/o relying on extra software.
 * Values:
 * 0=sender will send 0% (block 100%) of the probe packets;
 * 2=sender will send 4% (block 96%) of the probe packets;
 * 25=sender will send/block 50% of the probe packets;
 * 50=sender will send 100% of the probe protocols (DEFAULT) */
#define SIM_LIMIT_FOR_BLOCKED_SENDING 25
/* WARDEN_MODE_DYN/ADP -> RELOAD_INTERVAL [seconds]:
 * After how many seconds should we shuffle the active rules again?
 * Note: This is not exact. It is always RELOAD_INTERVAL+small overhead.
 */
#define RELOAD_INTERVAL		 10
/* WARDEN_MODE_ADP -> SIM_INACTIVE_CHECKED_MOVE_TO_ACTIVE:
 * How many of the recently triggered inactive rules are activated
 * during the next run?
 * 0=No rules will be moved (essentially this means: deactivation of feature!)
 * 2=the 2 latest triggered rules would be moved
 * 50=All rules will be moved (i.e. warden only based on observations of triggers!)
 */
#define SIM_INACTIVE_CHECKED_MOVE_TO_ACTIVE  5
```



# Scientific Work Using NELTool

NELTool was currently used to perform experiments for the following scientific projects:

- **Verification of Experiments of the Adaptive Warden**: The adaptive warden implemented in (Chourib et al., 2021) used the NEL code for verifying plausibility of experimental results.
- **Invention of a Dynamic Warden**: Testing how a new type of active warden, a so-called *dynamic warden*, performs in terms of combating NEL-capable covert channels. The publication appeared in the journal *Future Generation Computer Systems* (FGCS) as (Mazurczyk et al., 2019).

If you used NELTool for your experiments, let me know and I am happy to link your research here.

# Bug Reports, Patches and Extensions

Please send bug reports/patches and extensions (also in the form of patches) to the author (`wendzel (at) hs-worms (dot) de`) so that these improvements can be provided to all users.

# Additional Background

Several hiding methods are known that allow the realization of covert channels over the network, see e.g. (Mazurczyk et al., 2016) or (Wendzel et al., 2015) for a survey. Currently, the research community knows about ~150 different hiding methods for network data. However, this number does not include those methods that utilize the transferred payload (e.g. JPEG files or HTTP payload). Moreover, the number of known hiding methods continuously increases.

For the NEL phase, another aspect of covert channels is also important. Covert channels can transfer internal protocols, called *control protocols* or *micro protocols* that allow the exchange of structured information in a header, see (Wendzel and Keller, 2011), (Kaur et al., 2016) and (Mazurczyk et al., 2016; Chapter 4). Announcements for test traffic as well as acknowledgements (both over the feedback channel) are realized with a simple control protocol. More advanced control protocols enable TCP-like reliability or even dynamic overlay routing.


# References

- M. Chourib, S. Wendzel, W. Mazurczyk: Adaptive Warden Strategy for Countering Network Covert Storage Channels, in Proc. 36th Conference on Local Computer Networks (LCN), IEEE, 2021, [PDF](https://arxiv.org/abs/2111.03310).

- W. Mazurczyk, S. Wendzel, M. Chourib, J. Keller: [Countering Adaptive Network Covert Communication with Dynamic Wardens](https://www.sciencedirect.com/science/article/pii/S0167739X18316133), Future Generation Computer Systems (FGCS), Vol. 94, pp. 712-725, Elsevier, 2019.

- W. Mazurczyk, S. Wendzel: [Information Hiding – Challenges for Forensic Experts](https://cacm.acm.org/magazines/2018/1/223894-information-hiding/fulltext), Communications of the ACM, Vol. 61(1), pp. 86-94, January 2018. [Summarizing video](https://vimeo.com/245230404)


- W. Mazurczyk, S. Wendzel, S. Zander, A. Houmansadr, K. Szczypiorski (2016): *[Information Hiding in Communication Networks: Fundamentals, Mechanisms, Applications, and Countermeasures](http://eu.wiley.com/WileyCDA/WileyTitle/productCd-1118861698.html)*, Wiley-IEEE press.

- S. Wendzel, J. Keller (2011): *[Low-attention Forwarding for Mobile Network Covert Channels](http://www.researchgate.net/profile/Steffen_Wendzel/publication/215661202_Low-attention_Forwarding_for_Mobile_Network_Covert_Channels/links/00b495349285e2ae43000000.pdf)*, in Proc. Communications and Multimedia Security (CMS 2011), LNCS vol. 7025, pp. 122-133, Springer, Ghent, Belgium.

- S. Wendzel (2012): *[The Problem of Traffic Normalization Within a Covert Channel's Network Environment Learning Phase](https://www.researchgate.net/publication/229091999_The_Problem_of_Traffic_Normalization_Within_a_Covert_Channel%27s_Network_Environment_Learning_Phase?ev=srch_pub&_sg=yiWm%2Fl1DEUeQDayeMTW0oEMG5Uyxo4zfcmAAOkr6NkJtTx6g7xucnaWMAIFkzvlq_n6tx%2Fpj8MwJkZ%2FDhSCYZtVcY3G8XFjtuD0wGGY97liDms58KUp77JmWf%2F2uLjaFg_9rtZQe80mfDWVt%2BOxdHhJvIgvvSP8%2FJUpvi9Tx32b%2BASAG60z5JBglEJw%2Fx0RbUK)*, Proc. Sicherheit 2012, LNI vol. 195, pp. 149-161.

- S. Wendzel, S. Zander, B. Fechner, C. Herdin (2015): *[Pattern-based Survey and Categorization of Network Covert Channel Techniques](http://dl.acm.org/authorize?N10035)*, ACM Computing Surveys, Vol. 47(3), ACM, 2015.

- J. Kaur, S. Wendzel, O. Eissa, J. Tonejc, M. Meier (2016): *[Covert Channel-internal Control Protocols: Attacks and Defense](https://www.researchgate.net/publication/301235801_Covert_channel-internal_control_protocols_Attacks_and_defense)*, Security and Communication Networks (SCN), Vol. 9(15), pp. 2986–2997, Wiley, 2016.

- F. V. Yarochkin, S. Y. Dai, C.-H. Lin, Y. Huang, S.-Y. Kuo (2008): *Towards Adaptive Covert Communication System*, Proc. 2008 14th IEEE Pacific Rim International Symposium on Dependable Computing, pp. 153-159, IEEE.

## Websites
- [Information Hiding Patterns Project](http://ih-patterns.blogspot.de/p/authorscontact.html)
- [Massive Open Online Class on Network Information Hiding](https://github.com/cdpxe/Network-Covert-Channels-A-University-level-Course)
- [Github repository with several network covert channels](https://github.com/cdpxe/NetworkCovertChannels)
- [Open Covert Channel Detection System](https://github.com/cdpxe/nefias) (also Github)
- [CCEAP](https://github.com/cdpxe/CCEAP) covert channels learning tool
