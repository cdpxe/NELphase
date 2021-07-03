# Network Environment Learning (NEL) Phase for Covert Channels (incl. a Feedback Channel and Warden Simulator).

In *Network Steganography* research, a covert channel is a stealthy communication channel. Some covert channels are capable of performing a so-called [**Network Environment Learning** phase](https://www.researchgate.net/publication/229091999_The_Problem_of_Traffic_Normalization_Within_a_Covert_Channel%27s_Network_Environment_Learning_Phase?ev=srch_pub&_sg=yiWm%2Fl1DEUeQDayeMTW0oEMG5Uyxo4zfcmAAOkr6NkJtTx6g7xucnaWMAIFkzvlq_n6tx%2Fpj8MwJkZ%2FDhSCYZtVcY3G8XFjtuD0wGGY97liDms58KUp77JmWf%2F2uLjaFg_9rtZQe80mfDWVt%2BOxdHhJvIgvvSP8%2FJUpvi9Tx32b%2BASAG60z5JBglEJw%2Fx0RbUK) (or: **NEL** phase). Such covert channels can determine how data can be covertly exchanged in a way that countermeasures (firewalls, traffic normalizers, active wardens) can be bypassed.

For instance, a typical covert channel technique is to embed secret data in reserved or unused bits of protocol headers. A typical firewall filter could simply clear the bit to prevent such a covert channel. During the NEL phase, communicating covert channel peers can determine such a filter rule and switch to alternative covert channels.

Although the NEL phase was originally discussed in academia about ten years ago, *no implementation was made available by other researchers*. With *NEL*, **we provide the first public implementation of a NEL phase** on the basis of *scapy* and *libpcap*. In addition, NEL can simulate the influence of regular (static), dynamic and adaptive wardens on the NEL phase. NEL is written in C and runs best under Linux.

**Requirements:**

- Scapy must be installed
- gcc and make
- pcap library, incl. libpcap-dev, must be installed
- pthreads library

**Documentation:** Please have a look at the *[documentation](https://github.com/cdpxe/NELphase/blob/master/documentation/README.md)*.

**My open online class on Network Covert Channels:** available [here](https://github.com/cdpxe/Network-Covert-Channels-A-University-level-Course).

**Covert Channel Detection System:** If you are looking for a network covert channel detector, have a look at my project *[NeFiAS](https://github.com/cdpxe/nefias)*.

**Other Covert Channel Tools:** See my repository on [network covert channel tools](https://github.com/cdpxe/NetworkCovertChannels).

**Feedback:** Please send requests and feedback to the author ([Steffen Wendzel](https://www.wendzel.de)) (`wendzel (at) hs-worms (dot) de`).
