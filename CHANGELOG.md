## CHANGELOG for the NEL tool

v. current (0.4.0) (2021-July-22):
 * Add an option to simulate a regular warden by defining a fraction of CCs that are blocked (by simply preventing their probe packets being sent). Made sure time consumption is similar to regular sending.
 * Added option to simulate a regular warden.
 * Added option to simulate a *simplified* adaptive warden.
 * Remove unnecessary cs.h.
 * Put some macro checks in separate file so that some major configuration mistakes are caught.
 * Tell the CR about the configuration (type of warden and its settings) so that it can be displayed when NEL phase is completed to ease the analysis process. This is useful in combination with a typescript (see script(1)).
 * Fixed several (minor) bugs and performed code clean-ups; improved inline documentation.

v. 0.2.5:
 * Slightly updated the markdown files (also pointed out the idea of the dynamic warden).
 * Performed some tiny improvements of the documentation.

v. 0.2.4:
 * Changed several details in terms of the packet counting and general NEL parameters.
 * Changed utilization of libpcap.
 * Improved documentation.

v. 0.2.1-0.2.3:
 * Improved several aspects of the documentation
 * Added several new rules provided by Mehdi Chourib

v. 0.2.0 : 2017-05-06
 * Initial public release (github)

