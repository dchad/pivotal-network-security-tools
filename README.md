# pivotal-network-security-tools
Automatically exported from code.google.com/p/pivotal-network-security-tools

# Status: EXPERIMENTAL

Pivotal NST monitors network traffic to detect malicious activity, provides visualisation, reporting and management tools, and generates crafted pushback to malicious adversaries.

# 1. Introduction

Pivotal NST consists of four main components:

- Sensor: these processes run on Linux hosts and perform live packet capture using libpcap or parse Unified2 log files generated by Snort/Suricata IDS systems. Suspicious packets and alerts are forwarded to a Pivotal server. Sensors also perform 5-gram analysis on the IP packet data using a bloom filter. For a description of n-gram analysis see (Wressnegger et al, 2013). 

- Server: these processes receive data from the sensor processes and perform various analysis functions to determine the threat level of the suspicious activity. Relevant data is sent to the human interface for visualisation. Servers also perform real-time online intelligence gathering using resources such as Google Safebrowsing. For a description of the intelligence framework see (Amann et al, 2012). 

- GUI: implements functions for visualisation, alerting, reports and management activities. 

- Honeypot: spoofs typical server ports, generates pushback payloads, inserts the payloads into files pulled by the malicious adversary. 

# 2 Quick Start Guide

TODO

# 3 Screenshots

TODO


# 4 References

Bernhard Amann, Robin Sommer, Aashish Sharma, and Seth Hall. (2012). A lone wolf no more: Supporting network intrusion detection with real-time intelligence. Lecture Notes in Computer Science, 7462:314–333, 2012. CODEN LNCSD9. ISSN 0302-9743 (print), 1611-3349 (electronic). URL http://link.springer.com/chapter/10.1007/978-3-642-33338-5_16/

Ke Wang, Janak J. Parekh, Salvatore J. Stolfo. (2006). Anagram: A Content Anomaly Detector Resistant to Mimicry Attack. Computer Science Department, Columbia University.

Wressnegger, C., Schwenk, G., Arp, D., Rieck, K. (2013). A Close Look on n-Grams in Intrusion Detection: Anomaly Detection vs. Classification. In Proceedings of the 2013 ACM workshop on Artificial intelligence and security (AISec '13). ACM, New York, NY, USA, 67-76. DOI=10.1145/2517312.2517316 http://doi.acm.org/10.1145/2517312.2517316


# 5 Acknowledgements

TODO


# 6 Sensor/Server Protocol

All messages between between sensors and the server are plain text event data or control messages.

1. Event Messages

<event>

...data...

</event>

- Event data messages containing requested updates, remote connections or IDS alerts.

2. Control Messages

<control>

...data...

</control>

- Disconnect: a sensor shutdown.

- Alarm: a sensor generated an alarm.

- Error: a sensor encountered a critical error.

- Request: server requests sensor update, connection IP map or traffic statistics. 
