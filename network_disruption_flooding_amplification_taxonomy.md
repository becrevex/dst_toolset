# Network Disruption Through Packet Flooding, Reflection, and Amplification

*A comprehensive taxonomy of network-based Denial-of-Service (DoS) and Distributed Denial-of-Service (DDoS) attack vectors, organized by protocol, OSI layer, and resource exhaustion mechanism.*

The interesting thing about these attacks is that **a network doesn't have to run out of bandwidth to become unusable.** Depending on the protocol and the targeted infrastructure, relatively small amounts of traffic can overwhelm forwarding tables, connection state, CPU resources, memory, or routing processes.

The IETF's RFC 4732 distinguishes several of these mechanisms, including resource exhaustion, packet flooding, reflection, and amplification.

## 1. Fundamental disruption mechanisms

Before enumerating individual protocols, it's useful to separate six underlying failure mechanisms.

| Mechanism | What gets exhausted or disrupted |
|---|---|
| **Volumetric flooding** | Link bandwidth, ingress/egress capacity |
| **Packet-rate flooding** | Packet processing capacity, interrupts, forwarding performance |
| **State exhaustion** | Connection tables, NAT mappings, session memory |
| **CPU/compute exhaustion** | Routing CPUs, cryptographic processing, application threads |
| **Reflection/amplification** | Third-party services generate traffic toward a victim |
| **Control-plane disruption** | Routing convergence, topology stability, address resolution |

These mechanisms overlap. For example, a SYN flood might exhaust a server's connection backlog without saturating its network link, while a DNS amplification attack primarily attempts to saturate bandwidth.

---

## 2. Layer 2 — Data Link and Local Network Flooding

*Primary targets: Ethernet switches, wireless access points, VLANs, forwarding tables, and local broadcast domains.*

| # | Attack vector | Disruption mechanism |
|---:|---|---|
| 1 | Ethernet broadcast flooding | Saturates a broadcast domain with frames delivered to participating hosts |
| 2 | Unknown-unicast flooding | Forces switches to flood frames when destinations are absent from forwarding tables |
| 3 | Multicast flooding | Overwhelms multicast recipients or switching capacity |
| 4 | ARP request flooding | Excessive address-resolution broadcasts consume host and switch resources |
| 5 | ARP reply flooding | High volumes of ARP replies stress host processing and neighbor-cache handling |
| 6 | Gratuitous ARP flooding | Excessive address announcements can cause cache churn and processing overhead |
| 7 | CAM/MAC table flooding | Exhausts or destabilizes switch forwarding-table capacity |
| 8 | MAC address flapping | Repeated MAC-location changes cause forwarding instability |
| 9 | STP BPDU flooding | Excessive spanning-tree control traffic burdens switching control processes |
| 10 | STP topology-change flooding | Repeated topology-change notifications cause forwarding-table flushing and relearning |
| 11 | DHCP DISCOVER flooding | Overloads DHCP processing and can contribute to address-pool exhaustion |
| 12 | DHCP REQUEST/renew flooding | Burdens lease processing and DHCP server state |
| 13 | LLDP/CDP flooding | Excessive neighbor-discovery messages consume control-plane resources |
| 14 | IEEE 802.1X/EAPOL flooding | Overloads access authentication and supplicant/authenticator processing |
| 15 | PPPoE discovery flooding | Exhausts access concentrator processing or session setup capacity |
| 16 | IGMP report flooding | Overwhelms multicast membership processing |
| 17 | Wireless probe-request flooding | Consumes AP management-frame processing and airtime |
| 18 | Wireless authentication/association flooding | Exhausts AP authentication or association resources |
| 19 | 802.11 deauthentication/disassociation flooding | Disrupts wireless client connectivity, particularly where management frames lack protection |

**Important distinction:** ARP flooding, ARP spoofing, and MAC-table flooding are different mechanisms. ARP flooding is primarily a volume or processing problem; ARP spoofing is an integrity attack that can also disrupt availability.

Likewise, an Ethernet broadcast storm can arise from a switching loop without any malicious actor. An attacker-induced flood and an accidental topology loop may produce nearly identical symptoms.

Juniper documents both the propagation characteristics of Layer 2 broadcast storms and the forwarding-table effects associated with spanning-tree topology changes.

## 3. IPv6 Neighbor Discovery and Local Control Traffic

IPv6 deserves its own category because Neighbor Discovery Protocol (NDP) replaces several functions traditionally associated with IPv4 ARP.

| # | Attack vector | Disruption mechanism |
|---:|---|---|
| 20 | Neighbor Solicitation (NS) flooding | Consumes NDP processing and neighbor-cache resources |
| 21 | Neighbor Advertisement (NA) flooding | Causes neighbor-cache processing and potential state instability |
| 22 | Router Advertisement (RA) flooding | Overwhelms host router-discovery processing and may disrupt configuration |
| 23 | Router Solicitation (RS) flooding | Burdens IPv6 router-discovery responses |
| 24 | Duplicate Address Detection (DAD) disruption | Interferes with IPv6 address initialization, potentially denying address use |
| 25 | IPv6 neighbor-cache exhaustion | Forces excessive creation of incomplete neighbor entries |
| 26 | DHCPv6 SOLICIT/REQUEST flooding | Overloads DHCPv6 server processing or address assignment |
| 27 | MLD membership flooding | Stresses IPv6 multicast listener-state handling |
| 28 | ICMPv6 control-message flooding | Consumes resources used for essential IPv6 network operations |

IPv6 neighbor discovery is particularly interesting because resource exhaustion can occur in the router's neighbor cache rather than in the bandwidth of the link itself. This failure class is documented in RFC 6583 and RFC 9898.

## 4. Layer 3 — Network Layer Flooding

*Primary targets: Routers, firewalls, IP stacks, fragmentation handling, and forwarding capacity.*

| # | Attack vector | Disruption mechanism |
|---:|---|---|
| 29 | ICMP Echo Request flooding | Overwhelms endpoints or intermediate network capacity |
| 30 | ICMP Echo Reply flooding | Creates packet-processing or bandwidth pressure |
| 31 | ICMP Destination Unreachable flooding | Burdens ICMP error-message processing |
| 32 | ICMP Time Exceeded flooding | Consumes error-processing resources |
| 33 | Raw IP packet flooding | Saturates forwarding or host packet-processing capacity |
| 34 | IP protocol-number flooding | Burdens devices handling unsupported or unusual IP protocols |
| 35 | IPv4 fragmentation flooding | Exhausts fragmentation/reassembly processing and buffers |
| 36 | IPv6 fragmentation flooding | Stresses endpoint fragment reassembly resources |
| 37 | Malformed/overlapping fragment flooding | Exploits implementation weaknesses in fragment handling, where present |
| 38 | TTL/hop-limit expiration flooding | Forces exceptional packet handling or control-plane processing |
| 39 | Destination-address sweeping | Causes address-resolution churn, route misses, or exception processing |
| 40 | Routed multicast flooding | Saturates multicast distribution paths and receivers |
| 41 | GRE encapsulated flooding | Overwhelms tunnel processing or transported traffic capacity |
| 42 | IP-in-IP encapsulation flooding | Consumes tunnel decapsulation and forwarding capacity |
| 43 | VXLAN/Geneve overlay flooding | Overloads virtual network endpoints and overlay forwarding resources |

A crucial distinction here is **fast-path versus slow-path processing**. A high-end router might forward enormous quantities of ordinary IP packets in hardware, but certain exceptional packets must be handled by a comparatively limited control-plane CPU.

That means packets per second and processing path can matter more than raw gigabits per second.

## 5. Layer 4 — TCP, UDP, and Transport Flooding

*Primary targets: TCP/IP stacks, session tables, transport processing, and network appliances.*

| # | Attack vector | Disruption mechanism |
|---:|---|---|
| 44 | TCP SYN flooding | Exhausts half-open connection state or SYN backlogs |
| 45 | TCP SYN-ACK flooding | Burdens TCP response processing or packet forwarding |
| 46 | TCP ACK flooding | Saturates packet-processing paths or firewall state inspection |
| 47 | TCP RST flooding | Overloads reset processing; forged resets can also terminate sessions |
| 48 | TCP FIN flooding | Burdens TCP close-state or invalid-segment handling |
| 49 | TCP PSH/ACK flooding | Generates processing load through payload-bearing segments |
| 50 | TCP malformed/invalid-flag flooding | Stresses packet validation and security-device inspection |
| 51 | Completed TCP connection flooding | Exhausts accepted-connection capacity, sockets, or application workers |
| 52 | TCP connection-churn flooding | Forces continual allocation and deallocation of connection state |
| 53 | TCP retransmission/reordering flooding | Stresses buffering, sequencing, and inspection logic |
| 54 | TCP listen-backlog exhaustion | Exhausts queued incoming connection capacity |
| 55 | Connection-tracking exhaustion | Fills firewall or NAT session tables |
| 56 | Generic UDP flooding | Saturates bandwidth or UDP packet-processing capacity |
| 57 | UDP port-distribution flooding | Overwhelms packet filtering, classification, or ICMP-error handling |
| 58 | Small-packet UDP flooding | Exhausts packets-per-second forwarding capacity |
| 59 | QUIC Initial-packet flooding | Burdens QUIC handshake and connection setup |
| 60 | QUIC connection-churn flooding | Exhausts QUIC connection management and crypto processing |
| 61 | DTLS handshake flooding | Causes excessive datagram-based TLS handshake processing |
| 62 | TLS handshake flooding | Consumes CPU through repeated cryptographic handshakes |
| 63 | IKE/IPsec negotiation flooding | Exhausts VPN key-exchange or security-association processing |
| 64 | STUN/TURN request flooding | Overwhelms NAT traversal and relay infrastructure |
| 65 | RTP media flooding | Saturates voice/video media bandwidth or processing |
| 66 | IPsec ESP flooding | Overloads encrypted-packet forwarding, filtering, or security-association handling |

Cloudflare and Cisco document many of the TCP, UDP, and protocol-flood variants used in DDoS attacks.

Not every TCP flag variant represents a fundamentally different vulnerability. For example, ACK, FIN, and PSH/ACK floods may all primarily exhaust packet-processing capacity, depending on the target implementation.

---

## 6. Reflection and Amplification Attacks

This is a particularly important category.

**Reflection** means traffic is redirected toward a victim through third-party systems. **Amplification** means the resulting traffic or workload is larger than the triggering traffic.

An attack may employ reflection without significant amplification, and amplification can occur without IP-source spoofing.

```text
Attacker ── small requests ──► Reflectors / network services
                                      │
                                      └── larger responses ──► Victim
```

*Conceptual flow only. Typical reflected attacks depend on vulnerable services and the ability to misattribute the requester.*

The following are documented reflection or amplification vectors. Some remain relevant, while others are historical, uncommon, or dependent on vulnerable implementations. A10's 2025 DDoS Weapons Report tracks 31 protocol categories, demonstrating how broadly amplification extends beyond DNS and NTP.

| # | Protocol / attack vector | Abused service or behavior |
|---:|---|---|
| 67 | DNS amplification | DNS responses |
| 68 | NTP amplification | Network time-service responses |
| 69 | SSDP amplification | UPnP device discovery |
| 70 | CLDAP amplification | Connectionless directory queries |
| 71 | Memcached amplification | Exposed UDP cache services |
| 72 | SNMP amplification | Network management responses |
| 73 | Multicast DNS amplification | mDNS service discovery |
| 74 | NetBIOS Name Service amplification | Legacy Windows name-resolution responses |
| 75 | WS-Discovery amplification | Web Services device discovery |
| 76 | CoAP amplification | Constrained Application Protocol responses |
| 77 | TFTP amplification | File-transfer service responses |
| 78 | RPCbind/Portmap amplification | RPC service-discovery responses |
| 79 | RIPv1 amplification | Legacy routing information exchanges |
| 80 | CHARGEN amplification | Character Generator service |
| 81 | QOTD amplification | Quote of the Day service |
| 82 | UDP Echo amplification | Legacy echo service |
| 83 | BitTorrent amplification | Peer-to-peer protocol responses |
| 84 | Kademlia/DHT amplification | Distributed hash-table messages |
| 85 | Quake/Steam protocol amplification | Game-server discovery and status responses |
| 86 | Valve Source Engine amplification | Game-server information queries |
| 87 | SLP amplification | Service Location Protocol |
| 88 | NAT-PMP amplification | NAT Port Mapping Protocol |
| 89 | OpenVPN amplification | VPN protocol responses in vulnerable configurations |
| 90 | RDP UDP amplification | Remote Desktop UDP transport responses |
| 91 | IBM DB2 amplification | Database discovery/services |
| 92 | Microsoft SQL Server amplification | Database discovery responses |
| 93 | Ubiquiti discovery amplification | Network-device discovery responses |
| 94 | NETIS amplification | Vulnerable router service behavior |
| 95 | Plex amplification | Media-server discovery responses |
| 96 | Jenkins amplification | Jenkins discovery-service responses |
| 97 | Apple ARMS amplification | Legacy Apple Remote Management Service |
| 98 | Dahua UDP amplification | Network-camera/device services |
| 99 | Mitel amplification | Vulnerable telephony services |
| 100 | DHCPv6 amplification | DHCPv6 response behavior |
| 101 | DTLS amplification | Datagram TLS handshake responses |
| 102 | TCP SYN-ACK reflection | TCP server handshake responses |
| 103 | ICMP Smurf attack | Reflected ICMP responses through IP broadcast |
| 104 | UDP Fraggle attack | Reflected UDP responses through broadcast-capable services |

The last two deserve special attention historically: Smurf and Fraggle relied on broadcast reflection, while modern attacks commonly exploit exposed services capable of returning larger responses.

Also, a vulnerable protocol does not automatically make every implementation an amplifier. Exposure, implementation behavior, network configuration, and source-validation controls are decisive.

## 7. Layer 7 — Application and Service Flooding

*Primary targets: DNS, web servers, application servers, APIs, databases, and protocol-specific services.*

These attacks are particularly interesting because the volume of network traffic may be modest relative to the amount of computational work triggered.

| # | Attack vector | Disruption mechanism |
|---:|---|---|
| 105 | HTTP GET flooding | Overwhelms web servers with requests |
| 106 | HTTP POST flooding | Exhausts application processing, upload, or request-body handling |
| 107 | HTTPS request flooding | Saturates encrypted web application capacity |
| 108 | HTTP/2 stream flooding | Exhausts stream-management or concurrent-request resources |
| 109 | HTTP/2 Rapid Reset | Excessive stream creation/cancellation consumes server resources |
| 110 | HTTP/2 CONTINUATION flooding | Exploits vulnerable HTTP/2 header processing to exhaust CPU or memory |
| 111 | HTTP/3 request flooding | Burdens HTTP/3 application processing over QUIC |
| 112 | WebSocket message flooding | Exhausts persistent-connection handling or message processing |
| 113 | gRPC request flooding | Overwhelms RPC handlers and backend services |
| 114 | GraphQL query flooding | Exhausts API and backend processing through excessive queries |
| 115 | REST API endpoint flooding | Saturates API workers, rate-limit capacity, or downstream services |
| 116 | Authentication request flooding | Exhausts authentication, password hashing, or identity-provider capacity |
| 117 | Search/report generation flooding | Overloads computationally expensive application operations |
| 118 | Cache-bypass request flooding | Forces repeated work on backend systems instead of cached responses |
| 119 | DNS query flooding | Saturates authoritative or recursive DNS servers |
| 120 | DNS NXDOMAIN flooding | Overwhelms DNS processing with nonexistent-name queries |
| 121 | DNS water-torture/random-prefix flooding | Generates uncached DNS lookup pressure on authoritative infrastructure |
| 122 | DNSSEC processing flooding | Overloads DNSSEC validation or signed-response processing |
| 123 | Recursive DNS cache-miss flooding | Forces excessive upstream DNS resolution |
| 124 | SMTP connection/message flooding | Overloads mail transfer and message-processing infrastructure |
| 125 | LDAP query flooding | Exhausts directory server query processing |
| 126 | SIP INVITE flooding | Overwhelms VoIP session establishment |
| 127 | SIP REGISTER flooding | Exhausts SIP registration and authentication processing |
| 128 | SIP OPTIONS flooding | Burdens SIP capability discovery and signaling processing |
| 129 | RTSP request flooding | Overloads streaming-session control |
| 130 | MQTT CONNECT/PUBLISH flooding | Exhausts IoT messaging brokers and subscriber processing |
| 131 | AMQP message flooding | Overloads messaging exchanges, queues, and consumers |
| 132 | SMB request flooding | Exhausts file-sharing server resources |
| 133 | NFS/RPC request flooding | Overwhelms file-serving and remote-procedure processing |
| 134 | SSH/RDP authentication flooding | Exhausts remote-access authentication and session handling |
| 135 | Database query flooding | Overwhelms query execution, connection pools, or storage I/O |

Two particularly notable examples are HTTP/2 Rapid Reset (CVE-2023-44487) and HTTP/2 CONTINUATION flooding, which demonstrated that protocol implementation behavior can create substantial denial-of-service exposure without conventional bandwidth saturation.

Similarly, DNS water-torture attacks attempt to defeat caching advantages by generating high volumes of unique DNS queries.

---

## 8. Routing and Network Control-Plane Flooding

*Primary targets: Routing engines, control protocols, routing adjacencies, topology databases, and network controllers.*

This category can be especially disruptive because it targets the infrastructure responsible for keeping the network operational.

| # | Attack vector | Disruption mechanism |
|---:|---|---|
| 136 | BGP OPEN/session flooding | Exhausts routing-session establishment capacity |
| 137 | BGP UPDATE flooding | Burdens BGP update processing and routing information bases |
| 138 | BGP withdrawal/route-flap flooding | Causes repeated routing recalculations and convergence instability |
| 139 | OSPF Hello flooding | Overwhelms adjacency and control-packet processing |
| 140 | OSPF LSA flooding | Exhausts link-state database processing or SPF computation |
| 141 | IS-IS LSP flooding | Burdens link-state synchronization and routing calculations |
| 142 | EIGRP query/update flooding | Overloads routing information processing |
| 143 | BFD control-packet/session flooding | Disrupts rapid failure detection or session-management processing |
| 144 | PIM Join/Prune flooding | Exhausts multicast routing control-state processing |
| 145 | MPLS LDP message flooding | Overwhelms label-distribution or session management |
| 146 | RSVP-TE signaling flooding | Exhausts signaling state or reservation processing |
| 147 | EVPN MAC/IP advertisement flooding | Causes excessive overlay control-plane state updates |
| 148 | SDN/OpenFlow PACKET_IN flooding | Overwhelms centralized controller processing |
| 149 | Network-management API/SNMP polling flooding | Exhausts network-device management CPU resources |
| 150 | Control-plane exception/punt flooding | Forces excessive traffic from hardware forwarding into software processing |
| 151 | Firewall logging-event flooding | Exhausts log processing, storage, or inspection resources |
| 152 | IDS/IPS inspection flooding | Overwhelms deep-packet-inspection capacity |
| 153 | Load-balancer session flooding | Exhausts load-balancer state or backend connection resources |
| 154 | Overlay-controller event flooding | Burdens virtual-network state distribution and reconciliation |
| 155 | VPN tunnel-establishment flooding | Exhausts tunnel negotiation or session capacity |

Some of these require an authenticated routing adjacency, local network position, or access to a management interface. They are not universally exploitable from the public Internet.

IETF RFC 4593 documents generic routing-protocol threats, while Cisco's control-plane policing guidance describes how control-packet overload can disrupt network stability and forwarding.

## 9. Specialized Ethernet, Data Center, and Industrial Network Flooding

A few additional mechanisms don't fit neatly into traditional Internet DDoS classifications.

| # | Attack vector | Disruption mechanism |
|---:|---|---|
| 156 | IEEE 802.3x PAUSE-frame abuse | Unnecessarily suspends Ethernet transmission |
| 157 | Priority Flow Control (PFC) storms | Propagates congestion and can cause network-wide throughput collapse or deadlock |
| 158 | LACP control-message flooding | Burdens link-aggregation control processing or destabilizes membership |
| 159 | 802.11 RTS/CTS management/control flooding | Consumes wireless airtime or interferes with medium access |
| 160 | BACnet Who-Is/I-Am flooding | Overwhelms building-automation devices with discovery traffic and responses |
| 161 | BACnet router-discovery flooding | Overloads building-automation routing and discovery processes |
| 162 | Modbus TCP request flooding | Exhausts industrial controller communication/processing capacity |
| 163 | DNP3 polling flooding | Saturates industrial outstation request handling |
| 164 | OPC UA session/request flooding | Exhausts industrial application session and service resources |
| 165 | PTP timing-message flooding | Burdens timing infrastructure and, depending on implementation, interferes with synchronization |

PFC storms are a significant example of a nontraditional disruption mechanism. Because flow control is designed to pause traffic under congestion, pathological PAUSE propagation can interrupt traffic well beyond the original congested link.

BACnet discovery traffic presents another interesting case: relatively small discovery requests can produce widespread broadcast responses from building-automation devices.

---

## 10. How to categorize these attacks in a security research framework

I would use two independent classification dimensions rather than just assigning every attack an OSI layer.

First, identify the **protocol or packet family**. Then classify the **resource or process being attacked**.

For example:

| Attack | Bandwidth | Packet processing | State/memory | CPU/compute | Control-plane stability |
|---|---|---|---|---|---|
| SYN flooding | Possible | High | High | Moderate | Low |
| ARP flooding | Moderate | High | Possible | High | Possible |
| DNS amplification | High | High | Low | Variable | Low |
| MAC table flooding | Moderate | High | High | Variable | High |
| OSPF LSA flooding | Low–moderate | Moderate | High | High | High |
| HTTP/2 Rapid Reset | Variable | Moderate | High | High | Low |
| UDP small-packet flooding | Variable | High | Low | High | Low |
| PFC storm | Variable | Variable | Low | Low | High |

*Qualitative susceptibility, not measured severity. Actual impact depends on implementation, traffic rate, hardware acceleration, and protection mechanisms.*

### A useful way to think about defensive coverage

Every class should ultimately be mapped to the defense that addresses its particular failure mechanism: Ethernet storm control and Layer 2 security; source-address validation and anti-spoofing; connection-state protections; control-plane policing; application-level rate/resource limits; and upstream DDoS scrubbing or traffic engineering.

For network telemetry, I'd capture at least bandwidth (bps), packet rate (pps), request rate (rps/qps), connection creation rate, session-table occupancy, forwarding-table utilization, CPU consumption, packet drops, and routing-state changes.

## Final observation

This inventory contains **165 distinct vectors or variants**, although some overlap or share essentially the same underlying mechanism. No finite enumeration can be literally exhaustive because new protocols and vulnerable implementations continually introduce additional paths to resource exhaustion.

The most significant distinction is not SYN versus UDP versus DNS. It's this:

> **Network disruption occurs whenever externally influenced traffic causes a critical shared resource to be consumed, saturated, destabilized, or made unavailable faster than the system can recover.**

That includes attacks generating tremendous traffic volumes, but it also includes attacks where a relatively small amount of traffic triggers disproportionately expensive work.

For serious network security engineering, that second category is arguably the more intellectually interesting one.

---

## Selected cited standards and references

The original response referred to the following named sources and topics; the content above has been preserved as Markdown prose and tables without internal chat citation markers.

- IETF RFC 4732 — *Internet Denial-of-Service Considerations*: https://www.rfc-editor.org/rfc/rfc4732
- IETF RFC 6583 — *Operational Neighbor Discovery Problems*: https://www.rfc-editor.org/rfc/rfc6583
- IETF RFC 9898 — IPv6 Neighbor Discovery resource-exhaustion considerations: https://www.rfc-editor.org/rfc/rfc9898
- IETF RFC 4593 — *Generic Threats to Routing Protocols*: https://www.rfc-editor.org/rfc/rfc4593
- CVE-2023-44487 — HTTP/2 Rapid Reset denial of service
- A10 Networks — *2025 DDoS Weapons Report*
- Cisco — Control-plane policing and DDoS guidance
- Cloudflare — DDoS protocol flooding, HTTP/2 Rapid Reset, and DNS water-torture documentation
- Juniper Networks — Ethernet broadcast storms and spanning-tree topology change documentation
