# Scanning Networks

## Introduction

- Network scanning refers to a set of procedures performed to identify the hosts, ports, and services running in a network.

- Earlier, you gathered all possible information about the target such as organization information (employee details, partner details, web links, etc.), network information (domains, subdomains, sub sub-domains, IP addresses, network topology, etc.), and system information (OS details, user accounts, passwords, etc.). 

- Now, as an ethical hacker or penetration tester, your next step will be to perform port scanning and network scanning on the IP addresses obtained in the information-gathering phase. This will help you to identify an entry point into the target network.

- Scanning itself is not the actual intrusion but an extended form of reconnaissance in which the ethical hacker and pen tester learn more about the target, including information about open ports and services, OSes, and any configuration lapses.

- This is one of the most important phases of intelligence gathering, enabling you to create a profile of the target organization. In the process of scanning, you attempt to gather information, including the specific IP addresses of the target system that can be accessed over the network (live hosts), open ports, respective services running on the open ports, and vulnerabilities in the live hosts.

- Port scanning will help you identify open ports and services running on specific ports, which involves connecting to Transmission Control Protocol (TCP) and User Datagram Protocol (UDP) system ports. Port scanning is also used to discover the vulnerabilities in the services running on a port.

## Objective

- To conduct network scanning, port scanning, analyzing the network vulnerabilities, etc.

- **Network scans are needed to:**
    - Check live systems and open ports
    - Identify services running in live systems
    - Perform banner grabbing/OS fingerprinting
    - Identify network vulnerabilities

## Overview of Scanning Networks

- Network scanning is the process of gathering additional detailed information about the target by using highly complex and aggressive reconnaissance techniques. The purpose of scanning is to discover exploitable communication channels, probe as many listeners as possible, and keep track of the responsive ones.

- **Types of scanning:**
    - **Port Scanning:** Lists open ports and services
    - **Network Scanning:** Lists the active hosts and IP addresses
    - **Vulnerability Scanning:** Shows the presence of known weaknesses

## Methods

Ethical hackers and pen testers use numerous tools and techniques to scan the target network.

#### 1. Host Discovery

- **Host Discovery using nmap**
- **Host Discovery using angry IP Scanner**

#### 2. Port and Service Discovery

- **Port and Service Discovery using megaping**
- **Port and Service Discovery using NetScanTools Pro**
- **Port Scanning using sx Tool**
- **Explore Various Network Scanning Techniques using Nmap**
- **Explore Various Network Scanning Techniques using Hping3**

#### 3. OS Discovery

- **Identify the Target System's OS with Time-to-Live (TTL) and TCP Window Sizes using Wireshark**
- **OS Discovery using Nmap Script Engine (NSE)**
- **OS Discovery using Unicornscan**

#### 4. Scan Beyond IDS and Firewall

- **Scan beyond IDS/Firewall using various Evasion Techniques**
- **Create Custom Packets using Colasoft Packet Builder to Scan beyond IDS/Firewall**
- **Create Custom UDP and TCP Packets using Hping3 to Scan beyond IDS/Firewall**
- **Browse Anonymously using Proxy Switcher**
- **Browse Anonymously using CyberGhost VPN**

#### 5. Perform Network Scanning using Various Scanning Tools

- **Scan a Target Network using Metasploit**

---
### 1. Host Discovery

- Host discovery is considered the primary task in the network scanning process. It is used to discover the active/live hosts in a network. It provides an accurate status of the systems in the network, which, in turn, reduces the time spent on scanning every port on every system in a sea of IP addresses in order to identify whether the target host is up.

- **Examples of host discovery techniques:**
    - ARP ping scan
    - UDP ping scan
    - ICMP ping scan (ICMP ECHO ping, ICMP timestamp, ping ICMP, and address mask ping)
    - TCP ping scan (TCP SYN ping and TCP ACK ping)
    - IP protocol ping scan

#### Perform Host Discovery using Nmap

- Nmap is a utility used for network discovery, network administration, and security auditing. It is also used to perform tasks such as network inventory, managing service upgrade schedules, and monitoring host or service uptime. Here, we will use Nmap to discover a list of live hosts in the target network using various host discovery techniques.


- Host Discovery Commands:

---

| **Command**                                       | **Description**                                                                                                                                                                                                                                                                                                                                                                                                         |
|---------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `nmap -sn -PR [Target IP Address]`                 | ARP Ping Scan command: `-sn` disables port scan, `-PR` performs ARP ping scan. Result indicates live hosts in the target network. ARP ping scan sends ARP requests to target hosts; an ARP response means the host is active.                                                                                                                                                                                                |
| `nmap -sn -PU [Target IP Address]`                 | UDP Ping Scan command: `-sn` disables port scan, `-PU` performs UDP ping scan. Result indicates live hosts. UDP ping scan sends UDP packets; a UDP response means the host is active. Various error messages may indicate an offline or unreachable host.                                                                                                                                                                       |
| `nmap -sn -PE [Target IP Address]`                 | ICMP ECHO Ping Scan command: `-sn` disables port scan, `-PE` performs ICMP ECHO ping scan. Result shows live hosts. ICMP ECHO ping scan sends ICMP ECHO requests to hosts; if alive, they respond with an ICMP ECHO reply. Useful for locating active devices and checking ICMP passage through a firewall.                                                                                                             |
| `nmap -sn -PE [Target Range of IP Addresses]`      | ICMP ECHO Ping Sweep command: `-sn` disables port scan, `-PE` performs ICMP ECHO ping scan. Result indicates live hosts in a range of target IP addresses. ICMP ECHO ping sweep sends ICMP ECHO requests to multiple hosts; if alive, they respond with ICMP ECHO replies. Useful for determining live hosts from a range of IP addresses.                                                                                 |
| `nmap -sn -PP [Target IP Address]`                 | ICMP Timestamp Ping Scan command: `-sn` disables port scan, `-PP` performs ICMP timestamp ping scan. Result indicates live hosts. ICMP timestamp ping is an optional ICMP ping; attackers query a timestamp message to get information related to the current time from the target host machine.                                                                                                                                                                          |
| `nmap -sn -PM [target IP address]`                 | ICMP Address Mask Ping Scan command: `-sn` disables port scan, `-PM` performs ICMP address mask ping scan. Alternative to ICMP ECHO ping scan for host live detection, useful when administrators block ICMP ECHO pings.                                                                                                                                                                                                     |
| `nmap -sn -PS [target IP address]`                 | TCP SYN Ping Scan command: `-sn` disables port scan, `-PS` performs TCP SYN ping scan. Result indicates live hosts. TCP SYN ping scan sends empty TCP SYN packets; an ACK response means the host is active.                                                                                                                                                                                                               |
| `nmap -sn -PA [target IP address]`                 | TCP ACK Ping Scan command: `-sn` disables port scan, `-PA` performs TCP ACK ping scan. Result indicates live hosts. TCP ACK ping scan sends empty TCP ACK packets; an RST response means the host is active.                                                                                                                                                                                                               |
| `nmap -sn -PO [target IP address]`                 | IP Protocol Ping Scan command: `-sn` disables port scan, `-PO` performs IP protocol ping scan. Result indicates live hosts. IP protocol ping scan sends different probe packets of different IP protocols; any response indicates that a host is active.                                                                                                                                                               |

---

- You can also use other ping sweep tools such as [Angry IP Scanner](https://github.com/angryip/ipscan), [SolarWinds Engineer's Toolset](https://www.solarwinds.com), [NetScanTooIs Pro](https://www.netscantools.com), [Colasoft Ping Tool](https://www.colasoft.com), [Visual Ping Tester](http://www.pingtester.net), and [OpUtils](https://www.manageengine.com) to discover active hosts in the target network.

---
### 2. Port and Service Discovery

- Port and service discovery is the process of identifying open ports and services running on the target IP addresses/active hosts.

- As a professional ethical hacker or a pen tester, the next step after discovering active hosts in the target network is to scan for open ports and services running on the target IP addresses in the target network.

- Port scanning techniques are categorized according to the type of protocol used for communication within the network.

    - **TCP Scanning**
        - Open TCP scanning methods (TCP connect/full open scan)
        - Stealth TCP scanning methods (Half-open Scan, Inverse TCP Flag Scan, ACK flag probe scan, third party and spoofed TCP scanning methods)

    - **UDP Scanning**

    - **SCTP Scanning**
        - SCTP INIT Scanning
        - SCTP COOKIE/ECHO Scanning

    - **SSDP and List Scanning**

    - **IPv6 Scanning**

#### Perform Port Scanning using sx Tool

- The `sx` tool is a command-line network scanner that can be used to perform ARP scans, ICMP scans, TCP SYN scans, UDP scans, and application scans such as SOCS5 scan, Docker scan, and Elasticsearch scan.

- In the terminal window, type `sx arp [Target subnet]` and press Enter (e.g., 10.10.1.0/24) to scan all the IP addresses and MAC addresses associated with the connected devices in a local network.
   - `arp` performs an ARP scan.

- Type `sx arp [Target subnet] --json | tee arp.cache` and press Enter to create `arp.cache` file.

   - `--json` converts a text file to the JSON format, `tee` writes the data to stdin.
   - Before the actual scan, `sx` explicitly creates an ARP cache file which is a simple text file containing a JSON string on each line and has the same JSON fields as the ARP scan JSON output. The protocols such as TCP and UDP read the ARP cache file from stdin and then begin the scan.

- Type `cat arp.cache | sx tcp -p 1-65535 [Target IP address]` and press Enter to list all the open tcp ports on the target machine (e.g.,  10.10.1.11).

   - `tcp` performs a TCP scan
   - `-p` specifies the range of ports to be scanned (here, the range is 1-65535).

- In the terminal, type `sx help` and press Enter to obtain the list of commands that can be used. For more information, you can further use `sx --help` command.

- Now, let us perform UDP scan on the target machine to check if a port is open or closed.

- In the terminal, type `cat arp.cache | sx udp --json -p [Target Port] 10.10.1.11` and press Enter (here, target port is 53).

   - `udp` performs a UDP scan, `-p` specifies the target port.
   - In a UDP scan `sx` returns the IP address, ICMP packet type, and code set to the reply packet.

- The result appears, with the reply packet from the host with Destination Unreachable type (3) and Port Unreachable code (3), which indicates that the target port is closed.

   - Note: According to RFC1122, a host should generate Destination Unreachable messages with code: 2 (Protocol Unreachable), when the designated transport protocol is not supported; or 3 (Port Unreachable), when the designated transport protocol (e.g., UDP) is unable to demultiplex the datagram but has no protocol mechanism to inform the sender.
   - Note: According to RFC792, network unreachable error is specified with code: 0, Host unreachable error with code: 1, Protocol unreachable error with code: 2, Port unreachable error with code 3.

- Type `cat arp.cache | sx udp --json -p [Target Port] 10.10.1.11` and press Enter (here, the target port is 500).

- You can observe that `sx` does not return any code in the above command, which states that the target port is open.

#### Explore Various Network Scanning Techniques using Nmap

- Nmap comes with various inbuilt scripts that can be employed during a scanning process to find open ports and services running on the target. It sends specially crafted packets to the target host and analyzes the responses to achieve its goal. Nmap includes various port scanning mechanisms (TCP and UDP), OS detection, version detection, ping sweeps, etc.

- In [Zenmap](https://www.kali.org/tools/zenmap-kbx/), type the command `nmap -sT -v [Target IP Address]` (replace [Target IP Address] with the actual target IP, e.g., 10.10.1.22) and click Scan.

   ```bash
   nmap -sT -v 10.10.1.22
   ```
   - `-sT`: performs the TCP connect/full open scan.
   - `-v`: enables verbose output (includes all hosts and ports in the output).

- View the scan results displaying open TCP ports and services running on the target machine.

- Click the Ports/Hosts tab to gather more information on the scan results.

- Click the Topology tab to view the topology of the target network containing the provided IP address.

- Click the Host Details tab to view the details of the TCP connect scan.

- Click the Scans tab to view the command used to perform the TCP connect/full open scan.

- Click the Services tab to see a list of services.

- Perform a stealth scan, Xmas scan, TCP Maimon scan, and ACK flag probe scan on a firewall-enabled machine.

- In Zenmap, type the command `nmap -sS -v [Target IP Address]` and click Scan.

    ```bash
    nmap -sS -v 10.10.1.22
    ```

    - `-sS`: performs the stealth scan/TCP half-open scan.

- View the results showing open TCP ports and services on the target machine.

- Xmas scan (`nmap -sX -v [Target IP Address]`), TCP Maimon scan (`nmap -sM -v [Target IP Address]`), and ACK flag probe scan (`nmap -sA -v [Target IP Address]`).

- Perform a UDP scan on the target machine using the command `nmap -sU -v [Target IP Address]`.

    ```bash
    nmap -sU -v 10.10.1.22
    ```
    - `-sU`: performs the UDP scan.

- View the results showing open UDP ports and services on the target machine.

- Create and use custom scan profiles in Zenmap.

- Optionally, explore additional scanning techniques like IDLE/IPID Header Scan, SCTP INIT Scan, SCTP COOKIE ECHO Scan.

- Perform service version detection on the target machine using the command `nmap -sV [Target IP Address]`.

    ```bash
    nmap -sV 10.10.1.22
    ```
    - `-sV`: detects service versions.

- View the results showing open ports and versions of services running on the target machine.

- Perform an aggressive scan on a subnet using the command `nmap -A [Target Subnet]`.

    ```bash
    nmap -A 10.10.1.*
    ```

    - `-A`: enables an aggressive scan.

- View the results displaying information for all hosts in the scanned subnet.

- Choose an IP address from the list of hosts and click the Host Details tab to view detailed information.

#### Explore Various Network Scanning Techniques using Hping3

- Hping2/[Hping3](https://www.kali.org/tools/hping3/) is a command-line-oriented network scanning and packet crafting tool for the TCP/IP protocol that sends ICMP echo requests and supports TCP, UDP, ICMP, and raw-IP protocols. Using Hping, you can study the behavior of an idle host and gain information about the target such as the services that the host offers, the ports supporting the services, and the OS of the target.

- We can use Hping3 to discover open ports and services running on the live hosts in the target network.

---
| **Command**                                                                                                              | **Description**                                                                                                                                                                                               |
|--------------------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `hping3 -A [Target IP Address] -p 80 -c 5`                                                                              | ACK scan command: `-A` sets ACK flag, `-p` specifies port (80), `-c` specifies packet count (5). Result indicates an open port if sent and received packets are equal.                                        |
| `hping3 -8 0-100 -S [Target IP Address] -V`                                                                           | SYN scan command: `-8` specifies scan mode, `-p` specifies port range (0-100), `-V` specifies verbose mode. Result displays open ports and services.                                                       |
| `hping3 -F -P -U [Target IP Address] -p 80 -c 5`                                                                      | FIN, PUSH, URG scan command: `-F` sets FIN flag, `-P` sets PUSH flag, `-U` sets URG flag, `-p` specifies port (80), `-c` specifies packet count (5). Result indicates open port if packets sent and received are equal. |
| `hping3 --scan 0-100 -S [Target IP Address]`                                                                          | TCP Stealth scan command: `--scan` specifies port range, `0-100` specifies ports, `-S` sets SYN flag. Result displays open ports and services on the target IP.                                                |
| `hping3 -1 [Target IP Address] -p 80 -c 5`                                                                            | ICMP scan command: `-1` specifies ICMP ping scan, `-c` specifies packet count (5), `-p` specifies port (80). Result shows ICMP echo requests sent and received, confirming the host is up.                     |
| `hping3 -1 [Target Subnet] --rand-dest -I eth0`                                                                       | Entire subnet scan for live hosts command.                                                                                                                                                                   |
| `hping3 -2 [Target IP Address] -p 80 -c 5`                                                                            | UDP scan command: `-2` specifies UDP scan, `-p` specifies port (80), `-c` specifies packet count (5). Result indicates open ports.                                                                               |

---
### 3. OS Discovery

- Banner grabbing, or OS fingerprinting, is a crucial step in determining the operating system (OS) running on a remote target system. This information is valuable for assessing system vulnerabilities and planning potential exploits.

- As a professional ethical hacker or pen tester, the next step after discovering open ports and services on the target IP addresses is OS discovery. This enables a comprehensive understanding of the target system's weaknesses and potential attack vectors.

#### OS Discovery/Banner Grabbing Techniques

Banner grabbing involves active and passive techniques:

1. **Active Banner Grabbing**
Specially crafted packets are sent to the remote OS, and responses are compared with a database to determine the OS. Responses vary due to differences in TCP/IP stack implementation.

2. **Passive Banner Grabbing**
Relies on the differential implementation of the stack and includes banner grabbing from error messages, network traffic sniffing, and page extension analysis.

#### Parameters for OS Identification

Parameters like TTL and TCP window size in the IP header's first packet in a TCP session are vital for OS identification. The TTL field determines the maximum packet retention time, and the TCP window size indicates the reported packet length. Refer to the table below for TTL values and TCP window sizes associated with various OSes:

---

| Operating System | Time To Live | TCP Window Size |
|------------------|--------------|------------------|
| Linux            | 64           | 5840             |
| FreeBSD          | 64           | 65535            |
| OpenBSD          | 255          | 16384            |
| Windows          | 128          | 65,535 bytes to 1 Gigabyte |
| Cisco Routers    | 255          | 128              |
| Solaris          | 255          | 8760             |
| AIX              | 255          | 16384            |

---

*Note: Values may vary based on network conditions and configurations.*

---

#### Identify the Target System's OS with Time-to-Live (TTL) and TCP Window Sizes using Wireshark

- Wireshark is a network protocol analyzer used for capturing and analyzing network traffic. We can use Wireshark to identify the target OS by sniffing the response generated from the target machine. Specifically, we can observe the TTL and TCP window size fields in the captured TCP packet.

- **Launch Wireshark:** Open Wireshark.

- **Capture Packets:** Double-click the available Ethernet interface to start packet capture.

- **Generate Traffic:** Ping the target IP (e.g., `ping 10.10.1.22`) and observe captured packets in Wireshark.

- **Analyzing Packets:** Choose an ICMP reply packet from the captured data and expand the Internet Protocol Version 4 node to view TTL values.

- **Interpret TTL Values:** A TTL value of 128 suggests a Windows-based machine. A TTL value of 64 suggests a Linux-based machine.

#### Perform OS Discovery using Nmap Script Engine (NSE)

- Nmap, along with Nmap Script Engine (NSE), is a powerful tool for extracting valuable information from the target system. NSE provides scripts that reveal useful details such as OS, computer name, domain name, and more.

---

| No. | Task                            | Command                                     | Description                                                               |
|-----|---------------------------------|---------------------------------------------|---------------------------------------------------------------------------|
| 1.  | Perform Aggressive Scan         | `nmap -A [Target IP]`                        | Execute an aggressive scan on the target IP to gather detailed information. Analyze the results, including open ports, services, and target details, including OS. |
| 2.  | Perform OS Discovery Scan       | `nmap -O [Target IP]`                        | Execute an OS discovery scan on the target IP to identify the operating system. Examine the results, revealing open ports, services, and the detected OS name. |
| 3.  | Perform SMB OS Discovery        | `nmap --script smb-os-discovery.nse [Target IP]` | Execute an SMB protocol-based discovery on the target IP. Examine the results, revealing OS, computer name, domain, workgroup, and system time. |

---
- In summary, the aggressive scan is an all-encompassing scan that provides a wide range of information, the OS discovery scan specifically focuses on identifying the operating system, and the SMB OS discovery utilizes scripts for OS discovery using the SMB protocol.

---
#### Perform OS Discovery using Unicornscan

- Unicornscan is a Linux-based command line-oriented network information-gathering and reconnaissance tool. It is an asynchronous TCP and UDP port scanner and banner grabber that enables you to discover open ports, services, TTL values, etc. running on the target machine. In Unicornscan, the OS of the target machine can be identified by observing the TTL values in the acquired scan result.


- **Perform Unicornscan for OS Discovery:**
   - Type `unicornscan [Target IP Address] -Iv`
   - *Note: Use `-I` for immediate mode and `-v` for verbose mode.*

- **Review OS Discovery Results:**
   - Analyze the scan output for each target.
   - TTL values of 128 indicate a Windows OS (Windows 8/8.1/10/11 or Windows Server 16/19/22).
   - TTL value of 64 suggests a Linux-based OS.

- Using this information, attackers can formulate an attack strategy based on the OS of the target system.

### 4. Scan Beyond IDS and Firewall

- Scanning beyond IDS and firewall involves sending specific packets to the target system with the aim of exploiting IDS/firewall limitations. This process is crucial for ethical hackers and penetration testers to evaluate and enhance network security.

- As professionals in ethical hacking, the next step after discovering the OS of the target IP address is to conduct network scanning without triggering alarms from network security perimeters, such as firewalls and IDS. Despite their efficiency, IDSs and firewalls have limitations that can be exploited.

#### Techniques to Evade IDS/Firewall

1. **Packet Fragmentation:** Sending fragmented probe packets to the target, reassembling them after reception.
2. **Source Routing:** Specifying the routing path for a malformed packet to reach the target.
3. **Source Port Manipulation:** Manipulating the actual source port to evade IDS/firewall.
4. **IP Address Decoy:** Generating or manually specifying decoy IP addresses to confuse IDS/firewall.
5. **IP Address Spoofing:** Changing source IP addresses to mask the true origin of the attack.
6. **Creating Custom Packets:** Sending tailor-made packets to scan beyond firewalls.
7. **Randomizing Host Order:** Scanning hosts in a random order to reach the intended target beyond the firewall.
8. **Sending Bad Checksums:** Transmitting packets with incorrect TCP/UDP checksums to the target.
9. **Proxy Servers:** Using a chain of proxy servers to hide the true source of a scan and evade specific IDS/firewall restrictions.
10. **Anonymizers:** Utilizing anonymizers to bypass Internet censors and evade specific IDS and firewall rules.

#### Scan beyond IDS/Firewall using Various Evasion Techniques

- Nmap offers features to understand complex networks with security mechanisms and supports bypassing poorly implemented defenses. Various techniques can be implemented using Nmap to evade IDS/firewall security mechanisms.

---

| No. | Evasion Technique              | Command                                       | Description                                                               |
|-----|---------------------------------|-----------------------------------------------|---------------------------------------------------------------------------|
| 1.  | Packet Fragmentation           | `nmap -f [Target IP Address]`                  | Perform a packet fragmentation scan using the `-f` switch to split the IP packet into tiny fragments. Observe results displaying all open TCP ports, even with Windows Defender Firewall turned on. |
| 2.  | Source Port Manipulation       | `nmap -g 80 [Target IP Address]`               | Perform a source port manipulation scan using the `-g` or `--source-port` option. Results show open TCP ports along with service names. |
| 3.  | MTU (Maximum Transmission Unit) | `nmap -mtu 8 [Target IP Address]`              | Perform an MTU evasion scan using the `-mtu` option, specifying the number of Maximum Transmission Unit (MTU) in bytes. Results show fragmented packets with a maximum length of 8 bytes. |
| 4.  | IP Address Decoy               | `nmap -D RND:10 [Target IP Address]`           | Perform an IP address decoy scan using the `-D` option with randomly generated IP addresses. Results show multiple source IP addresses, making it difficult for IDS/firewall to determine the actual scanning IP. |
| 5.  | MAC Address Spoofing           | `nmap -ST -Pn --spoof-mac 0 [Target IP Address]` | Perform a scan with MAC address spoofing using the `--spoof-mac 0` option to randomize the MAC address. Results show open ports with a randomized MAC address. |

---

#### Create Custom UDP and TCP Packets using Hping3 to Scan beyond the IDS/Firewall

- Hping3 is a scriptable program that uses the TCL language, whereby packets can be received and sent via a binary or string representation describing the packets. Here, we will use Hping3 to create custom UDP and TCP packets to evade the IDS/firewall in the target network.

**Custom UDP Packet Creation**

1. On the attacker machine, type the following command to create random UDP packets and send them to the target:
    ```bash
    hping3 [Target IP Address] --udp --rand-source --data 500
    ```

   **Note:** `--udp` specifies sending UDP packets, `--rand-source` enables random source mode, and `--data` specifies the packet body size.

2. To observe the packets, switch to the target machine and use Wireshark to capture and analyze the random UDP packets.

   **Note:** Double-click any UDP packet in Wireshark to inspect details.

3. Expand the Data node in the Packet Details pane to observe the size and length of Data, matching the specified packet body size (500).

**TCP SYN Request**

4. On the attacker machine, type the following command to send TCP SYN requests to the target:
    ```bash
    hping3 -S [Target IP Address] -p 80 -c 5
    ```

   **Note:** `-S` specifies TCP SYN requests, `-p` assigns the port, and `-c` sets the packet count.

5. Observe the result, indicating the transmission and reception of five packets through port 80.

**TCP Flooding Attack**

6. On the attacker machine, type the following command to flood the target with TCP packets:
    ```bash
    hping3 [Target IP Address] --flood
    ```

   **Note:** `--flood` performs TCP flooding.

7. Observe the response in the hping3 terminal after flooding the target.

8. On the target machine, use Wireshark to capture and analyze the TCP packet flooding.

9. Stop the packet capture in the Wireshark window.

10. Observe the Wireshark window, displaying the TCP packet flooding from the host machine.

- You can also use other packet crafting tools such as [NetScanTools Pro](https://www.netscantools.com), [Colasoft Packet Builder](https://www.colasoft.com), etc. to build custom packets to evade security mechanisms.


#### Browse Anonymously using CyberGhost VPN

- CyberGhost VPN hides the attacker's IP and replaces it with a selected IP, allowing for anonymous surfing and access to blocked content. It encrypts the connection and does not keep logs, ensuring data security.

### 5. Perform Network Scanning using Various Scanning Tools

- The information obtained in the previous steps might be insufficient to reveal potential vulnerabilities in the target network; there may be more information available that could help in finding loopholes. As an ethical hacker and pen tester, you should look for as much information as possible about systems in the target network using various network scanning tools when needed.

- Scanning tools are used to scan and identify live hosts, open ports, running services on a target network, location-info, NetBIOS info, and information about all TCP/IP and UDP open ports. Information obtained from these tools will assist an ethical hacker in creating the profile of the target organization and scanning the network for open ports of the connected devices.

#### Scan a Target Network using Metasploit

- Metasploit Framework is a versatile tool that provides information about security vulnerabilities, aiding in penetration testing and IDS signature development. It's known for its modular approach, allowing the combination of any exploit with any payload.


- Start the PostgreSQL service with `service postgresql start`.

- Launch Metasploit with `msfconsole`.

- Check the database connection with `db_status`.

- If not connected, exit Metasploit (`exit`) and initiate the database with `msfdb init`.

- Restart PostgreSQL with `service postgresql restart` and relaunch Metasploit.

- Scan the target subnet (e.g., `nmap -Pn -sS -A -oX Test 10.10.1.0/24`).

- Import the Nmap results into the database with `db_import Test`.

- View active hosts using `hosts`.

- List services on active hosts with `services` or `db_services`.

- Search for port scanning modules with `search portscan`.

- Use the SYN scanning module with `use auxiliary/scanner/portscan/syn`.

- Configure the module (e.g., set INTERFACE, PORTS, RHOSTS, THREADS).

- Run the scan with `run`.

- Explore other scanning options, such as TCP scanning.

- Load the TCP scanning module with `use auxiliary/scanner/portscan/tcp`.

- Set the target IP address with `set RHOSTS`.

- Run the TCP scan with `run`.

- Determine OS details using the SMB version scanning module.

- Revert to the msf command line with `back`.

- Use `use auxiliary/scanner/smb/smb_version`.

- Set target IP range and threads.

- Run the SMB version scan with `run`.

- Document the results and explore other Metasploit modules.

---