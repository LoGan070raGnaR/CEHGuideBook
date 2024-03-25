# Sniffing

- Packet sniffing is the process of monitoring and capturing all data packets passing through a given network using a software application or hardware device.

- Earlier tasks taught how to damage target systems by infecting them using malware, which gives limited or full control of the target systems to further perform data exfiltration.

- Packet sniffing allows observing and accessing the entire network's traffic from a given point. There are two types of sniffing: passive and active. Passive sniffing refers to sniffing on a hub-based network, while active sniffing refers to sniffing on a switch-based network.

- Attackers often use sniffers to target vulnerable protocols like HTTP, FTP, SMTP, POP, Telnet, IMAP, and NNTP. Sniffed traffic may contain sensitive information, such as passwords, chat sessions, email and web traffic, and DNS traffic.

## Objective

- Sniff the network
- Analyze incoming and outgoing packets for any attacks
- Troubleshoot the network for performance
- Secure the network from attacks

## Overview of Network Sniffing

Sniffing is straightforward in hub-based networks, but most networks today work on switches. Packet sniffers are used to convert the host system's NIC to promiscuous mode, capturing packets addressed to the specific network. There are two types of sniffing: Passive Sniffing and Active Sniffing.

**Passive Sniffing**

- Involves capturing and monitoring packets flowing in the network.

**Active Sniffing**

- Searches for traffic on a switched LAN by injecting traffic into the LAN.

## Methods

#### 1. Active Sniffing

   - MAC flooding using `macof`
   - DHCP starvation attack using `yersinia`
   - ARP poisoning using `arpspoof`
   - Man-in-the-Middle (MITM) attack using `Cain & Abel`
   - Spoof a MAC Address using `TMAC` and `SMAC`
   - Spoof a MAC Address of Linux Machine using `macchanger`

#### 2. Network Sniffing using Various Tools

   - Password Sniffing using Wireshark
   - Analyze a Network using the Omnipeek Network Protocol Analyzer
   - Analyze a Network using the SteelCentral Packet Analyzer

#### 3. Detect Network Sniffing

   - Detect ARP Poisoning and Promiscuous Mode in a Switch-Based Network
   - Detect ARP Poisoning using the Capsa Network Analyzer

---

### 1. Active Sniffing

- Active sniffing searches for traffic on a switched LAN by actively injecting traffic into the LAN. Active sniffing also refers to sniffing through a switch.

- As a professional ethical hacker or pen tester, the first step is to perform active sniffing on the target network using various active sniffing techniques such as MAC flooding, DHCP starvation, ARP poisoning, or MITM. In active sniffing, the switched Ethernet does not transmit information to all systems connected through the LAN as it does in a hub-based network.

- In active sniffing, ARP traffic is actively injected into a LAN to sniff around a switched network and capture its traffic. A packet sniffer can obtain all the information visible on the network and records it for future review. A pen tester can see all the information in the packet, including data that should remain hidden.


**Overview of Active Sniffing:**

- Active sniffing involves sending out multiple network probes to identify access points. The following is the list of different active sniffing techniques:

---

| Technique               | Description                                                                                                                                                                           |
|-------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| MAC Flooding            | Involves flooding the CAM table with fake MAC address and IP pairs until it is full                                                                                                   |
| DNS Poisoning           | Involves tricking a DNS server into believing that it has received authentic information when, in reality, it has not                                                                  |
| ARP Poisoning           | Involves constructing a large number of forged ARP request and reply packets to overload a switch                                                                                     |
| DHCP Attacks            | Involves performing a DHCP starvation attack and a rogue DHCP server attack                                                                                                           |
| Switch Port Stealing    | Involves flooding the switch with forged gratuitous ARP packets with the target MAC address as the source                                                                             |
| Spoofing Attack         | Involves performing MAC spoofing, VLAN hopping, and STP attacks to steal sensitive information                                                                                       |

---

#### Perform MAC Flooding using macof

- MAC flooding is a technique used to compromise the security of network switches that connect network segments or network devices. Attackers use the MAC flooding technique to force a switch to act as a hub, so they can easily sniff the traffic. 
- `macof` is a Unix and Linux tool that is a part of the dsniff collection. It floods the local network with random MAC addresses and IP addresses, causing some switches to fail and open in repeating mode, thereby facilitating sniffing. This tool floods the switch's CAM tables (131,000 per minute) by sending forged MAC entries. When the MAC table fills up, the switch converts to a hub-like operation where an attacker can monitor the data being broadcast.

##### Steps

- Launch Wireshark and double-click the available Ethernet or interface (e.g., `eth0`) to start the packet capture.

- Leave the Wireshark application running.

- In Terminal window, type `macof -i eth0 -n 10` and press Enter. Note: `-i` specifies the interface and `-n` specifies the number of packets to be sent (here, 10).

- This command will start flooding the CAM table with random MAC addresses.

- Switch to the Wireshark window and observe the IPv4 packets from random addresses.

- Click on any captured IPv4 packet and expand the Ethernet II node in the packet details section. Information regarding the source and destination MAC addresses is displayed.

- Similarly, you can switch to a different machine to see the same packets that were captured by Wireshark.

- `macof` sends the packets with random MAC and IP addresses to all active machines in the local network. If you are using multiple targets, you will observe the same packets on all target machines.

---

#### DHCP Starvation Attack using Yersinia

- DHCP starvation attack using the Yersinia tool to flood the DHCP server and cause a Denial-of-Service (DOS) attack.

##### Steps

- Open the Wireshark Network Analyzer on the Attacker machine.

- In the Wireshark application, double-click the relevant ethernet or interface (e.g., eth0) to start packet capture.

- Leave Wireshark running in the background.

- Open Yersinia in interactive mode:
    ```bash
    yersinia -I
    ```

- Press `F2` to select DHCP mode; the STP Fields will change to DHCP Fields.

- Press `x` to list available attack options.

- In the Attack Panel window, press `1` to start a DHCP starvation attack.

- Yersinia will start sending DHCP packets to the network and all active machines in the local network.

- After a few seconds, press `q` to stop the attack and terminate Yersinia.

- Switch to the Wireshark window and observe the captured DHCP packets.

- Click on any DHCP packet to expand the Ethernet II node and view source/destination MAC addresses.

---

#### ARP Poisoning using arpspoof

- ARP spoofing is a technique for compromising an Ethernet LAN by manipulating ARP (Address Resolution Protocol) messages. Here, the attacker's system tricks the target system into associating the attacker's MAC address with the IP address of the gateway, leading to a Man-in-the-Middle (MITM) scenario. The arpspoof tool is employed to redirect packets within the LAN, effectively allowing the attacker to intercept and modify traffic.

##### Steps

- Open Wireshark Network Analyzer; select the Ethernet interface (e.g., eth0) and start packet capture.
- Keep Wireshark running in the background.

**ARP Poisoning with arpspoof**

- Execute the arpspoof command to poison ARP caches:
   ```bash
   arpspoof -i eth0 -t 10.10.1.1 10.10.1.11
   ```
   - Replace `eth0` with the appropriate network interface.
   - Here, 10.10.1.1 is the gateway's IP, and 10.10.1.11 is the target's IP.

- After sending a few packets, stop ARP poisoning by pressing `CTRL + Z`.

- Observe captured ARP packets in Wireshark, showcasing the manipulation.

- Switch back to the terminal and issue the reverse arpspoof command:
    ```bash
    arpspoof -i eth0 -t 10.10.1.11 10.10.1.1
    ```
    - This informs the target system that the attacker's system is the gateway.

- Stop poisoning again with `CTRL + Z`.

- In Wireshark, note the alert "duplicate use of 10.10.1.11 detected!"

- Click on any ARP packet to inspect details, revealing MAC addresses of 10.10.1.1 and 10.10.1.11.

- Verify that MAC addresses are the same for 10.10.1.1 and 10.10.1.13, indicating ARP poisoning.

**Analysis**

- Understand that the attacker, using arpspoof, replaced the MAC address in the ARP cache of the target.

- Any traffic from the victim to the gateway is redirected to the attacker's system.

---

#### Spoof a MAC Address of Linux Machine using macchanger

- A MAC address is a unique identifier for network interfaces, crucial for system programs and protocols. While it's generally not possible to change a hardcoded MAC address on the NIC, some drivers allow modification. MAC spoofing, changing the MAC address to mask the computer's identity, can be achieved using tools like macchanger.

##### Steps

- Before changing the MAC address, turn off the network interface:
   ```bash
   ifconfig eth0 down
   ```

- Check available options for macchanger:
   ```bash
   macchanger --help
   ```

- To view the current MAC address of the machine:
   ```bash
   macchanger -s eth0
   ```

- Change the MAC address to a random vendor MAC:
   ```bash
   macchanger -a eth0
   ```

- Set a completely random MAC address:
   ```bash
   macchanger -r eth0
   ```

- Turn on the network interface:
   ```bash
   ifconfig eth0 up
   ```

- Check the changed MAC address:
   ```bash
   ifconfig
   ```

- The network interface now has a spoofed MAC address.

---

### 2. Perform Network Sniffing using Various Sniffing Tools

- Data flowing through HTTP channels is often in plain-text format, making it susceptible to Man-in-the-Middle (MITM) attacks. While network administrators use sniffers for legitimate purposes such as troubleshooting and debugging, attackers can exploit tools like Wireshark to intercept and analyze traffic. This intercepted data may contain sensitive information, such as login credentials, enabling malicious activities like user session impersonation.

- Attackers may manipulate switches to view all passing traffic. Packet sniffers, or sniffing programs, in promiscuous mode can capture and analyze all network traffic. Enterprises with open switch ports are particularly vulnerable. Sniffing tools disable Ethernet Network Interface Card (NIC) filters, allowing the capture of traffic from all stations.

- System administrators utilize automated tools to monitor networks, but attackers exploit these tools for unauthorized network data sniffing. Network sniffing tools enable detailed network analysis, providing essential information about packet traffic. Actively scanning the network allows threat hunters to stay vigilant and respond promptly to potential attacks.

---

#### Perform Password Sniffing using Wireshark

- Wireshark, a powerful network packet analyzer, facilitates the capture and detailed display of network packets. Utilizing Winpcap, it can capture live network traffic from various networks, including Ethernet, IEEE 802.11, PPP/HDLC, ATM, Bluetooth, USB, Token Ring, Frame Relay, and FDDI networks.

##### Steps

- Capture Packets:
    - Start capturing packets on the chosen interface (e.g., Ethernet) on Wireshark.

- Perform Actions on Victim Machine:
    - Switch to the victim machine.
    - Log in, open a browser, and visit a website, perform actions that involve entering a username and password.

- Stop Packet Capture:
    - Switch back to the attacker machine.
    - Stop capturing packets in Wireshark.

- Save Captured Packets:
    - Save the captured packets with an appropriate file name (e.g., PasswordSniffing.pcapng).

- Apply Display Filter:
    - Apply a display filter to narrow down the search for HTTP POST traffic (e.g., `http.request.method POST`).

- Analyze Captured Data:
    - Use Wireshark's features to analyze captured data, including finding packets.

- Extract Password:
    - Locate and extract the sniffed password from the captured packets.

**Remote Packet Capture (Optional):**

- Start Remote Packet Capture:
    - Launch Wireshark and go to Capture Options.
    - Manage Interfaces, add a remote host (Victim machine) with its IP address and port (e.g., 10.10.1.11:2002).

- Authentication:
    - Provide credentials (e.g., Username: Jason, Password: qwerty) for the target machine.

- Capture Remote Traffic:
    - Start capturing packets from the remote interface.

- Perform Actions on Victim Machine:
    - On the victim machine, perform actions like browsing a website.

- Stop Remote Capture:
    - Stop the remote packet capture and analyze.

---

### 3. Detect Network Sniffing

**Overview of Detecting Network Sniffing**

- Network sniffing involves the real-time monitoring and analysis of data packets within computer networks. Detection of network sniffers is achieved through various techniques, including:

---

| Detection Method  | Description                                                                                                                |
|-------------------|----------------------------------------------------------------------------------------------------------------------------|
| Ping Method       | Identifies systems in promiscuous mode on the network by sending ICMP Echo Requests (ping) and observing responses.        |
| DNS Method        | Detects sniffers by analyzing increased network traffic related to DNS requests, which may indicate unauthorized monitoring. |
| ARP Method        | Sends a non-broadcast ARP (Address Resolution Protocol) to all nodes, identifying nodes in promiscuous mode through cached local ARP addresses. |

---
