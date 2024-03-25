# Denial-of-Service (DoS) and Distributed Denial-of-Service (DDoS) Attacks

## Introduction

- Denial-of-Service (DoS) attacks pose a significant threat to computer networks by disrupting or preventing legitimate user access to system resources. 

- DoS and DDoS attacks exploit vulnerabilities in TCP/IP protocol implementations or OS bugs. In a DoS attack, the system is overwhelmed with non-legitimate service requests, rendering the victim's resources inaccessible. Perpetrators often target high-profile web servers like banks and payment gateways.

## Objectives

- Perform DoS attacks: SYN flooding, Ping of Death (POD), and UDP application layer flood.
- Execute a DDoS attack.
- Detect and analyze DoS attack traffic.
- Detect and protect against a DDoS attack.

## Overview of Denial of Service

- DoS attacks can disrupt services and harm targets in terms of time and resources. Protection is crucial to prevent accidental destruction of files and programs. Various types of DoS attacks include flooding systems, crashing TCP/IP stacks, and causing services to hang.

## Methods

#### 1. DoS and DDoS Attacks
   - SYN flooding using Metasploit.
   - DoS Attack on a Target Host using hping3.
   - Execute a DoS Attack using Raven-storm.
   - Initiate a DDoS Attack using HOIC.
   - Launch a DDoS Attack using LOIC.

#### 2. Detect and Protect Against DoS and DDoS Attacks
   - Implement detection and protection against DDoS using Anti DDoS Guardian.

---

### 1. Perform DOS and DDoS Attacks using Various Techniques

- DOS and DDoS attacks have gained popularity due to accessible exploit plans and minimal effort required for execution. These attacks pose severe threats, capable of rendering even the largest Internet hosts useless. Impact includes loss of goodwill, disabled networks, financial losses, and organizational disruption. DDoS attacks inundate targets with fake requests, making systems slow, useless, or entirely unavailable.

- DDoS attacks primarily target network bandwidth, exhausting resources and restricting legitimate user access. Attack vectors include volumetric attacks, protocol attacks, and application layer attacks.

##### Categories of Attack Vectors

---

| Category                | Description                                                                                                     | Techniques                                           |
|-------------------------|-----------------------------------------------------------------------------------------------------------------|------------------------------------------------------|
| Volumetric Attacks      | Consume target network or service bandwidth, overwhelming resources.                                            | - UDP flood<br>- ICMP flood<br>- Ping of Death<br>- Smurf attack<br>- Pulse wave<br>- Zero-day attack              |
| Protocol Attacks        | Consume resources like connection state tables in network infrastructure components.                           | - SYN flood<br>- Fragmentation attack<br>- Spoofed session flood<br>- ACK flood                                   |
| Application Layer Attacks | Consume application resources, making them unavailable.                                                          | - HTTP GET/POST attack<br>- Slowloris attack<br>- UDP application layer flood<br>- DDoS extortion attack            |

---

#### DOS Attack (SYN Flooding) on a Target Host using Metasploit

- SYN flooding exploits a flaw in the TCP three-way handshake, overwhelming the system with unlimited SYN packets. Metasploit, a powerful penetration testing platform, provides the tools needed to conduct such attacks.

##### Steps

- Check Port 21:
   - Use Nmap to check if port 21 on the victim machine is open.

- Metasploit Setup:
   - Launch `msfconsole` from the command line.

- Load SYN Flood Module:
   - Type `use auxiliary/dos/tcp/synflood` to load the SYN flood module.

- View Module Options:
   - Type `show options` to display configuration options for the module.

- Configure Attack Parameters:
   - Set target IP (`RHOST`), target port (`RPORT`), and spoofed IP (`SHOST`) using `set` commands.

- Initiate DOS Attack:
    - Type `exploit` to start the SYN flooding attack.

- Verify Attack:
    - Switch to victim machine, observe performance degradation, indicating the ongoing DOS attack.

- Capture Traffic with Wireshark:
    - Open Wireshark on attacker machine to observe traffic and IP spoofing.

---

#### DOS Attack on a Target Host using hping3

- [hping3](https://github.com/antirez/hping) is a versatile command-line network scanning and packet crafting tool for TCP/IP protocols. It serves various purposes, including network security auditing, firewall testing, manual path MTU discovery, advanced traceroute, and more. Here, we can use hping3 to execute DOS attacks like SYN flooding, Ping of Death (POD), and UDP application layer flood attacks on a target host.

##### Steps

**On Victim machine**

- Launch Wireshark.
- Start capturing packets by double-clicking on the primary network interface.

**On attacker machine**

- Initiate SYN Flooding:
   - Execute SYN flooding attack: `hping3 -S (Target IP) -a (Spoofed IP) -p 22 --flood`.
   - Stop the attack with `Ctrl+C` after a few seconds.

- Perform Ping of Death (POD) Attack:
   - In Terminal, type `hping3 -d 65538 -S -p 21 --flood (Target IP)` to initiate a POD attack.

- UDP Application Layer Flood Attack:
   - Determine if NetBIOS port 139 is open on the target using `nmap -p 139 (Target IP)`.
   - Execute UDP flood attack: `hping3 -2 -p 139 --flood (Target IP)`.

**On Victim machine**

- Analyze Attack Impact:
   - Observe the captured TCP-SYN packets in Wireshark on victim machine.
   - Analyze the graphical view of captured packets by going to Statistics > I/O Graph.

##### Note:

- `SYN flooding` can lead to system crashes if sustained for a long time.
- `POD attacks` aim to destabilize systems with malformed or oversized packets.
- `UDP application layer flood attacks` overload the victim's resources.

---

#### DOS Attack using Raven-storm

- Raven-Storm is a powerful DDoS tool for penetration testing, featuring Layer 3, Layer 4, and Layer 7 attacks. It is written in Python3 and is effective in shutting down hosts and servers. Here, we will use Raven-storm to perform a DOS attack.

##### Steps:

**On Attacker machine**

- Run Raven-storm:
   - Type `sudo rst` and press Enter to start the Raven-storm tool.

- Load Layer 4 module:
   - Type `14` and press Enter to load the Layer 4 module (UDP/TCP).

**On Victim machine**

- Open Wireshark:
   - Launch Wireshark.
   - Double-click on the primary network interface to start capturing network traffic.

**On Attacker machine**

- Specify target details:
   - In the terminal, type:
      - `ip 10.10.1.19` to specify the target IP address.
      - `port 80` to specify the target port.
      - `threads 20000` to specify the number of threads.
      - Type `run` to start the DOS attack.
      - Raven-storm starts the DOS attack on the target machine.

**On Victim machine**

   - Observe a large number of packets received from the attacker machine.

---
