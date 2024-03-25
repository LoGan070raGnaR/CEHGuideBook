# Session Hijacking

## Introduction

- Session hijacking involves the unauthorized takeover of either a valid TCP communication session or a user session in a web application. This attack exploits vulnerabilities in session token-generation mechanisms or token security controls, allowing an attacker to establish an unauthorized connection with a target server.

- Here, we are performing session hijacking attack where an attacker exploits session token vulnerabilities to establish unauthorized connections with a target server. Two types of session hijacking are explored: application-level and network-level. 

- Application-level hijacking involves gaining control over HTTP user sessions, while network-level hijacking is mitigated by packet encryption using protocols like IPsec, SSL, and SSH.

## Objectives

- Hijack a session by intercepting traffic between the server and client.
- Steal a user session ID by intercepting traffic.
- Detect session hijacking attacks.

## Overview of Session Hijacking

- Session hijacking can be active or passive:

    - **Active Session Hijacking**: An attacker takes over an active session.
    - **Passive Session Hijacking**: An attacker monitors and records traffic in a session without taking control.

## Methods

#### 1. Session Hijacking
- Hijack a session using Zed Attack Proxy (ZAP)
- Intercept HTTP traffic using Bettercap
- Intercept HTTP traffic using Hetty

#### 2. Detect Session Hijacking
- Detect session hijacking using Wireshark

---

### 1. Session Hijacking

- In a session hijacking attack, an attacker seizes control of a valid user session, establishing an unauthorized connection with a target server. This involves exploiting vulnerabilities in the authentication process, allowing the attacker to guess or steal a valid session ID, subsequently impersonating an authenticated user.

- Session hijacking enables attackers to take over an active session by circumventing authentication. By acquiring a victim's session ID, used by the server to identify authenticated users, the attacker establishes a connection, allowing them to interact with the server as the compromised user. This can lead to various attacks, including man-in-the-middle (MITM) and Denial-of-Service (DOS), where the attacker intercepts or floods the system to disrupt services.

**Overview of Session Hijacking:**

Session hijacking involves three phases:

---

| Phase                               | Description                                                                                                              |
|-------------------------------------|--------------------------------------------------------------------------------------------------------------------------|
| Tracking the Connection              | The attacker identifies a target with a predictable TCP sequence using network sniffers or tools like Nmap.              |
| Desynchronizing the Connection       | The attacker creates a desynchronized state by manipulating the connection, taking advantage of unstable or no data transmission between the server and target. |
| Injecting the Attacker's Packet      | Once the connection is interrupted, the attacker injects data into the network or acts as a man-in-the-middle, controlling data flow between the target and server. |

---

#### Hijack a Session using Zed Attack Proxy (ZAP)

- [Zed Attack Proxy (ZAP)](https://www.zaproxy.org/) is a versatile penetration testing tool designed to uncover vulnerabilities in web applications. It caters to users with varying levels of security expertise, making it suitable for both developers and functional testers. ZAP offers automated scanners and a manual testing toolkit, allowing users to identify security flaws efficiently.

##### Steps

- Configure Proxy on Victim's Machine
    - Open Google Chrome, navigate to Settings > Advanced > System, and access proxy settings.
    - Configure manual proxy setup with IP: 10.10.1.19, Port: 8080, and save the settings.

- Launch ZAP on Attacker's Machine
    - Launch ZAP.
    - Set up ZAP as a proxy by configuring Local Proxies with the server's IP (10.10.1.19) and port (8080).

- Initiate Session Hijacking
    - Add a Breakpoint in ZAP to capture requests and responses.
    - Switch to the victim's machine, launch the configured browser, and visit a website (github.com).
    - Observe ZAP capturing requests in the Break tab.

- Modify Requests in ZAP
    - In ZAP's Break tab, modify captured GET requests (e.g., github.com to amazon.com).
    - Forward the modified traffic to the victim's machine.

- Verify Session Hijacking
    - Continue modifying and forwarding requests until the victim's browser displays amazon.com instead of github.com.

---

#### Intercept HTTP Traffic using bettercap

- Attackers leverage session hijacking for various attacks, including man-in-the-middle (MITM) attacks. Ethical hackers and penetration testers must understand MITM attacks to safeguard sensitive information. Here, we are using bettercap, a versatile tool for MITM attacks, to intercept HTTP traffic on a target system.

##### Steps

- View bettercap options:
   ```bash
   bettercap -h
   ```

- Set the network interface (replace eth0 with your interface):
   ```bash
   bettercap -iface eth0
   ```

- View available modules:
   ```bash
   help
   ```

- Start network probes:
   ```bash
   net.probe on
   ```

- Enable network reconnaissance:
    ```bash
    net.recon on
    ```

- Enable SSL stripping:
    ```bash
    set http.proxy.sslstrip true
    ```

- Start ARP spoofing:
    ```bash
    set arp.spoof.internal true
    ```

- Spoof the target IP address:
    ```bash
    set arp.spoof.targets 10.10.1.11
    ```

- Initiate HTTP proxy:
    ```bash
    http.proxy on
    ```

- Start ARP spoofing:
    ```bash
    arp.spoof on
    ```

- Enable network sniffing:
    ```bash
    net.sniff on
    ```

- Observe network activity.

- On the Victim machine, open a web browser and visit github.com. and enter credentials on the website.

- Observe intercepted traffic on attacker machine.

- Observe credentials in plain text on attacker machine.

---

### 2. Detect Session Hijacking

- Session hijacking poses severe risks, including identity theft, fraud, and sensitive information loss. Networks using TCP/IP are susceptible to these attacks, often challenging to detect and may go unnoticed unless causing significant damage.

- Session hijacking is a serious threat, necessitating awareness and preventive measures. As an ethical hacker or penetration tester, possessing the knowledge to detect and counter session hijacking is paramount. Effective tools, such as packet sniffers, IDSs, and SIEMs, play a vital role in identifying and mitigating session hijacking attacks.


There are two primary methods to detect session hijacking:

---

| Detection Method   | Description                                                                                                           |
|--------------------|-----------------------------------------------------------------------------------------------------------------------|
| Manual Method      | - Use packet sniffing software like Wireshark and SteelCentral Packet Analyzer.<br>- Monitor session hijacking attacks by capturing network packets.<br>- Analyze captured packets using various filtering tools. |
| Automatic Method   | - Deploy Intrusion Detection Systems (IDS) and Intrusion Prevention Systems (IPS).<br>- Monitor incoming network traffic.<br>- IDS generates alerts if a packet matches any attack signatures in the internal database.<br>- IPS blocks traffic matching attack signatures from entering the network. |

---

#### Detect Session Hijacking using Wireshark

- Wireshark is a powerful network traffic analysis tool that captures and interactively browses traffic on a network. It utilizes WinPcap to capture packets, supporting various network types such as Ethernet, IEEE 802.11, PPP/HDLC, ATM, Bluetooth, USB, Token Ring, Frame Relay, and FDDI. Security professionals often use Wireshark to monitor and detect session hijacking attempts.

##### Steps

- On victim machine launch Wireshark.

- In Wireshark, double-click the primary network interface (e.g., Ethernet) to start capturing network traffic.

- Leave Wireshark running and proceed to launch a session hijacking attack on the victim machine using bettercap.

- On attacker machine set the network interface with `bettercap -iface eth0`.

- Enable bettercap modules: `net.probe on`, `net.recon on`, and `net.sniff on`.

- Observe bettercap sniffing network traffic on various machines in the network.

- Switch back to victim machine and observe the captured ARP packets in Wireshark.

- The high number of ARP requests indicates the attacker's system acting as a client for all IP addresses in the subnet.

---
