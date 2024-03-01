# Hacking Web Servers

## Introduction

- A web server is a critical component of web infrastructure, serving web pages globally via HTTP. Web server attacks, often following a preplanned methodology, aim to breach the server's security.

- Organizations view their web presence as an extension of themselves. Web servers, hosting web applications, are susceptible to attacks that can lead to security breaches. Attackers employ methods like DOS, DDoS, DNS hijacking, phishing, and more to exploit vulnerabilities.

## Objective

- To perform web server hacking tasks, including footprinting, information enumeration, and password cracking. 
- Identify vulnerabilities, misconfigurations, unpatched flaws, and improper authentication on the company's web server.

## Overview of Web Server

- Beyond hardware, a web server involves software applications. Clients initiate communication through HTTP requests, and servers respond with the requested information.

## Lab Tasks

#### 1. Footprint the web server
   - Information gathering using Ghost Eye
   - Web server reconnaissance using Skipfish
   - Footprint a web server using the httprecon tool
   - Footprint a web server using ID Serve
   - Footprint a web server using Netcat and Telnet
   - Enumerate Web Server Information using Nmap Scripting Engine (NSE)
   - Uniscan Web Server Fingerprinting in Parrot Security

#### 2. Perform a Web Server Attack
   - Crack FTP Credentials using a Dictionary Attack

---
### 1. Footprint the web server

- Footprinting the web server is a crucial initial step for ethical hackers or penetration testers. This process involves collecting comprehensive information about the target web server, aiding in the assessment of its security posture.

- Professional ethical hackers initiate the web server hacking process by gathering detailed information about the target. This step helps uncover potential security lapses, understand remote access capabilities, and assess ports and services. Tools like Whois.net and Whois Lookup, alongside web server fingerprinting, play a vital role in this phase.

- Web server footprinting enables the extraction of system-level data, including account details, OS, software versions, server names, and database schema details. Tools like Telnet, Netcraft, ID Serve, and httprecon are employed for this purpose. Each tool has unique features to extract valuable information, contributing to a comprehensive understanding of the target server.

#### Information Gathering using Ghost Eye

- [Ghost Eye](https://github.com/BullsEye0/ghost_eye), a Python 3 information-gathering tool, facilitates the collection of data about a target by performing various tasks such as Whois lookup, DNS lookup, port scanning, and more.

#### Perform Web Server Reconnaissance using Skipfish

- [Skipfish](https://www.kali.org/tools/skipfish/), an active web application security reconnaissance tool, conducts a thorough analysis of web servers. It creates an interactive sitemap through recursive crawls and dictionary-based probes, offering a foundation for professional web application security assessments.


- Perform Security Reconnaissance with Skipfish:
   ```bash
   skipfish -o test -S /usr/share/skipfish/dictionaries/complete.wl http://[IP Address of Windows Server]:8080
   ```
   - Customize output directory and dictionary file as needed.

- Observe scan statistics and tips provided by Skipfish.
- Let the scan run for 5 minutes then stop the scan.

- View Scan Results:
    - Double-click the 'test' folder.
    - Right-click on 'index.html' and open it with Firefox.
    - Review the overview of document and issue types found.
    - Expand nodes for detailed information.

- Analyze Vulnerabilities:
    - Click on an issue type to expand and analyze specific vulnerabilities.
    - Examine the provided HTTP trace for detailed information.

#### Footprint a Web Server using Netcat and Telnet

- We can use Netcat and Telnet as networking utilities to perform banner grabbing attacks for footprinting a web server. Netcat is a versatile tool for reading and writing data across network connections, while Telnet serves as a client-server protocol widely used for remote logins.

- **Netcat:** A versatile networking utility for reading and writing data across network connections using the TCP/IP protocol. It is commonly used for backend tasks, network debugging, and exploration.

- **Telnet:** A client-server network protocol that provides a user login session on the Internet or LANs. It is used for banner-grabbing attacks to determine the Server field in the HTTP response header.

- Use Netcat for Banner Grabbing:
   ```bash
   nc -vv www.moviescope.com 80
   GET / HTTP/1.0
   ```
- Netcat will display hosting information, including content type, last modified date, accept ranges, ETag, and server information.

- Use Telnet for Banner Grabbing:
   ```bash
   telnet www.moviescope.com 80
   GET / HTTP/1.0
   ```
- Telnet will connect to the domain and display information similar to the Netcat results.

#### Enumerate Web Server Information using Nmap Scripting Engine (NSE)

- Web applications on the Internet may have vulnerabilities, and attackers often need specific information about the server. Nmap, coupled with the Nmap Scripting Engine (NSE), can extract valuable details about the target web server. This includes directory enumeration, hostnames, HTTP traces, and Web Application Firewall (WAF) detection.

---

| Enumeration Technique                           | Command                                               | Description                                                           |
|--------------------------------------------------|-------------------------------------------------------|-----------------------------------------------------------------------|
| Enumerate Directories with Nmap                 | `nmap -sv --script=http-enum www.goodshopping.com`    | Use Nmap to enumerate directories used by web servers and applications. Provides details about open ports, services, and potential vulnerabilities. |
| Discover Hostnames                               | `nmap --script hostmap-bfk -script-args hostmapbfk.prefix=hostmap- www.goodshopping.com` | Discover hostnames associated with the target domain, providing insights into the network structure. |
| Perform HTTP Trace                               | `nmap -script http-trace -d www.goodshopping.com`      | The HTTP trace script checks for the TRACE method vulnerability, revealing if this method is enabled on the server. |
| Check for Web Application Firewall (WAF)         | `nmap -p80 --script http-waf-detect www.goodshopping.com` | Scan for a Web Application Firewall (WAF) by probing the target with malicious payloads and detecting changes in response codes. |

---

#### Uniscan Web Server Fingerprinting

- Uniscan is a powerful server fingerprinting tool that performs various checks on web servers, including static, dynamic, and stress tests. It also conducts automated searches on Bing and Google using provided IPs and compiles a comprehensive report.

---

| Web Application Testing Technique               | Command                                             | Description                                                           |
|--------------------------------------------------|-----------------------------------------------------|-----------------------------------------------------------------------|
| Search for Directories                            | `uniscan -u http://10.10.1.22:8080/CEH -q`          | Execute this command to scan and search for directories on the target web server. |
| Perform File Check                                | `uniscan -u http://10.10.1.22:8080/CEH -we`         | Enable file checks (robots.txt and sitemap.xml) to discover files and directories. |
| Dynamic Testing                                   | `uniscan -u http://10.10.1.22:8080/CEH -d`          | Initiate dynamic testing to gather more information about the web server. |

---

- Open the file '10.10.1.22.html' to view the comprehensive scan report.

- Analyze the Uniscan report for detailed information about the web server.

---
### 2. Perform a Web Server Attack

- After gathering essential information about the target web server, the ethical hacker or pen tester's next objective is to test the web server's security by launching attacks. The goal is to evaluate the web server's resilience against different attack techniques.

- Attackers may have diverse objectives, ranging from financial gain to sheer curiosity. Techniques employed include password guessing, dictionary attacks, brute force attacks, hybrid attacks, pre-computed hashes, rule-based attacks, distributed network attacks, and rainbow attacks. Automated tools like Brutus and THC-Hydra may also be utilized.

#### Crack FTP Credentials using a Dictionary Attack

- Here, we can perform a dictionary attack to crack FTP credentials on the target machine. This involves finding the open FTP port using Nmap and then using the THC Hydra tool to execute the dictionary attack.

- Nmap Scan:
   - Open a terminal window and run an Nmap scan to check if FTP port 21 is open.
     ```bash
     sudo su
     nmap -p 21 [IP Address of Windows 11]
     ```

- Verify FTP Server:
   - Check if an FTP server is hosted.
     ```bash
     ftp [IP Address of Windows 11]
     ```
   - Confirm the need for credentials, indicating an FTP server presence.

- Run the Hydra tool for the dictionary attack.
     ```bash
     hydra -L Usernames.txt -P Passwords.txt ftp://[IP Address of Victim]
     ```

- Hydra will output cracked usernames and passwords.
   - Attempt to log in to the FTP server using the obtained credentials.

- Remote FTP Access:
    - Upon successful logon remotely create a directory named "Hacked" on the Victim machine.
      ```bash
      mkdir Hacked
      ```

- If you want to verify, switch to the victim machine and navigate to C:\FTP (if it's windows) to view the "Hacked" directory.

---