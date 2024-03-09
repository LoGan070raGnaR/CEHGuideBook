# Enumeration

## Introuduction

Enumeration is the process of extracting usernames, machine names, network resources, shares, and services from a system or network.

## Objective

The objective is to extract information about the target organization, including:
- Machine names, OSes, services, and ports
- Network resources
- Usernames and user groups
- Lists of shares on individual hosts
- Policies and passwords
- Routing tables
- Audit and service settings
- SNMP and FQDN details

## Overview of Enumeration

Enumeration creates an active connection with the system and performs directed queries to gain more information about the target. It involves extracting lists of computers, usernames, user groups, ports, OSes, machine names, network resources, and services using various techniques in an intranet environment.

---

## Tools

#### 1. NetBios Enumeration
   - Using Windows command-line utilities
   - Using NetBios enumerator
   - Using NSE scripts

#### 2. SNMP Enumeration
   - Using snmp-check
   - Using SoftPerfect Network Scanner
   - Using SnmpWalk
   - Using Nmap

#### 3. LDAP Enumeration
   - Using Active Directory Explorer (AD Explorer)
   - Using Python and Nmap
   - Using Idapsearch

#### 4. NFS Enumeration
   - Using RPCScan and SuperEnum

#### 5. DNS Enumeration
   - Using Zone Transfer
   - Using DNSSEC Zone Walking
   - Using Nmap

#### 6. SMTP Enumeration
   - Using Nmap

#### 7. RPC, SMB, and FTP Enumeration
   - Using NetScanTools Pro
   - Using Nmap

#### 8. Enumeration using Various Enumeration Tools
   - Enumerate Information using Global Network Inventory
   - Enumerate Network Resources using Advanced IP Scanner
   - Enumerate Information from Windows and Samba Hosts using Enum4linux

---

### 1. NetBIOS Enumeration

- **NetBIOS enumeration** is a process of obtaining sensitive information about the target such as a list of computers belonging to a target domain, network shares, policies, etc.

- As a professional ethical hacker or penetration tester, your first step in the enumeration of a Windows system is to exploit the NetBIOS API. NetBIOS enumeration allows you to collect information about the target such as a list of computers that belong to a target domain, shares on individual hosts in the target network, policies, passwords, etc. This data can be used to probe the machines further for detailed information about the network and host resources.

**Overview of NetBIOS Enumeration:**

- NetBIOS stands for Network Basic Input Output System. Windows uses NetBIOS for file and printer sharing. A NetBIOS name is a unique computer name assigned to Windows systems, comprising a 16-character ASCII string that identifies the network device over TCP/IP. The first 15 characters are used for the device name, and the 16th is reserved for the service or name record type.

- The NetBIOS service is easily targeted, as it is simple to exploit and runs on Windows systems even when not in use. NetBIOS enumeration allows attackers to read or write to a remote computer system (depending on the availability of shares) or launch a denial of service (DOS) attack.

---

#### NetBIOS Enumeration using Windows CommandLine Utilities

- **Nbtstat** helps in troubleshooting NETBIOS name resolution problems. The `nbtstat` command removes and corrects preloaded entries using several case-sensitive switches. `Nbtstat` can be used to enumerate information such as NetBIOS over TCP/IP (NetBT) protocol statistics, NetBIOS name tables for both the local and remote computers, and the NetBIOS name cache.

- `net use` connects a computer to, or disconnects it from, a shared resource. It also displays information about computer connections.

- Here, we will use the `nbtstat` and `net use` Windows command-line utilities to perform NetBIOS enumeration on the target network.

##### Steps

- Type `nbtstat -a [IP address of the remote machine]` (in this example, the target IP address is 1.1.1.11) and press Enter.

  Note: In this command, `-a` displays the NetBIOS name table of a remote computer.

- The result appears, displaying the NetBIOS name table of a remote computer.

- In the same Command Prompt window, type `nbtstat -c` and press Enter.

  Note: In this command, `-c` lists the contents of the NetBIOS name cache of the remote computer.

- The result appears, displaying the contents of the NetBIOS name cache, the table of NetBIOS names, and their resolved IP addresses.

- Now, type `net use` and press Enter. The output displays information about the target such as connection status, shared folder/drive, and network information.

- Using this information, attackers can read or write to a remote computer system, depending on the availability of shares, or even launch a DOS attack.

---

#### NetBIOS Enumeration using an NSE Script

- NSE (Nmap Scripting Engine) allows for the automation of various networking tasks. we can utilize the nbstat NSE script to discover NetBIOS shares on the network, extracting information such as NetBIOS names and MAC addresses.

3. **Run Nmap Script for NetBIOS Enumeration.**
   - Execute the command: `nmap -sV -v --script nbstat.nse [Target IP Address]` (e.g., `nmap -sV -v --script nbstat.nse 10.10.1.22`).
        - `-sV` for service version detection and `--script nbstat.nse` for NetBIOS enumeration.
   - View scan results displaying open ports and services, along with NetBIOS details.

4. **Run UDP Scan for NetBIOS Enumeration.**
   - Execute the command: `nmap -sU -p 137 --script nbstat.nse [Target IP Address]` (e.g., `nmap -sU -p 137 --script nbstat.nse 10.10.1.22`).
   - Check scan results for NetBIOS details on the target system.

- Other tools that can be used for NetBIOS enumeration such as Global Network Inventory, Advanced IP Scanner, Hyena, and Nsauditor Network Security Auditor.

---
### 2. SNMP Enumeration

- As a professional ethical hacker or penetration tester, the next step involves SNMP enumeration to extract critical information about network resources, including hosts, routers, devices, and shares. Additionally, network-specific details such as ARP tables, routing tables, device-specific information, and traffic statistics are targeted. This information becomes instrumental in conducting further vulnerability assessments, formulating a hacking strategy, and executing targeted attacks.

**Overview of SNMP Enumeration**

- **SNMP (Simple Network Management Protocol)** is an application layer protocol that operates on UDP (User Datagram Protocol) and is responsible for maintaining and managing routers, hubs, and switches on an IP network. SNMP agents are deployed on networking devices within Windows and UNIX networks. SNMP enumeration utilizes SNMP to generate a comprehensive list of user accounts and devices on a target computer. The SNMP communication involves two key software components: the SNMP agent positioned on the networking device, and the SNMP management station responsible for communication with the agent.

---

#### SNMP Enumeration using snmp-check

- `snmp-check` is a tool that enumerates SNMP devices, displaying the output in a simple and reader-friendly format. The default community used is "public."

Here, we will use the `snmp-check` tool to perform SNMP enumeration on the target IP address.

- **Note:** Before starting SNMP enumeration, we must first discover whether the SNMP port is open. SNMP uses port 161 by default; to check whether this port is opened, we will first run Nmap port scan.

##### Steps

- Type `nmap -sU -p 161 [Target IP address]`

   - Note: `-sU` performs a UDP scan, and `-p` specifies the port to be scanned.

- The results appear, displaying that port 161 is open and being used by SNMP.

- We have established that the SNMP service is running on the target machine. Now, we shall exploit it to obtain information about the target system.

- Type `snmp-check [Target IP Address]`

- The result will appear. It reveals that the extracted SNMP port 161 is being used by the default "public" community string.

   - Note: If the target machine does not have a valid account, no output will be displayed.

- The `snmp-check` command enumerates the target machine, listing sensitive information such as System information and User accounts.

- Scroll down to view detailed information regarding the target network under the following sections: Network information, Network interfaces, Network IP and Routing information, and TCP connections and listening ports.

- Similarly, scrolling down reveals further sensitive information on Processes, Storage information, File system information, Device information, Share, etc.

- Attackers can further use this information to discover vulnerabilities in the target machine and further exploit them to launch attacks.

---

You can also use other SNMP enumeration tools such as Network Performance Monitor ([SolarWinds](https://www.solarwinds.com)), OpUtils ([ManageEngine](https://www.manageengine.com)), PRTG Network Monitor ([Paessler](https://www.paessler.com)), and Engineer's Toolset ([SolarWinds](https://www.solarwinds.com)) to perform SNMP enumeration on the target network.

---

#### SNMP Enumeration using SnmpWalk

- SnmpWalk is a command-line tool that scans numerous SNMP nodes instantly and identifies a set of variables that are available for accessing the target network. It is issued to the root node so that the information from all the sub-nodes such as routers and switches can be fetched.

##### Steps

- Type `snmpwalk -v1 -c public [target IP]` and press Enter (here, the target IP address is 10.10.1.22).
   - Note: `-v`: specifies the SNMP version number (1 or 2c or 3) and `-c`: sets a community string.

- The result displays all the OIDs, variables, and other associated information.

   ```bash
   snmpwalk -v1 -c public 10.10.1.22
   ```

   Sample Output:
   ```
   Created directory: /var/lib/snmp/cert Indexes
   iso.3.6.1.2.1.1.1.0 STRING: "Hardware: Family 23 Model 49 Stepping 0 AT/AT COMPATIBLE - Software: Windows Version 6.3 (Build 20348 Multiprocessor Free)"
   iso.3.6.1.2.1.1.2.0 OID: iso.3.6.1.4.1.311.1.1.3.1.3
   iso.3.6.1.2.1.1.3.0 Timeticks: (595603)
   iso.3.6.1.2.1.1.4.0
   ...
   ```

- Type `snmpwalk -v2c -c public [Target IP Address]` and press Enter to perform SNMPv2 enumeration on the target machine.

   ```bash
   snmpwalk -v2c -c public 10.10.1.22
   ```

   Sample Output:
   ```
   iso.3.6.1.2.1.1.1.0 STRING: "Hardware: Intel64 Family 6 Model 85 Stepping 7 AT/AT COMPATIBLE - Software: Windows Version 6.3 (Build 26348 Multiprocessor Free)"
   iso.3.6.1.2.1.1.2.0 OID: iso.3.6.1.4.1.311.1.1.3.1.3
   iso.3.6.1.2.1.1.3.0 Timeticks: (2890168650) 334 days, 12:14:0.50
   iso.3.6.1.2.1.1.4.0
   ...
   ```

- The result displays data transmitted from the SNMP agent to the SNMP server, including information on the server, user credentials, and other parameters.

---

#### SNMP Enumeration using Nmap

- The Nmap SNMP script is used against an SNMP remote server to retrieve information related to the hosted SNMP services. Here, we will use various Nmap scripts to perform SNMP enumeration on the target system.

- In the terminal, type `nmap -sU -p 161 --script=snmp-sysdescr [target IP Address]`
   - Note: `-sU`: specifies a UDP scan, `-p`: specifies the port to be scanned, and `--script`: is an argument used to execute a given script (here, snmp-sysdescr).

   ```bash
   nmap -sU -p 161 --script=snmp-sysdescr 10.10.1.22
   ```

   Output:
   ```
   # Displaying information regarding SNMP server type and operating system details
   ```

- Type `nmap -sU -p 161 --script=snmp-processes [target IP Address]`

   ```bash
   nmap -sU -p 161 --script=snmp-processes 10.10.1.22
   ```

   Output:
   ```
   # Displaying a list of all the running SNMP processes along with the associated ports
   ```

- Type `nmap -sU -p 161 --script=snmp-win32-software [target IP Address]`

   ```bash
   nmap -sU -p 161 --script=snmp-win32-software 10.10.1.22
   ```

   Output:
   ```
   # Displaying a list of all the applications running on the target machine
   ```

- Type `nmap -sU -p 161 --script=snmp-interfaces [target IP Address]`

   ```bash
   nmap -sU -p 161 --script=snmp-interfaces 10.10.1.22
   ```

   Output:
   ```
   # Displaying information about the Operating system, network interfaces, and applications
   ```

---

### 3. LDAP Enumeration

- LDAP (Lightweight Directory Access Protocol) enumeration is a crucial step for ethical hackers or penetration testers to gather information from directory services, particularly Active Directory. Directory services offer a logically structured view of a network, akin to an organizational chart, encompassing details from printers to email directories.

**LDAP Enumeration in a Nutshell**

LDAP operates as an Internet protocol facilitating access to distributed directory services over a network. It leverages DNS (Domain Name System) for swift lookups and query resolution. Clients initiate an LDAP session by connecting to a Directory System Agent (DSA) on TCP port 389. The client sends operation requests to the DSA, which responds accordingly. Basic Encoding Rules (BER) are utilized for information exchange between the client and server.

LDAP enumeration allows for the retrieval of sensitive information like usernames, addresses, departmental details, and server names.

---

LDAP enumeration tools like [Softerra LDAP Administrator](https://www.ldapadministrator.com), [LDAP Admin Tool](https://www.ldapsoft.com), [LDAP Account Manager](https://www.ldap-account-manager.org), and [LDAP Search](https://securityxploded.com) can also be for LDAP enumeration.

---

#### LDAP Enumeration using Python and Nmap

- The goal is to obtain details about the LDAP server and connections, including potential username enumeration through a brute-force attack.

##### Steps

- Perform Nmap Scan:
   - Execute `nmap -sU -p 389 [Target IP address]` to perform a UDP scan on port 389.
   - Confirm that port 389 is open and used by LDAP.

- Username Enumeration with Nmap:
   - Use Nmap and its NSE script to attempt username enumeration.
   - Execute `nmap -p 389 --script ldap-brute --script-args ldap.base="'cn=users,dc=CEH,dc=com'" [Target IP Address]`.
   - Nmap displays usernames found during the brute-force attempt.

- Manual LDAP Enumeration with Python:
   - Open a Python3 shell in the Terminal.
   - Import the `ldap3` module (`import ldap3`).

    - Connect to LDAP Server:
        - Establish a connection to the target LDAP server using Python commands.

    - Retrieve Naming Context:
        - Type `server.info` to gather information such as naming context or domain name.

    - Perform LDAP Queries:
        - Use Python commands to make queries to the LDAP server.
        - Retrieve directory objects and user password information.

    - Extract LDAP Information:
       - Utilize the obtained information for potential web application attacks or gaining access to the target machine.


---

#### LDAP Enumeration using Idapsearch

- Idapsearch, is a shell-accessible interface to the Idap_search_ext(3) library call, to perform LDAP enumeration on the target system. Idapsearch opens a connection to an LDAP server, binds the connection, and performs searches based on specified parameters. This tool is valuable for extracting information about naming contexts, domain details, and directory objects.

##### Steps


- Perform LDAP Enumeration with Idapsearch:
   - Execute `Idapsearch -h [Target IP Address] -x -s base namingcontexts` to gather details related to naming contexts.
     - `-x`: Specifies simple authentication
     - `-h`: Specifies the host
     - `-s`: Specifies the scope

- Retrieve Information about Primary Domain:
   - Execute `Idapsearch -h [Target IP Address] -x -b "DC=CEH,DC=com"` to obtain more information about the primary domain.
     - `-b`: Specifies the base DN for search

- Retrieve Information about All Objects:
   - Execute `Idapsearch -x -h [Target IP Address] -b "DC=CEH,DC=com" "objectclass=*"` to retrieve information related to all objects in the directory tree.

- Understand Idapsearch Usage:
   - Recognize that Idapsearch is a tool used for enumerating AD users, enabling attackers to establish connections with LDAP servers and conduct searches with specific filters.

---

### 4. NFS Enumeration

- NFS enumeration is a crucial step for ethical hackers and penetration testers to extract information about exported directories and shared data on target systems. This process involves identifying NFS (Network File System) configurations, understanding connected clients, and obtaining details about shared resources.

**NFS Enumeration Overview**

- NFS (Network File System) is a file system that facilitates remote access, viewing, storage, and updating of files on a server. This protocol allows client computers to interact with remote data as seamlessly as with local files.

- Use RPCScan and SuperEnum for efficient NFS enumeration.

---
#### NFS Enumeration using RPCScan and SuperEnum

- NFS enumeration using RPCScan and SuperEnum involves scanning for misconfigurations in NFS (Network File System) services, listing RPC services, mountpoints, and accessible directories.

## Prerequisites

Before starting this task, ensure that the NFS service is enabled on the target machine (Windows Server 2019).

## Steps

- Initiate NFS Enumeration:
   - Open a Terminal window and run `nmap -p 2049 [Target IP Address]` to check NFS port (2049) status.

- Use SuperEnum:
   - Navigate to SuperEnum folder using `cd SuperEnum`.
   - Create a target file with the command `echo "10.10.1.19" >> Target.txt`.
   - Run SuperEnum with `./superenum`, specifying the IP list file.
   - After the scan completes, review the results in the Terminal.
   - Observe open ports, services, and the status of NFS (port 2049).

- RPCScan Enumeration:
   - Run RPCScan with `python3 rpc-scan.py [Target IP Address] --rpc`.
   - Examine the results to identify open ports and NFS service status.

---

# Perform DNS Enumeration

## Overview

DNS Enumeration is a crucial step for ethical hackers and penetration testers to gather detailed information about a target domain. This process involves locating and listing all possible DNS records, providing insights into DNS server names, hostnames, machine names, usernames, IP addresses, and aliases within the target domain.

## Lab Objectives

- Perform DNS enumeration using zone transfer.
- Perform DNS enumeration using DNSSEC zone walking.
- Perform DNS enumeration using Nmap.

## Lab Environment

To execute this lab, the following components are required:

- Windows 11 virtual machine
- Parrot Security virtual machine
- Web browsers with an Internet connection
- Administrator privileges to run the tools

## DNS Enumeration Techniques

DNS enumeration employs various techniques to extract information about DNS servers and network infrastructure. The key techniques include:

1. **Zone Transfer:**
   - Extracts a complete zone file from a DNS server, revealing detailed information about the domain.

2. **DNSSEC Zone Walking:**
   - Utilizes DNSSEC (DNS Security Extensions) vulnerabilities to navigate through DNS zones, disclosing valuable information.

3. **Nmap DNS Enumeration:**
   - Leverages Nmap tool to perform DNS enumeration, providing a comprehensive overview of DNS records.

## Conclusion

The DNS Enumeration process provides valuable insights into the target domain's infrastructure. Document the acquired information for analysis and further penetration testing.

---

### 5. DNS Enumeration

#### DNS Enumeration using Zone Transfer

- DNS zone transfer involves transferring a copy of the DNS zone file from the primary DNS server to a secondary DNS server. This process can reveal crucial information about the domain, including DNS server names, hostnames, machine names, and usernames. We can perform DNS enumeration through zone transfer using the `dig` utility on Linux-based systems and `nslookup` on Windows-based systems.

##### Steps

**Linux DNS Servers Enumeration:**

- Perform DNS Query:
   - Use `dig` to query DNS name servers:
     ```bash
     dig ns [Target Domain]
     ```
   - Retrieve information about DNS name servers in the ANSWER SECTION.

- Attempt Zone Transfer:
   - Execute zone transfer command:
     ```bash
     dig @[NameServer] [Target Domain] axfr
     ```
   - Verify if zone transfer is allowed or not.

**Windows DNS Servers Enumeration:**

- Enter nslookup:
   - Launch Command Prompt and Enter `nslookup` in interactive mode.

- Set Query Type:
   - Set the query type to SOA record:
     ```bash
     set querytype=soa
     ```

- Resolve Target Domain:
   - Resolve target domain information:
     ```bash
     [Target Domain]
     ```

- Attempt Zone Transfer:
   - In nslookup interactive mode, attempt zone transfer:
     ```bash
     ls -d [Name Server]
     ```

- Review Results:
   - Analyze the results to check if the DNS server allows zone transfers.

---

#### DNS Enumeration using DNSSEC Zone Walking

DNSSEC zone walking is a DNS enumeration technique used to obtain internal records of the target DNS server when the DNS zone is not properly configured. This information assists in building a host network map. Various DNSSEC zone walking tools can be utilized for this purpose. Here, we will use the DNSRecon tool.

##### Steps

- Make the script executable:
   ```bash
   chmod +x ./dnsrecon.py
   ```

- View available options:
   ```bash
   ./dnsrecon.py -h
   ```

- Perform DNS enumeration through DNSSEC zone walking:
   ```bash
   ./dnsrecon.py -d [Target domain] -z
   ```
   - For example, if the target domain is [github.com](https://github.com).

- Review the result:
   - The result will display enumerated DNS records for the target domain, including SOA, NS, MX, CNAME, A, TXT, and more.

- Other tools like [LDNS](https://www.nlnetlabs.nl), [nsec3map](https://github.com), [nsec3walker](https://dnscurve.org), and [DNSwalk](https://github.com) can also be used for DNS enumeration on the target domain.

---
#### Perform DNS Enumeration using Nmap

- Nmap can be utilized to scan domains, extracting subdomains, records, IP addresses, and other valuable information from the target host.

##### Steps


- Run the command below to perform DNS service discovery on the target domain (replace [Target Domain] with the actual domain, e.g., github.com):
    ```bash
    nmap --script=broadcast-dns-service-discovery [Target Domain]
    ```

   - The result will display available DNS services on the target host along with associated ports.

- Run the following command to perform DNS brute-force enumeration:
    ```bash
    nmap -T4 -p 53 --script dns-brute [Target Domain]
    ```

   - The result will show a list of subdomains associated with their IP addresses.

- Run the command below to enumerate common service (SRV) records:
    ```bash
    nmap --script dns-srv-enum --script-args "dns-srv-enum.domain='[Target Domain]'"
    ```

   - The result will display various common SRV records for the specified domain.

- Utilize the acquired information for potential web application attacks like injection, brute-force, or DOS attacks.

---
### 6. SMTP Enumeration

- SMTP enumeration is crucial for identifying valid user accounts on an SMTP server. This process helps ethical hackers and penetration testers gather a list of valid users, delivery addresses, and message recipients associated with an SMTP server.

**Overview of SMTP Enumeration**

The Simple Mail Transfer Protocol (SMTP) serves as an internet standard communication protocol for electronic mail transmission. SMTP, often paired with POP3 and IMAP, facilitates the storage and retrieval of messages in a server mailbox. SMTP utilizes Mail Exchange (MX) servers to route mail via DNS and commonly operates on TCP ports 25, 2525, or 587.

---
#### SMTP Enumeration using Nmap

- The Nmap scripting engine can be used to enumerate the SMTP service running on the target system, obtaining information about all user accounts on the SMTP server.

##### Steps

- Run the Nmap script for SMTP user enumeration:

   ```bash
   nmap -p 25 --script=smtp-enum-users [Target IP Address]
   ```

   - The result displays a list of possible mail users on the target machine.

- Run the Nmap script for identifying open SMTP relays:

   ```bash
   nmap -p 25 --script=smtp-open-relay [Target IP Address]
   ```

   - The result displays a list of open SMTP relays on the target machine.

- Run the Nmap script for SMTP commands:

   ```bash
   nmap -p 25 --script=smtp-commands [Target IP Address]
   ```

   - A list of SMTP commands in the Nmap directory appears for further exploration.

- Use this information to perform password spraying attacks for unauthorized access.

---
### 3. RPC, SMB, and FTP Enumeration

Various techniques can be employed by ethical hackers and penetration testers to facilitate information-gathering during security assessments.

**Overview of Other Enumeration Techniques:**

- **RPC Enumeration:** Identifying RPC endpoints helps in pinpointing vulnerable services on associated ports.

- **SMB Enumeration:** This technique involves banner grabbing, providing information such as OS details and versions of running services.

- **FTP Enumeration:** Extracting information about port 21 and any active FTP services enables the discovery of potential attack vectors, including FTP bounce, FTP brute force, and packet sniffing.

---

#### RPC, SMB, and FTP Enumeration using Nmap

- Conduct an initial Nmap scan for port 21 on the target (e.g., `nmap -p 21 [Target IP Address]`).

- Perform an aggressive scan on all ports (e.g., `nmap -T4 -A [Target IP Address]`).

   - Note the identified services, especially FTP on port 21.

- Repeat Nmap scans for ports 111 and 2049 for RPC/NFS enumeration.

   - For SMB enumeration, scan port 445 (e.g., `nmap -p 445 -A [Target IP Address]`).

      - Document the discovered services and versions.

   - For FTP enumeration, scan port 21 (e.g., `nmap -p 21 -A [Target IP Address]`).

      - Document the FTP-related information.

- Analyze the scan results to identify potential vulnerabilities.

---
### 8. Enumeration using Various Enumeration Tools

- The details obtained in the previous steps might not reveal all potential vulnerabilities in the target network. There may be more information available that could help attackers identify loopholes to exploit.

- Enumeration tools collect detailed information about target systems for exploitation. This includes data on NetBIOS services, usernames and domain names, shared folders, network details (ARP tables, routing tables, traffic, etc.), user accounts, directory services, and more.

---
#### Enumerate Information from Windows and Samba Hosts using Enum4linux

- Enum4linux is a powerful tool designed for enumerating information from both Windows and Samba systems. It provides insights into share enumeration, password policies, remote OS identification, workgroup/domain status, user listings, group memberships, and more.

- View Enum4Linux options with `enum4linux -h`.

---

| Enumeration Method | Command | Description |
|------|---------|-------------|
| NetBIOS Enumeration | `enum4linux -u martin -p apple -n [Target IP Address]` | Enumerate NetBIOS information. |
| User List Enumeration | `enum4linux -u martin -p apple -U [Target IP Address]` | Enumerate user list. |
| OS Information Enumeration | `enum4linux -u martin -p apple -o [Target IP Address]` | Enumerate OS information. |
| Password Policy Enumeration | `enum4linux -u martin -p apple -P [Target IP Address]` | Enumerate password policy. |
| Group Policy Enumeration | `enum4linux -u martin -p apple -G [Target IP Address]` | Enumerate group policy. |
| Share Policy Enumeration | `enum4linux -u martin -p apple -S [Target IP Address]` | Enumerate share policy. |

---

- The tool displays results for each enumeration, including NetBIOS information, user lists, OS details, password policies, group policies, and shared folders.

- This information can be exploited for unauthorized access to user accounts, groups, and confidential data in shared drives.


---