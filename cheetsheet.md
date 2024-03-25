# Scanning Network

## Scanning network using Nmap


| Description                                       | Nmap Command                                         |
|---------------------------------------------------|------------------------------------------------------|
| Scanning network `Live Host` (ping sweep)        | `nmap -sP IP/CIDR`                                   |
| Scanning `Live Host` without port scan in same subnet (ARP scan) | `nmap -PR -sn IP/CIDR`                       |
| `Script + Version` running on target machine      | `nmap -sC -sV IP/CIDR`                               |
| `OS` of the target                                | `nmap -O IP`                                         |
| All `open ports` of the target                    | `nmap -p- IP/CIDR`                                   |
| `Specific Port` scan of the target                | `nmap -p <port-number> IP/CIDR`                      |
| Aggressive Scan                                   | `nmap -A IP/CIDR`                                    |
| Scanning using NSE scripts                        | `nmap --script <script-name> -p <port-number> IP/CIDR`|
| `Script + Version + Ports + OS Scan (Overall)`    | `nmap -sC -sV -p- -A -v -T4 IP/CIDR`                 |


---

# Service Enumeration

## Services

- FTP
- SNMP
- SMB
- RDP
- NetBIOS

### FTP (21)

- FTP (File Transfer Protocol) is a network protocol for transmitting files between computers over TCP/IP connections.

- Commands
	- `nmap -sC -p 21 <IP>`
	- connecting target ftp service
		- `ftp <IP>`
	- brute forcing ftp login
		- `hydra -L userlist.txt -P passwordlist.txt <IP> ftp`
	- Login to victim machine
		- `ftp <IP>`
			- `get <file>`

### SNMP (161)

- SNMP protocol is used to monitor and manage network devices like PCs, Routers, Switches, Servers, etc.
- Tools used to enumerate
	- `nmap`
	- `snmp-check`
	- `metasploit`
- What to enumerate?
	- default UDP port used by SNMP
	- identify the processes running on the target machine using nmap scrips
	- list valid community strings of the server using nmap scripts
	- list valid community strings of the server by using snmp_login metasploit module.
	- list all the interfaces of the machine. use appropriate nmap scripts
- Default UDP port
	- `nmap -sU <IP>`
	- Using snmp-check
		- `snmp-check <IP>`
- identify process (using [nse](https://nmap.org/nsedoc/scripts/))
	- `nmap -sU -p 161 --script=snmp-processes <target>`
- list valid community strings (using nse)
	- `nmap -sU --script snmp-brute <target> [--script-args snmp-brute.communitiesdb=<wordlist> ]`
- list valid community strings (metasploit)
	- search snmp
	- use auxiliary/scanner/snmp/snmp_login
	- show options - set RHOSTS
	- exploit
		- we will get 2 public strings (private and public)
- all the interfaces of the machine (using nse)
	- `nmap -sU -p 161 --script=snmp-interfaces <target>`

### SMB (445)

- Network file sharing protocol that allows applications on a computer to read and write to files.
- Request services from server programs in a computer network.
- what to hack? (enumerate)
	- network file shares
	- logged in users details
	- workgroups
	- security level information
	- domain and services

- network file shares
	- service enumeration
		- `nmap <IP>`
		- `nmap --script smb-enum-shares.nse -p445 <host>`
		- `sudo nmap -sU -sS --script smb-enum-shares.nse -p U:137,T:139 <host>`

	- connect to smb (gui method)
		- `smb://<IP>/<path-name>`
		- if you don't know the password use hydra to bruteforce

- logged in users details
	- `nmap --script smb-enum-users.nse -p445 <host>`
	- `sudo nmap -sU -sS --script smb-enum-users.nse -p U:137,T:139 <host>`

- workgroups
	- `nmap --script smb-enum-groups.nse -p445 <host>`
	- `sudo nmap -sU -sS --script smb-enum-groups.nse -p U:137,T:139 <host>`
	- `nmap -p 445 --script smb-enum-groups --script-args smbusername=<user>,smbpassword=<password> <IP>`

- security level information
	- `nmap -sC -sV -A -T4 -p 445 <IP>`

- domain and services
	- `nmap --script smb-enum-domains.nse -p445 <host>`
	- `sudo nmap -sU -sS --script smb-enum-domains.nse -p U:137,T:139 <host>`

	- `nmap --script smb-enum-services.nse -p445 <host>`
	- `nmap --script smb-enum-services.nse --script-args smbusername=<username>,smbpass=<password> -p445 <host>`
	- `nmap -p 445 --script smb-enum-services --script-args smbusername=<user>,smbpassword=<password> <IP>`

### RDP (3389)

- protocol used for remotely accessing the computers
- How to exploit?
	- check for running services on the target and confirm if RDP is running on any open port
	- check metasploit to confirm the services running is RDP
	- use hydra to brute force the login credentials
	- use and RDP tools to login into the victim's machine

- find port running RDP
	- `nmap <IP>`
- confirm port running RDP services
	- msfconsole
	- search rdp
	- use auxiliary/scanner/rdp/rdp_scanner
	- show options
	- set RHOSTS <IP>
	- set RPORT <suspect-port>
	- exploit
- bruteforce rdp login credentials
	- `hydra -L usernamelist.txt -P passwordlist.txt rdp://<IP> -s <rdp-port>`
- Using Xfreerdp to create rdp session
	- `xfreerdp /u:<username> /p:<password> /v:<target-ip>:<rdp-port>`

### NetBIOS Enumeration (137/138/139)

- `NBName: 137/UDP`
- `NBName: 137/TCP`
- `NBDatagram: 138/UDP`
- `NBSession: 139/TCP`
- Network Basic Input Output System
- Facilitates and allow computer to connect over the local network, access shared resources, such as files and printers, and to find each other.

- basic
	- `nmap -sP <IP>`
- using nse
	- `sudo nmap -sU --script nbstat.nse -p137 <host>`
		- we can know the "workgroup" of the ip address using netbios enumeration (e.g., ECLABS)

---

# Traffic Sniffing

## Wireshark > Pcap File Analysis

- Pcap (Packet Capture) File Structure
	- Filtering packets
	- Follow up Streams
	- Finding Files
	- Finding Comments
	- Search Strings
- DoS Attack
- DDoS Attack

- DoS attack (SYN - SYN/ACK)
	- filter - `tcp.flags.syn==1`
- Follow Streams (TCP/HTTP)
	- right click on packet - `Follow` -> `TCP/HTTP Stream`
	- HTTP stream (`tcp.stream eq 0`) (`red` [us i.e., client], `blue` [response from server])
	- TCP stream (`tcp.stream eq 0`)
	- You can use shortcut on bottom right corner (stream [0,1,2, etc.])
		- follow the stream you will find some useful info.

- To find text file - extracting files
	- `File` -> `Export Objects` -> `HTTP`
		- check "Content Type" and save the file

- Tip
	- select any packet and go to bottom left corner (select icon for getting file properties)
		- there will be "capture file comments"
		- also SHA hashes

- To find specific strings (to find specific regex)
	- `ctrl+f` (search e.g., ceh{ )

- DOS attack
	- To filter different IP that are performing DOS attack
		- Statistics -> Conversations - IPv4
			- filter by "Bytes" (max sized IP is answer)


---

# Stegnography

- "Stegnography is the practice of hiding secret information within a seemingly harmless carrier medium, such as an image or a sound file."
- the goal is to conceal the existence of the secret information, so that it can only be accessed by someone who knows where to look for it and how to decode it. it is like writing a secret message with invisibility, where only the intended recipient knows how to reveal the hidden message.

## Tools
- `SNOW` - For hiding and extracting hidden data from a text file
- `Openstego` - For hiding and extracting hidden data from an image file
- `Covert TCP` - For hiding data in TCP/IP packet headers

### SNOW
- Hiding/extracting data - text file
- To hide:
	- `SNOW.EXE -C -m "20/20 in CEH practical" -p "pa$$word" secret.txt hiddnesecrect.txt`
		- note: secret.txt (original file) & hiddensecret.txt (hiddne file)
- To extract:
	-`SNOW.EXE -C -p "pa$$word" hiddensecret.txt`

### Openstego
- Hiding/Extracting Data - image file

- To Hide:
	- In Openstego, `Data hiding` -> `Hide data`
		- choose message file & cover image and output stego file -> `hide data`
- To Extract data
	- `Data hiding` -> `Extract data`
		- choose input stego file & output folder for message file -> `extract data`

### Covert TCP

- Hiding/Extracting Data - TCP/IP Packet Headers

- Intro:
	- covert TCP help us to hide the data that is being sent over the network by manipulating the TCP/IP header.
	- we send the data in the left out spaces present in the header 1 Byte at a time.

- Commands
	- `cc -o covert_tcp covert_tcp.c`
	- for receiving/listening
		- `./covert_tcp -dest <Dest-IP> -source <Source-IP> -source_port 9999 -dest_port 8888 -server -file /path/to/file.txt`
	- for sending
		- `./covert_tcp -dest <Dest-IP> -source <Source-IP> -source_port 8888 -dest_paort 9999 -file /path/to/file.txt`


---

# Cryptography

## Intro

- "Cryptography is the practice of securing information so that only authorized individual can access it. It involves transforming information into an unreadable format, which can only be understood by those who have the key to unlock it."
- The goal is to protect sensitive information, such as personal data, financial transactions, and military secrets, from unauthorized access or theft.
- It is also used to ensure the authenicity and integrity of information, such as verifying the identity of a sender or ensuring that a message has not been tampered with during transmission.

## Tools

- Hashmyfiles: For calculating and comparing hashes of files
- Cryptool: For encryption/decryption of the hex data - by manipulating the key length
- BcTextEncoder: For encoding and decoding text in file (.hex)
- CryptoForge: For encrypting and decrypting the files
- VeraCrypt: For hiding and encrypting the disk partitions.

### HashMyFiles

- For comparing file hashes
- Used to calculate different hashes of the file to check if the file has been tampered

- Open HashMyFile and drag and drop the files (it will calculate MD5, SHA1, CRC32, SHA-256 hashes)

### CryptoForge

- For encrypting/decrypting files

- To encrypt:
    - right click on file -> `Encrypt` -> Enter `Passphrase`
- To decrypt:
    - right click on encrypted file -> `Decrypt` -> Enter `Passphrase`
    - it may contain hashes, to decrypt it go to [Hashes](https://hashes.com/en/decrypt/hash)

### BcTextEncoder

- For encoding data to hex format

- To encode:
    - in `Decoded plain text` window type the content you want to encode, then click on `Encode` button. then provide `Password`
    - it will create encoded text in `Encoded Text` window
        ```text
        ------BEGIN ENCODED MESSAGE-------
        Version: BCTextEncoder Utility v. 1.03.2.1

        < Enocded text>

        -------END ENCODED MESSAGE--------
        ```

- To decode:
    - in `Encoded text` window paste the encoded text, then click on `Decode` button. then provide the `Password`


### Cryptool

- For encrypting/decrypting files

- To decrypt:
    - Open CrypTool and right click on `File` -> `Open`, then choose `.hex` file
    - Click on `Analysis` -> `Symmetric Encryption (modern)` -> `RC4`
        - it will open `Brute-Force Analysis of RC4`, enter `Key length` (e.g., 16 bits), then hit `Start`
        - it will show the result in `Brute-Force Analysis - Results` window with 4 columns (`Entropy`, `Decryption: hex dump`, `Decryption`, `Key`)


### VeraCrypt

- For encrypting/decrypting hidden partition

- To encrypt:
    - Click on `Create Volume` -> `Create an encrypted file container` -> `Hidden VeraCrypt volume` -> `Normal mode`
        - `Volume Location` -> `Select File` -> `Outer volume` to be created (within this volume the `hidden volume` will be created later on)
        - Outer Volume
            - `Outer Volume Encryption Options` -> choose `Encryption Algorithm` and `Hash Algorithm` -> type `Outer Volume Size` -> `Outer Volume Password` -> `Outer Volume Format` (Randomness Collected From Mouse Movements)  -> `Format`
        - Hidden Volume
            - `Hidden Volume Encryption Options` -> choose `Encryption Algorithm` and `Hash Algorithm` -> type `Hidden Volume Size` (should be less than `Outer Volume Size`) -> `Hidden Volume Password`-> `Hidden Volume Format` (Randomness Collected From Mouse Movements)  -> `Format`


- To decrypt:
    - Click on free drive letter from the list of `Drive`
    - Click `Select Drive` or `Select File` to select a Veracrypt volume -> `Mount` (enter the password for the partition/file either `Outer` or `Hidden` volume password)
        - It will create a volume of type `Normal` (for Outer Volume) or `Hidden` (for Hidden Volume)
        - You can add any files to the partition (`Outer` or `Hidden`)
    - To Dismount
        - `Dismount` or `Dismount All`
#### Note:

- The process of unhiding the hidden volume is almost same as we unhide/mount the normal encryted volume. but, for unhiding the hidden volume we just need to enter the password of hidden volume

---

# Hacking Web & Android application

- Command Injection
- SQLi
- XSS

## Tools

- `SQLMap`: For finding SQL Injection Vulnerabilities
- `Wpscan`: Scanning and finding issues in wordpress websites
- `ADB`: For connecting android devices to PC and binay analysis
- `Burpsuite`: For analysing and manipulating the traffic

- First download and install DVWA

### SQLMap

```bash
sqlmap -r <get-request-file> --dbs
sqlmap -r <get-request-file> -D dvwa
sqlmap -r <get-request-file> -D dvwa --tables
sqlmap -r <get-request-file> -D dvwa --tables --colums
sqlmap -r <get-request-file> -D dvwa --dump
```

### WPScan

```bash
wpscan --url http://10.10.208.164/ --enumerate u
```

### ADB

```bash
adb devices
adb connect <IP>:5555
```
- first find out which ip is a android device while enumerating using nmap (can determine OS of each devices)
- or simply bruteforce among which ip is android device
	e.g.,
	- `adb connect 1.1.1.1:5555`
	- `adb connect 1.1.1.2:5555`
	- `adb connect 1.1.1.3:5555` etc.

```bash
adb shell
```
	- ls
	- whoami (shell)
	- cd sdcard/
	- cat secret.txt

---

# New Topics

- IoT
- RATs
- Malware Analysis
- Vulnerability Analysis
- Privilege Escalation

## Updated topics

- packet analysis
- mobile devices
- wireless networks

## What one must be aware of?

- some servers are very slow
- provided wordlist doesn't work for some questions

---

# Privilage Escalation

- `ssh user-name@<IP> -p <PORT>`
	- how to know the user and password?
		- you will be provided with checklist/wordlist
		- from previous question you have identified credentils
		- bruteforce credentials using hydra

- To escalate
	- always check previlage level
		- `sudo -l`
		- `sudo -u user2 /bin/bash`

- Thought process
	- what are the ways a user can escalte to root user?
		- we can use secure keys to login as a root user
		- note if we don't have the access to root directory, we can switch to another user by horizontal privilage escaltion, then we can try to esclate to root user.
		- if we don't have the permission to read any file, go to root home directory (/root), `ls -la`, find .ssh directory
		- in .ssh directory we have two major components (one is rsa key, another one authorized key) through which we can login as a root user
		- .ssh -> `authorized_keys`, `id_rsa` and `id_rsa.pub`
		- when creating a key there are two things that are generated (private and public key)
		- common method is to use `id_rsa` to esclate to root user

- copy the `id_rsa` of root user to your local machine
- first thing first, update the permission of this specific file - `chmod 600 id_rsa`
	- `ssh root@<IP> -p <PORT> -i id_rsa` (don't forget to specify the port, sometimes you will get permission error, if you didn't specify the proper port number)

- another thing to remember
	- if we have the authority to change 'authorized_keys' of a root user as a normal user (not root user)
	- if you have the permission, first create new public and private ssh key in your local machine, and copy 'authorized_key' to the victim machine, through that you can successfully login.
	- `ssh-keygen -f key`
		- you will get `key` and `key.pub`
		- copy "public key" to /root/.ssh/
		- now you can ssh into root user with your own private key
	- `ssh root@<IP> -p <PORT> -i key`

---

# Privalage Escalation - Advanced

## Access rights flags

- the linux and unix access rights flags `setuid` (set user identity) and `setgid` (set group identity) allow users to run an executable with the file system permissions of the executable's owner or group respectively and to change behaviour in directories.
- the flags `setuid` and `setgid` are needed for task that require different privileges than what the user is normally granted.

## File Modes

- The `setuid` and `setgid` bits are normally represented as the values:
	- `4` for `setuid`
	- `2` for `setgid`
- In the high-order octal digit of the file mode.
- For e.g., 6711 has both the setuid and setgid bits ( 4 + 2 = 6)
	- 6: Access rights flags
	- 7: owner permission
	- 1: group permission
	- 1: others permission
- Note: `Read (4)` + `Write (2)` + `Execute (1)`

---

- To display file or file system status
	`stat -c "%a %A  %U %G %F" *`

- To check user is in which group
	`groups <user-name>`

- Have some thought process.
	- sometimes one file with root privilages can have dipendencies on other files (so we can modify that other file which we have access)
	- for e.g., lets consider two file (`greetings` and `welcome`)
		- lets see if there is any strings that is related to other file
			strings welcome (if it contains the string related to greeting, we can modify it.)
		- sometimes we don't have the permission to modify the other file. but we could have the permission to delete it. then recreate that file.
			cp /bin/bash greetings
		- now execute `welcome` script, you will get the root access through the shell.

- here we vertically escalated by using wrong permission allocated to files and directories

---

- lets say you already got the credentials directly or you got some credentials which are valid in your previous questions. from those credentials you logged into the server (lets say its a shared server)
- consider it as scenario like you have a shared server, say you are an employee where everyone can share there files are host their website.
- we know that its a web server, if we want to host something, we generally host it on `/var/www/html` directory
- lets see if we have any database contents among those files in that directory
	- `grep -nr "db_users"`
- it will list path to possible files which may contains credentials.through which you can escalate the privilage.

---

#### Tips: 

- use `LinEnum` (https://github.com/rebootuser/LinEnum) or use '`LinPEASE`' (https://github.com/carlospolop/PEASS-ng)

---

# Malware threat (RAT)

## Scenario

- A server access code is hidden in a windows machine in the <IP>/24 subnet.
- An RAT has been installed in the machine for remote administration purposes.
- Task is to retrive an secret file/code from the target machine and enter the string present in the file as an answer.

## Approach

- which machine to target?
	- target windows OS
	- there are n number of tools are used to make a connection, the RAT server that is installed on the remote machine is dependend on the specific RAT generated tool

- what if it says not active connection?
	- there could be 2 reasons
		- you are choosing wrong target machine (i.e., window machine you chose is the wrong one) or the port you connected is the wrong one.
		- whether server installed on the remote machine for remote administration purpose is of different tool and you are using the different tool (e.g., the server being installed is generated by ProRAT and you are using njRAT to connect over it.)
			- these tools behaves by generating a server using this tool and sending it to the victim machine, then the victime will install it over the machine, after that you will be able to make the connection. where you can see that there is a direct dependancy on the tool.

	- This shows that you need to simply bruteforce it by making the right combination, this question will definately take good amount of time

## Tool List (RAT)

- `njRAT`
- `MoSucker`
- `ProRAT`
- `Theef`
- `HTTP RAT`

- how you can use this tool to connect to the remote machine, find the file and get the flag.
	- process is same for all the tools, only GUI is different.


### ProRAT

- To create
	- `Create` -> `Create ProRat Server`

- To connect to the victim machine
	- Type `IP` and `Port` of victim machine -> `Connect` (optional: provide `Password`)
		- If the password is correct it will display `Password correct, Entrance Complete`
	- Click on `Search Files` -> Provide `Loction` and `Searching for` (e.g., `*.txt`) -> `Find`
	- Click on `File Manager` -> `Refresh` -> click on file you want to download -> right click and `Download`
		- it will show `Transfer is complete` (check in your download folder)

---

#### Note:

- Connection to the victim machine is totally depend on the `Server` that is generated from the tool.
    - In `njRAT` - you don't need to provide the IP address of the victime machine (works on a concept that is similar to reverse shell - Here attackeer machine is listening and Victim is connecting)
        - we will get the connection automatically (even if they shutdown and restart the machine)
    - `Other tools (HTTP RAT, ProRAT, Theef)` - You need to provide the `IP` address and `Port` number of the victim machine (works on a concept that is similar to bind shell - Here Victim machine is listening and we are connecting)

- Try to connect with machines having OS as Windows. After enumerating those systems try to check that on which port some other services are running apart from standard service configuration

---
