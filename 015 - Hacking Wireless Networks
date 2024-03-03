# Hacking Wireless Networks

## Introduction

- A wireless network employs radio-frequency technology for unbounded data communication. Wi-Fi facilitates cable-free device access within range of an access point, presenting security challenges such as access control, integrity, confidentiality, availability, and authentication attacks.

- Wireless local area networks (WLANs), following the IEEE 802.11 standard, revolutionize data communication. Despite the convenience, security issues, absent in wired networks, arise. Airborne data packets, particularly Wired Equivalent Privacy (WEP) weaknesses, pose risks.

## Lab Objective

- Discovering Wi-Fi networks
- Capturing and analyzing wireless traffic
- Cracking WEP, WPA, and WPA2 Wi-Fi networks

## Overview of Wireless Networking

Wireless communication at the physical layer leads to fundamental changes. Wireless networks include extensions to wired networks, multiple access points, LAN-to-LAN networks, and 3G/4G hotspots.

## Tasks

#### 1. Footprint a Wireless Network
    - Find Wi-Fi networks using NetSurveyor

#### 2. Perform Wireless Traffic Analysis
    - Find Wi-Fi networks and sniff packets using wash and Wireshark

#### 3. Perform Wireless Attacks
    - Find hidden SSIDs using Aircrack-ng
    - Crack WEP network using Wifiphisher
    - Crack WEP network using Aircrack-ng
    - Crack a WPA Network using Fern Wifi Cracker
    - Crack a WPA2 Network using Aircrack-ng
    - Create a Rogue Access Point to Capture Data Packets

---
### 1. Footprint a Wireless Network

- Footprinting a wireless network involves actively or passively discovering and identifying the wireless network.

- As an ethical hacker or pen tester, your goal is to find a Wi-Fi network or device using wireless footprinting. This involves identifying an appropriate target within range. Attackers typically use wireless network scanning tools to scan for Wi-Fi networks, tuning into different radio channels of networking devices. The SSID (Service Set Identifier), which is the wireless network's name, is discovered through beacons, probe requests, responses, association, and re-association requests.

- Attackers can obtain the SSID through passive or active scanning and subsequently connect to the wireless network to launch attacks. Ethical hackers must perform footprinting to detect the SSID of a wireless network in the target organization, aiding in predicting the effectiveness of additional security measures.

- To footprint a wireless network, identification of the BSS (Basic Service Set) or Independent BSS (IBSS) provided by the access point is essential. This is achieved by leveraging the wireless network's SSID, which establishes an association with the access point to potentially compromise its security.

- Footprinting methods to detect the SSID of a wireless network include:

---

| Technique                | Description                                                                                       |
|--------------------------|---------------------------------------------------------------------------------------------------|
| Passive Footprinting     | Detects the existence of an access point by sniffing packets from the airwaves.                    |
| Active Footprinting      | Involves a wireless device sending a probe request with the SSID to check if an access point responds.|

---
#### Find Wi-Fi Networks in Range using NetSurveyor

[NetSurveyor](https://www.nutsaboutnets.com/netsurveyor-wifi-scanner/) is an 802.11 (Wi-Fi) network discovery tool that provides real-time information about nearby wireless access points. Follow these steps to find Wi-Fi networks using NetSurveyor:

- Launch NetSurveyor.

- View Access Points:
   - NetSurveyor initializes, showing discovered access points under the Network Discovery tab.
   - Details include SSID, BSSID, Channel, and Beacon Strength.

- Channel Usage and Timecourse:
   - Explore Channel Usage and AP Timecourse tabs for graphical views.
   - Analyze Channel Spectrogram for spectrum usage analysis.

- Generate Report:
   - Click File > Create Report.
   - Save the report as an Adobe PDF file.
   - Open the saved PDF file, detailed information about discovered access points is presented.


**Additional Tools:**
    - Explore other Wi-Fi discovery tools like inSSIDer Plus (https://www.metageek.com), Wi-Fi Scanner (https://lizardsystems.com), Acrylic Wi-Fi Home (https://www.acrylicwifi.com), WirelessMon (https://www.passmark.com), and Ekahau HeatMapper (https://www.ekahau.com).

### 2. Perform Wireless Traffic Analysis

- Wireless traffic analysis involves identifying vulnerabilities and potential targets within a wireless network.

- The focus is on understanding the network's characteristics, such as the broadcasted SSID, the presence of multiple access points, potential SSID recovery, authentication methods, WLAN encryption algorithms, and more.

- Wireless traffic analysis is crucial for devising a successful attack strategy. Wi-Fi protocols at Layer 2 offer unique characteristics, and the non-serialized nature of over-the-air traffic simplifies the process of sniffing and analyzing wireless packets. Various Wi-Fi packet-sniffing tools can be employed to capture and scrutinize the traffic of a target wireless network.

#### Find Wi-Fi Networks and Sniff Wi-Fi Packets using Wash and Wireshark

- Here we will discover WPS-enabled access points and capture wireless traffic using [Wash](https://www.kali.org/tools/reaver/) and Wireshark.

- [Wash](https://github.com/t6x/reaver-wps-fork-t6x/blob/master/docs/README.WASH) is a utility for identifying WPS enabled access points.

- Enable Monitor Mode:
   - Execute `airmon-ng check kill` to stop interfering processes.
   - Run `airmon-ng start wlan0` to activate monitor mode (`sudo iwconfig wlan0 mode monitor`).
   - Confirm that the adapter is in monitor mode (`iwconfig`).

- Find WPS-Enabled Devices:
   - Execute `wash -i wlan0mon` to detect WPS-enabled devices.
   - Results will display discovered Wi-Fi access points.

- Capture Wi-Fi Packets using Wireshark:
    - Open Wireshark in the terminal using `wireshark`.
    - In Wireshark, double-click the wireless network interface (e.g., wlan0mon).

- Start Packet Capture:
    - Observe Wireshark capturing 802.11 labeled packets.
    - Captured packets include information like source, destination, protocol, etc.

**Other Traffic Analyzers:**
    - Other Wi-Fi traffic analyzers like [AirMagnet WiFi Analyzer PRO](https://www.netally.com), [SteelCentral Packet Analyzer](https://www.riverbed.com), [Omnipeek Network Protocol Analyzer](https://www.liveaction.com), [CommView for Wi-Fi](https://www.tamos.com), and [Capsa Portable Network Analyzer](https://www.colasoft.com) can also be explored.

### 3. Perform Wireless Attacks

- As an ethical hacker, your responsibilities include conducting wireless attacks post the discovery, mapping, and analysis of the target wireless network. The objective is to test the security infrastructure comprehensively. This involves executing diverse attacks such as Wi-Fi encryption cracking (WEP, WPA, and WPA2), fragmentation, MAC spoofing, denial-of-service (DOS), and ARP poisoning attacks.

- WEP encryption, although commonly used for wireless networks, possesses exploitable vulnerabilities. Changing the SSID and addressing DHCP server configurations are initial steps for network protection.

---

| Wireless Attack                   | Description                                                                                                                                                     |
|------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Fragmentation Attack               | Successful attacks can obtain 1,500 bytes of PRGA (pseudo-random generation algorithm), compromising the security of the wireless communication.              |
| MAC Spoofing Attack                | The attacker changes their MAC address to that of an authenticated user to bypass MAC-filtering configurations, gaining unauthorized access to the network.     |
| Disassociation Attack              | The attacker disrupts connectivity between the access point and client, making the victim unavailable to other devices on the network.                           |
| Deauthentication Attack            | Floods station(s) with forged deauthentication packets to disconnect users from an access point, causing a denial-of-service (DoS) scenario.                    |
| Man-in-the-Middle Attack           | An active Internet attack where the attacker intercepts, reads, or alters information between two computers, potentially gaining unauthorized access to data.      |
| Wireless ARP Poisoning Attack      | Exploits the lack of verification in the ARP protocol to corrupt the ARP cache and associate the attacker's MAC address with the target host, leading to MITM attacks. |
| Rogue Access Points                | Unauthorized wireless access points installed by attackers, not under the network administrator's management, posing potential security risks to the network.     |
| Evil Twin                          | A fraudulent wireless access point imitating a legitimate one by mimicking another network name, deceiving users into connecting to an insecure network.          |
| Wi-Jacking Attack                  | Attackers gain access to numerous wireless networks using this method, potentially exploiting vulnerabilities in wireless security protocols.                     |

---

#### Find hidden SSIDs using Aircrack-ng

- Revealing a hidden SSID using [Aircrack-ng](https://www.kali.org/tools/aircrack-ng/).

- Enable Monitor Mode:
   - Execute `airmon-ng check kill` to stop interfering processes.
   - Run `airmon-ng start wlan0mon` to activate monitor mode (`sudo iwconfig wlan0 mode monitor`).

- List Detected Access Points:
   - Type `airodump-ng wlan0mon` and press Enter.
   - Observe available access points, noting the hidden ESSID associated with BSSID.


- Deauthentication Attack:
    - Use `aireplay-ng -0 11 -a <BSSID> -c <ClientMAC> wlan0mon` to generate de-authentication packets.
    - e.g., use `aireplay-ng -0 11 -a 54:37:BB:68:88:F9 -c 20:A6:0C:30:23:D3 wlan0mon` to generate de-authentication packets.

        - `-0`: Activates deauthentication mode.
        - `11`: Number of deauthentication packets to be sent.
        - `-a`: Sets the access point MAC address.
        - `-c`: Sets the destination MAC address.
        - `wlan0mon`: Wireless interface.

- Fake Authentication:
    - Switch back to the terminal with airodump-ng.
    - Observe the hidden SSID revealed under ESSID.

**Note:**
- In real attacks, this information is used to crack encryption and obtain the access key.

#### Crack a WEP Network using Wifiphisher

- [Wifiphisher](https://www.kali.org/tools/wifiphisher/) is a powerful rogue access point framework designed for conducting red team engagements or Wi-Fi security testing. 
- It enables penetration testers to establish a man-in-the-middle position against wireless clients through targeted Wi-Fi association attacks.
- Moreover, Wifiphisher can execute victim-customized web phishing attacks against connected clients, aiming to capture credentials (from third-party login pages or WPA/WPA2 Pre-Shared Keys) or infect victim stations with malware.
- Here, our objective is to utilize Wifiphisher for cracking a WEP network. While Wifiphisher can also crack WPA/WPA2 networks, the steps for doing so might differ. 
- Ensure that the hidden SSID of the target access point is unhidden before initiating this task. Additionally, a mobile device is required for victim simulation. The victim's device connects to the rogue access point created by Wifiphisher, and when the user enters the pre-shared WEP key, it gets captured by the application.

- Utilize Wifiphisher, a rogue access point framework, to perform targeted Wi-Fi association attacks and crack a WEP network by typing `wifiphisher`.

- **Launch Wifiphisher:**
   - Type `wifiphisher --force-hostapd` and press Enter.
   - Wifiphisher initializes and detects the wireless interfaces.

- **Select Target Access Point:**
   - Navigate the list of available access points and select target("Victim Wifi").

-  **Choose Phishing Scenario:**
   - Select Network Manager Connect for this task.
   - Note: Other phishing options are available (Firmware Upgrade Page, OAuth Login Page, or Browser Plugin Update).

- **Initiate Rogue Access Point:**
   - A fake network is created, and deauthentication packets are sent to connected devices.

-  **On Victim's Mobile Device:**
   - Identify the rogue access point "Victim Wifi" (unsecured).
   - Connect to this access point.

-  **Monitor Connected Victims:**
   - In the Wifiphisher window, observe the connected device under Connected Victims.

-  **Capture WEP Key:**
   - Victim receives a "Connection Failed" page and is prompted for the pre-shared key.
   - Enter the pre-shared WEP key (e.g., 1234567890).
   - Wifiphisher captures the entered key.

#### Crack a WEP Network using Aircrack-ng

- **Enable Monitor Mode:**
   - Execute `airmon-ng check kill` to stop interfering processes.
   - Run `airmon-ng start wlan0mon` to activate monitor mode.

- **Capture Access Point Information:**
   - Type `airodump-ng wlan0mon` to display access points and connected clients.

- **Filter WEP Networks:**
    - Optionally, use `airodump-ng wlan0mon --encrypt wep` to display only WEP networks.

- **Capture Initialization Vectors (IVs):**
    - Execute `airodump-ng --bssid [Target_BSSID] -c [Channel_Number] -w WEPcrack wlan0mon`.

- **Generate ARP Traffic:**
    - In a new terminal, type `aireplay-ng -3 -b [Target_BSSID] -h [Client_BSSID] wlan0mon`.
    - Wait for sufficient ARP packets, then press Ctrl+C on both terminals.

- **Crack WEP Key:**
    - Launch `aircrack-ng WEPcrack-01.cap` to recover the WEP key.
    - Connect to the target access point using the cracked WEP key.

**Wireless Attacks:**
Wireless attacks involve exploiting vulnerabilities in wireless networks. Common attacks include eavesdropping, packet sniffing, denial-of-service (DoS), Man-in-the-Middle (MitM), and cracking encryption protocols like WEP, WPA, or WPA2. Tools like Aircrack-ng, Wireshark, and airmon-ng are commonly used for wireless penetration testing. Understanding these attacks is crucial for securing wireless infrastructures.

#### Crack a WPA Network using Fern Wifi Cracker

##### WPA Encryption Protocol:

WPA (Wi-Fi Protected Access) is a robust wireless encryption protocol outlined by the 802.11i standard. It incorporates advanced security features, including:
- **Temporal Key Integrity Protocol (TKIP):** A protocol ensuring the integrity and confidentiality of wireless communications.
- **48-bit Initialization Vector (IV):** Used in conjunction with TKIP to enhance encryption.
- **64-bit Message Integrity Code (MIC):** A cryptographic checksum for verifying the integrity of transmitted messages.
- **RC4 Stream Cipher Encryption:** Utilizes the RC4 algorithm with 128-bit keys for secure data encryption.
  
The implementation of these features results in more robust encryption and authentication compared to its predecessor, WEP.

##### Fern Wifi Cracker:

[Fern Wifi Cracker](https://www.kali.org/tools/fern-wifi-cracker/) is a powerful wireless security auditing and attack software designed for both wired and wireless networks. Key features include:
- **WEP/WPA Key Cracking:** Capable of cracking and recovering WEP/WPA keys to expose vulnerabilities in wireless networks.
- **Versatile Attacks:** Enables a range of network-based attacks, such as session hijacking, service brute-forcing, and HTTP injection.
- **Enhanced Security Testing:** Facilitates in-depth security testing of wireless infrastructures, identifying weaknesses for mitigation.

**Note:** It's essential to configure the target access point with WEP encryption and a hidden SSID before initiating the task.

- **Launch Fern Wifi Cracker:**
   - Type `fern-wifi-cracker`.

- **Configure Fern Wifi Cracker:**
   - Click 'Select Interface' and choose the wireless interface.
   - Click 'Scan for Access points' to initiate the scan.

- **Select WPA Network and Password File:**
   - Click 'Wi-Fi WPA' to display detected access points with WPA enabled.
   - Choose the target access point.
   - Click 'Browse' and select the 'password.txt' file.

- **Launch WPA Attack and Monitor Attack Progress:**
   - Click 'Wi-Fi Attack' to start the attack.
   - Ensure at least 1 client is connected to the target access point.
   - Observe the various phases of the attack, including probing, deauthentication, handshake capture, and WPA encryption brute-forcing.
   - After the completion of the attack, the cracked WPA key will be displayed.

- **Verify Cracked Key:**
    - If the Attack Panel window closes, relaunch Fern Wifi Cracker and click 'Key Database' to verify the acquired key.

- Wireless attacks exploit vulnerabilities in wireless networks, including WEP and WPA encryption protocols. Fern Wifi Cracker facilitates the cracking of WPA keys, enhancing security testing and network penetration.


#### Crack a WPA2 Network using Aircrack-ng

- Ensure the access point router is configured for WPA2-PSK encryption.

- **Put Interface in Monitor Mode:**
   - Type `airmon-ng start wlan0mon`.

   Note:
   - If processes cause trouble, run `airmon-ng check kill`.

- **Capture Packets:**
   - Use `airodump-ng wlan0mon` to capture access points and clients.

- **Target Access Point:**
   - Use `airodump-ng --bssid 54:37:BB:68:88:F9 -c 11 -w <target> wlan0mon` to capture packets.

- **Send De-authentication Packets:**
    - Open a new terminal and type `aireplay-ng -0 11 -a 54:37:BB:68:88:F9 -c wlan0mon` multiple times.

- **Capture WPA Handshake:**
    - Switch back to the terminal running `airodump-ng` and capture the WPA handshake.

- **Crack WPA2 Key:**
    - aircrack-ng -a2 54:37:BB:68:88:F9 -w password.txt <target.cap>
    - The cracked key will be displayed under "KEY FOUND!"

**Additional Tools:**

   - Explore other tools for WEP/WPA/WPA2 encryption cracking:
      - [Elcomsoft Wireless Security Auditor](https://www.elcomsoft.com)
      - [Portable Penetrator](https://www.secpoint.com)
      - [WepCrackGui](https://sourceforge.net)
      - [Pyrit](https://github.com)
      - [WepAttack](http://wepattack.sourceforge.net)


#### Create a Rogue Access Point to Capture Data Packets

- Rogue access points pose a serious security threat, providing unauthorized access to networks. In this task, we'll utilize the [create_ap](https://github.com/oblique/create_ap) tool along with [Bettercap](https://www.kali.org/tools/bettercap/) to create a rogue access point, enabling us to capture data packets.

- Install required packages by running the following command in the terminal:

    ```bash
    sudo apt-get install haveged hostapd git util-linux procps iproute2 iw dnsmasq iptables bettercap
    ```

- Navigate to the [create_ap](https://github.com/oblique/create_ap) repository and install it:

    ```bash
    cd create_ap
    make install
    ```

- Identify the wireless interface:

    ```bash
    ip a
    ```

- Launch the rogue access point:

    ```bash
    create_ap <wireless-interface> eth0 Freelnternet
    ```

    (Replace `<wireless-interface>` with your wireless interface)

- On your mobile device, connect to the Freelnternet access point.

- Capture traffic from the victim's device:
    ```bash
    sudo bettercap -X -I <wireless-interface> -S NONE --proxy --no-discovery
    ```
    - `-X`: Sniffing enabled
    - `-I`: Interface specified
    - `-S`: ARP spoofing set to NONE
    - `--proxy`: HTTP proxy enabled
    - `--no-discovery`: Disable client discovery

- Observe captured traffic, switch to the mobile device, and browse a website (e.g., http://testphp.vulnweb.com/login.php).

- Return to the terminal running Bettercap. Captured credentials will be displayed.

**Note**
- Ensure the victim's device connects to the Freelnternet access point.
- For HTTPS websites, configure Bettercap accordingly.