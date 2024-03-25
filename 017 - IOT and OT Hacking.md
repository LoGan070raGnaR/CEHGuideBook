# IOT and OT Hacking

- IOT and OT device hacking involves compromising smart devices like CCTV cameras, automobiles, printers, door locks, washing machines, etc., to gain unauthorized access to network resources and the devices themselves.

- The proliferation of Internet of Things (IOT) devices in daily life, from smart homes to healthcare applications, has introduced vulnerabilities to cyber-attacks due to a lack of basic security. The objective of a hacker exploiting IOT devices is to gain unauthorized access, potentially leading to DDoS attacks or misuse of sensitive information.

## Objective

- Performing IOT and OT device footprinting
- Capturing and analyzing traffic between IOT devices

## Overview of IOT and OT Hacking

- In IOT and OT hacking, attackers use methodologies like information gathering, attack surface area identification, and vulnerability scanning to acquire information and hack the target devices and networks. The phases include:
    - Information gathering
    - Vulnerability scanning
    - Launch attacks
    - Gain remote access
    - Maintain access

## Methods

#### 1.Perform Footprinting

- Gather information using online footprinting tools

#### 2. Capture and Analyze IOT Device Traffic

- Capture and analyze IOT traffic using Wireshark


---
### 1. Perform Footprinting using Various Footprinting Techniques

- As a professional ethical hacker or pen tester, the initial step involves gathering comprehensive information about the target IOT and OT devices through footprinting. This process includes utilizing search engines, advanced Google hacking, Whois lookup, and other techniques.

- The primary goal in IOT and OT device hacking is to extract key details such as IP address, protocols used (MQTT, ModBus, ZigBee, BLE, 5G, IPv6LoWPAN, etc.), open ports, device type, geolocation, manufacturing number, and manufacturer details.

- Footprinting techniques play a crucial role in collecting fundamental information about the target IOT and OT platforms for potential exploitation. The information gathered includes IP address, hostname, ISP, device location, target IOT device banner, FCC ID information, device certifications, and more.

#### Gather Information using Online Footprinting Tools

- Gathering information about the target IOT and OT devices using various online sources, including Whois domain lookup, advanced Google hacking, and the Shodan search engine.
- Perform footprinting on the MQTT protocol, a machine-to-machine (M2M) connectivity protocol used in the Internet of Things (IOT).
- Use information gathered for vulnerability scanning and potential exploitation.

1. Visit [Whois Domain Lookup](https://www.whois.com/whois/).

2. Perform a Whois lookup for www.oasis-open.org.

3. Open a new tab, visit the [Google Hacking Database](https://www.exploit-db.com/google-hacking-database), and search for SCADA.

4. Utilize obtained dorks to query results in Google.

5. Visit [Shodan Login](https://account.shodan.io/login) and log in.

6. In the Shodan main page, search for devices with `port 1883` (default `MQTT port`).

7. Explore additional Shodan filters:
   - Search for Modbus-enabled ICS/SCADA systems: `port:502`
   - Search for SCADA systems using specific PLC names: `PLC name:"Schneider Electric"`
   - Search for SCADA systems in certain countries: `SCADA Country:"US"`

**Note:**

- Whois lookup provides information on domain registration.
- Google Hacking Database helps discover sensitive information.
- Shodan allows searching for devices based on various criteria.
    - Using Shodan, you can obtain the details of SCADA systems that are used in water treatment plants, nuclear power plants, HVAC systems, electrical transmission systems, home heating systems, etc.


### 2. Capture and Analyze IoT Device Traffic

- As an ethical hacker, it is essential to possess the skills to capture and analyze the traffic between IoT devices. This involves using tools and techniques to intercept valuable data exchanged among IoT devices, extracting information on communication protocols, and obtaining sensitive details like credentials and device identification numbers.

- Many IoT devices, such as security cameras, often host insecure websites for remote control or configuration. These websites commonly use the HTTP protocol instead of HTTPS, making them susceptible to various attacks. Default factory credentials further increase the vulnerability, allowing attackers to intercept and decrypt traffic between devices and web applications using tools like Wireshark.

#### Capture and Analyze 10T Traffic using Wireshark

- Wireshark is a powerful open-source packet analyzer, widely used for network troubleshooting, analysis, software development, and education.


1. Install and run MQTT Broker on the Attacker machine:
   - Download and install `Bevywise_MQTTRoute_Win_64.exe`.
   - Launch MQTTRoute using the installed shortcut.
   - The command prompt will appear with TCP port 1883.

2. Install IoT run Simulator on the Victim machine:
   - Download and install `Bevywise_10TSimulator_Win_64.exe`.
   - Double-click `runsimulator.bat` to launch the simulator.
   - Access the web interface at http://127.0.0.1:9000/setnetwork?network=HEALTH CARE.

3. Create Virtual IoT Network and Devices:
   - In the IoT Simulator:
     - Create a new network (e.g., GITHUB FINANCE NETWORK).
     - Set Broker IP Address to 10.10.1.19.
     - Save the configuration.

4. Connect Devices to Network:
   - Add a device (e.g., Temperature_Sensor) to the network.
   - Start the network.

5. Capture Traffic with Wireshark:
   - Open Wireshark, select the Ethernet interface.
   - Start capturing packets.

6. Send Commands and Verify:
   - In the Attacker machine, open Chrome and go to http://localhost:8080.
   - Sign in to MQTTRoute.
   - Navigate to Devices, locate connected devices, and send commands.

7. Analyze Traffic in Wireshark:
   - Stop Wireshark capture.
   - Filter packets with `mqtt`.
   - Analyze MQTT protocol packets, including Publish Message details.

---