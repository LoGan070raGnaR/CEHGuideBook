# Footprinting and Reconnaissance

## Introduction

-   **Footprinting** refers to collecting information about a target network from publicly accessible sources. It involves creating a blueprint or "footprint" of the organization, aiding in the selection of effective attack strategies.

-   **Reconnaissance** is the initial step in any system attack, involving the collection of information to narrow down efforts and choose attack weapons.

As an ethical hacker in a large organization, your task is to perform a proactive security assessment. Before starting, discuss and define the scope with management and establish rules of engagement (RoE).

## Objective

Extract information about the target organization, including:

- **Organization Information:** Employee details, addresses, partner details, weblinks, web technologies, patents, trademarks, etc.
- **Network Information:** Domains, sub-domains, network blocks, topologies, routers, firewalls, IP addresses, Whois records, DNS records, etc.
- **System Information:** Operating systems, web server OSes, web server locations, user accounts, passwords, etc.

## Overview of Footprinting

- **Footprinting** involves collecting information about a target network and its environment to evaluate the security posture. It can be passive or active.
    - **Passive Footprinting:** Gathering information without direct interaction, useful when detection is undesirable.
    - **Active Footprinting:** Gathering information with direct interaction, where the target may recognize the process.

## Task

Ethical hackers use tools and techniques for footprinting:

#### 1. Perform footprinting through search engines

- **Advanced Google Hacking Technique**
- **Video Search Engines**
- **FTP Search Engines**
- **IOT Search Engines**

#### 2. Perform Footprinting Through Web Services

- **Netcraft:** Find the company's domains and sub-domains.
- **PeekYou:** Gather personal information.
- **theHarvester:** Gather email lists.
- **Deep and Dark Web Searching:** Gather information.

#### 3. Perform Footprinting Through Social Networking Sites

- **Linkedln:** Gather employee information.
- **Sherlock:** Gather personal information from various social networking sites.
- **Followerwonk:** Gather information.

#### 4. Perform Website Footprinting

- **Ping Command Line Utility:** Gather information about a target website.
- **Photon:** Gather information about a target website.
- **Central Ops:** Gather information about a target website.
- **Web Data Extractor:** Extract company's data.
- **HTTrack Web Site Copier:** Mirror a target website.
- **GRecon:** Gather information about a target website.
- **CeWL:** Gather a wordlist from the target website.

#### 5. Perform Email Footprinting

- **eMailTrackerPro:** Trace emails.

#### 6. Perform Whois Footprinting

- **DomainTools:** Perform Whois lookup.

#### 7. Perform DNS Footprinting

- **nslookup Command Line Utility and Online Tool:** Gather DNS information.
- **Reverse IP Domain Check and DNSRecon:** Perform reverse DNS lookup.
- **SecurityTrails:** Gather subdomain and DNS records.

#### 8. Perform Network Footprinting

- **Locate the Network Range**
- **Network Tracerouting in Windows and Linux Machines**
- **Path Analyzer Pro:** Advanced network route tracing.

#### 9. Perform Footprinting using Various Tools

- **Recon-ng**
- **Maltego**
- **OSRFramework**
- **FOCA**
- **BillCipher**
- **OSINT Framework**

---
### 1. Perform footprinting through search engines

- Search engines serve as primary information sources to extract critical details about a target organization from the internet.

- As a professional ethical hacker or pen tester, your initial step is to gather maximum information about the target organization through footprinting using search engines. This involves advanced searches such as image searches, reverse image searches, and video searches.

- Search engines use crawlers to continuously scan active websites and add the results to their index. Major search engines include Google, Bing, Yahoo, Ask, Aol, Baidu, WolframAlpha, and DuckDuckGo.

#### Gather Information using Advanced Google Hacking Techniques

- Advanced Google hacking involves creating complex search engine queries using advanced Google operators to extract sensitive or hidden information about a target company from search results.

- **Basic Google Operators for GitHub:**
    - `intitle:login site:github.com`: Identify login pages on GitHub.
    - `github.com filetype:pdf`: Search for PDF files related to GitHub.

- **Additional Advanced Google Operators for GitHub:**
    - `cache:github.com`: View cached versions of web pages on GitHub.
    - `allinurl: GitHub repository`: Restrict results to pages containing the specified terms in the URL.
    - `inurl: copy site:github.com`: Restrict results to pages on GitHub containing the word "copy" in the URL.
    - `allintitle: open source projects`: Restrict results to pages containing specified terms in the title.
    - `inanchor:Git`: Restrict results to pages with anchor text containing the word "Git."
    - `allinanchor: best coding practices`: Restrict results to pages with anchor text containing all specified terms.
    - `link:github.com`: Find pages that link to GitHub's home page.
    - `related:github.com`: Find pages similar or related to GitHub's home page.
    - `info:github.com`: Find information about the www.github.com home page.
    - `location: GitHub`: Find information for a specific location related to GitHub.

---
### 2. Perform Footprinting Through Web Services

- Web services offer a wealth of publicly accessible information that can be exploited during the footprinting phase. Extracting critical details about a target organization, such as domains, sub-domains, operating systems, geographic locations, employee details, emails, financial information, and hidden web content, is essential for planning ethical hacking strategies.

- Web services, including social networking sites, people search services, alerting services, financial services, and job sites, provide valuable information about a target organization. This information encompasses infrastructure details, physical location, employee details, etc. Groups, forums, and blogs may also expose sensitive details about a target, such as public network information, system data, and personal information. Internet archives may even retain information that has been removed from the World Wide Web.

#### Find the Company's Domains and Sub-domains using Netcraft

- Web services such as Netcraft provide valuable information about a target organization's domains and sub-domains. Extracting this information is crucial for understanding the organization's online presence, infrastructure, and potential attack vectors.

- Visit [Netcraft](https://www.netcraft.com).

- Click on the menu icon from the top-right corner, navigate to Resources -> Tools -> Site Report.

- On the "What's that site running?" page, enter the target website's URL (e.g., https://github.com/) in the text field. Click the Look up button.

- The Site report for the target website will appear, containing information related to Background, Network, Hosting History, etc.

- In the Network section, click on the website link (e.g., github.com) in the Domain field to view the subdomains.

- The result will display subdomains of the target website along with netblock and operating system information.

- The collected list of subdomains can be used for web application attacks.

- Optionally, tools such as [Sublist3r](https://www.kali.org/tools/sublist3r/), [Pentest-Tools Find Subdomains](https://pentest-tools.com), etc., can be used to identify domains and sub-domains of any target website.

---
#### Gather Personal Information using PeekYou Online People Search Service

- Online people search services are widely used to find personal information about individuals, providing details such as names, addresses, contact information, date of birth, photographs, videos, and more. In this task, we will use the PeekYou online people search service to gather information about a person from the target organization, focusing on Satya Nadella from Microsoft.

- Visit [PeekYou](https://www.peekyou.com).

- In the First Name and Last Name fields, type Satya and Nadella, respectively. In the Location drop-down box, select Washington, DC. Click the Search icon.

- The people search begins, and the best matches for the provided search parameters will be displayed.

- The result shows information such as public records, background details, email addresses, contact information, address history, etc., which can be used for phishing, social engineering, and other attacks.

- Click on View Full Report to access detailed information about the person.

- Scroll down to view the entire information about the person.

- Optionally, you can also use other people search services such as [Spokeo](https://www.spokeo.com), [pipl](https://pipl.com), [Intelius](https://www.intelius.com), [BeenVerified](https://www.beenverified.com), etc., to gather personal information of key employees in the target organization.

---
#### Gather an Email List using theHarvester

- Emails play a crucial role in communication and are essential for ethical hackers to understand an organization's footprint on the Internet. TheHarvester is a tool that gathers emails, subdomains, hosts, employee names, open ports, and banners from various public sources. It utilizes search engines, PGP key servers, and databases like SHODAN to extract valuable information from the target domain. In this task, we will use [theHarvester](https://www.kali.org/tools/theharvester/) tool to gather a list of email IDs related to a target organization, considering Microsoft as an example.


- In the terminal, type `theHarvester -d microsoft.com -l 200 -b baidu` and press Enter.
   - `-d` specifies the domain or company name.
   - `-l` specifies the number of results to retrieve.
   - `-b` specifies the data source (here, Baidu).

- theHarvester starts extracting details and displays them on the screen.

- Review the email IDs related to the target company and company hosts obtained from the Baidu source.

---
#### Gather Information using Deep and Dark Web Searching

- The deep web and dark web contain hidden and unindexed web pages and content, providing information that cannot be located through traditional browsers and search engines. Accessing the dark web can be done using tools like Tor Browser, allowing users to navigate anonymously.

- Use `Tor Browser`
- You can also use tools like [ExoneraTor](https://metrics.torproject.org), [OnionLand Search Engine](https://onionlandsearchengine.com), etc., for deep and dark web browsing.

---
#### Determine Target OS Through Passive Footprinting

- Operating system information is crucial for ethical hackers to plan and execute attacks effectively. In this task, we will gather details about the operating system running on the target machine through passive footprinting techniques using the Censys web service.

- Vist [Censys web service](https://search.censys.io/?q=)

- In the search field, type the target website (e.g., github.com) and press Enter. Click on any Hosts IP address from the results to gather OS details.

- The selected host page appears, showing details such as OS (e.g., Ubuntu), protocols, software, host keys, etc. This information aids attackers in identifying vulnerabilities and planning effective exploits.

- Additionally, you can use other web services like Netcraft (https://www.netcraft.com), Shodan (https://www.shodan.io), etc., to gather OS information through passive footprinting.

---
### 3. Footprinting Through Social Networking Sites

- Social networking services play a crucial role in facilitating the building of social networks and relationships online. As a professional ethical hacker, the task involves gathering personal and professional information about employees in key positions within the target organization through footprinting on social networking sites.

- Social networking sites provide online platforms for people to connect and build interpersonal relationships. Users maintain profiles containing basic information, contacts, interests, and more. Organizations also utilize these platforms for sharing company-related information. Examples include LinkedIn, Facebook, Instagram, Twitter, Pinterest, YouTube, etc.

#### Gather Employees' Information from LinkedIn using theHarvester

- In the terminal window, type `theHarvester -d microsoft -l 200 -b linkedin` and press Enter to retrieve 200 results of Microsoft from the LinkedIn source.

   - `-d` specifies the domain or company name to search (here, `microsoft`).
   - `-l` specifies the number of results to be retrieved (200 in this case).
   - `-b` specifies the data source as LinkedIn.

7. Scroll down to view the list of employees along with their job roles in Microsoft. This information can be utilized by attackers for social engineering or phishing attacks.

---
#### Gather Personal Information from Various Social Networking Sites using Sherlock

- [Sherlock](https://www.kali.org/tools/sherlock/) is a python-based tool used to gather information about a target person from various social networking sites. It searches and locates the target user on different platforms, providing results along with complete URLs associated with the target person. In this task, we will use Sherlock to gather personal information about the target individual, Satya Nadella.

- Type `sherlock satya nadella` and press Enter. Retrieve all the URLs related to Satya Nadella. Scroll down to view all the results.Ignore any error messages if encountered.

- The gathered URLs can be used by attackers to obtain sensitive information about the target, including date of birth, employment status, and details about the organization they work for.

- You can also use other tools such as Social Searcher (https://www.social-searcher.com), UserRecon (https://github.com/wishihab/userrecon), etc., to gather additional information related to the target company and its employees from social networking sites.

---
#### Gather Information using Followerwonk

- Followerwonk is an online tool that allows users to explore and grow their social graph, providing deeper insights into Twitter analytics. It helps in understanding who the followers are, their locations, and when they tweet. In this task, we will utilize Followerwonk to gather information about the followers on social networking sites.

- Visit [Followerwonk](https://followerwonk.com/analyze).

- On the Followerwonk website, the analysis page appears.

- In the Screen Name search bar, enter the target individual's Twitter handle (e.g., @satyanadella), and click the "Do it" button to analyze the users whom the target person follows.

- The results related to the target individual appear, displaying an analysis of Twitter users that the target person follows.

- Scroll down to view detailed analysis on the geographical location and active hours of the followers. This information can be valuable for social engineering and non-technical attacks.

- Additionally, tools such as Hootsuite (https://www.hootsuite.com), Meltwater (https://www.meltwater.com), etc., can be used to gather more information related to the target company and its employees from social networking sites.

---
### 4. Perform Website Footprinting

- Website footprinting involves the collection of information about a target organization's website. This technique provides sensitive details associated with the website, including domain owner information, domain names, hosting details, operating system details, IP addresses, registrar details, emails, filenames, etc.

#### Gather Information About a Target Website using Ping Command Line Utility

- Type the following command to find the IP address of the target website:

   ```bash
   ping github.com
   ```

- Note the target domain's IP address in the result. You also obtain information on Ping Statistics such as packets sent, received, lost, and the round-trip time.

- Type the following command to determine the maximum frame size:

   ```bash
   ping github.com -f -l 1500
   ```

    - The response, "Packet needs to be fragmented but DF set," indicates that the frame is too large.
    - Try different values to find the maximum frame size.
    - A successful ping indicates the maximum frame size.

- Now, discover what happens when TTL (Time to Live) expires:

   ```bash
   ping github.com -i 3
   ```

    - The response "TTL expired in transit" means the router discarded the packet due to TTL reaching 0.
    - Continue experimenting with different TTL values until you find the hop count to reach the target.

    ```bash
    ping www.certifiedhacker.com -i 2 -n 1
    ```

    - Find the hop count by adjusting the TTL value

#### Gather Information About a Target Website using Photon

- [Photon](https://www.kali.org/tools/photon/) is a Python script used to crawl a given target URL and extract various information such as URLs (in-scope and out-of-scope), URLs with parameters, email addresses, social media accounts, files, secret keys, and subdomains. The extracted information can be exported in JSON format.

- Type `photon -h` to view the list of options that Photon provides.

- Execute the command to crawl the target website (e.g., github.com):

   ```bash
   photon -u https://github.com
   ```

- View the results saved in the `github.com` directory under the working directory.

- To explore the crawled URLs, navigate to the `github.com` folder and open the `external.txt`, `internal.txt`, and `scripts.txt` files.

- Execute a more complex command to crawl the target website using URLs from archive.org:

    ```bash
    python3 photon.py -u https://github.com -l 3 -t 200 --wayback
    ```

- View the results obtained in the `github.com` directory.

- Explore other functionalities of Photon, such as cloning the target website, extracting secret keys and cookies, obtaining strings by specifying regex patterns, etc.

---
#### Gather Information About a Target Website using Central Ops

- [CentralOps](https://centralops.net) is a free online network scanner that investigates domains and IP addresses, DNS records, traceroute, nslookup, whois searches, etc.

- Visit [CentralOps](https://centralops.net).

- On the Central Ops website, enter the target website's URL (e.g., github.com) in the "Enter a domain or IP address" field, and click on the "go" button.

- View the search results for GITHUB.COM, including information such as Address lookup and Domain Whois record.

- Scroll down to view additional information like Network Whois record and DNS records.

- The obtained information, including DNS records, can be used for injection attacks and other web application attacks on the target website.

- You can also use tools such as [Website Informer](https://website.informer.com), [Burp Suite](https://portswigger.net), [Zaproxy](https://www.zaproxy.org), etc., to perform website footprinting on a target website.

---
#### Gather Information About a Target Website using GRecon

- [GRecon](https://github.com/TebbaaX/GRecon) is a Python tool designed for running Google search queries to perform reconnaissance on a target. It helps find subdomains, sub-subdomains, login pages, directory listings, exposed documents, and WordPress entries.

- Type `python3 grecon.py` and press Enter.

- GRecon initializes. In the "Set Target (site.com):" field, type `github.com` and press Enter.

- GRecon searches for available subdomains, sub-subdomains, login pages, directory listings, exposed documents, WordPress entries, and pasting sites. It displays the results.

- Attackers can use the gathered information to perform various web application attacks on the target website.

---
#### Gather a Wordlist from the Target Website using CeWL

- The words available on the target website may reveal critical information that can assist in performing further exploitation. [CeWL](https://www.kali.org/tools/cewl/) is a Ruby app that is used to spider a given target URL to a specified depth, optionally following external links, and returns a list of unique words that can be used for cracking passwords.

- In the terminal window, type `cewl -d 2 -m 5 github.com` and press Enter. (*Note: -d represents the depth to spider the website (here, 2) and -m represents the minimum word length (here, 5).*)

- A unique wordlist from the target website is gathered. (*Note: The minimum word length is 5, and the depth to spider the target website is 2.*)

- Alternatively, this unique wordlist can be written directly to a text file. To do so, type `cewl -w wordlist.txt -d 2 -m 5 github.com` and press Enter. (*Note: -w - Write the output to the file (here, wordlist.txt).*)

- This wordlist can be used further to perform brute-force attacks against the previously obtained emails of the target organization's employees.

---
### 5. Perform Email Footprinting

- E-mail footprinting, or tracking, is a method to monitor or spy on email delivered to the intended recipient. This kind of tracking is possible through digitally time-stamped records that reveal the time and date when the target receives and opens a specific email.

- Email footprinting reveals information such as:
    - Recipient's system IP address
    - The GPS coordinates and map location of the recipient
    - When an email message was received and read
    - Type of server used by the recipient
    - Operating system and browser information
    - If a destructive email was sent
    - The time spent reading the email
    - Whether or not the recipient visited any links sent in the email
    - PDFs and other types of attachments
    - If messages were set to expire after a specified time

#### Gather Information about a Target by Tracing Emails using eMailTrackerPro

- Use [eMailTrackerPro](https://emailtracker.website/pro).

- You can also use email tracking tools such as [Infoga](https://github.com/The404Hacking/Infoga), [Mailtrack](https://mailtrack.io), etc. to track an email and extract target information such as sender identity, mail server, sender's IP address, location, etc.

---
### 6. Perform Whois Footprinting

- Whois lookup provides valuable information about a target, including details such as the owner, registrar, registration information, name servers, IP address, and more.

#### Perform Whois Lookup using DomainTools

- Visit [DomainTools](https://whois.domaintools.com/).

- In the search bar, enter the target domain or IP address (e.g., github.com) and click Search.

- Review the search result, which includes organizational details, registration information, name servers, IP address, and location.

- The Whois lookup revealed essential information about the target, providing insights into the domain's registration, ownership, and technical details. This data is crucial for mapping the organization's network, executing social engineering attacks, and obtaining internal network details. Additionally, other Whois lookup tools such as SmartWhois and Batch IP Converter can be explored for additional information extraction.

---
### 7. Perform DNS Footprinting

- DNS, or Domain Name System, footprinting reveals information about DNS zone data.

- During the footprinting process, gathering DNS information on the target domain obtained in previous steps is crucial. As an ethical hacker, you need to perform DNS footprinting to collect details about DNS servers, records, and server types used by the target organization. DNS zone data include domain names, computer names, IP addresses, mail servers, service records, etc. This information aids in mapping the organization's network, executing social engineering attacks, and obtaining internal network details.

- DNS is a critical component of Internet communication, translating domain names to IP addresses and vice versa. It simplifies human-machine communication by providing a readable format for IP addresses.

#### Gather DNS Information using nslookup Command Line Utility and Online Tool

- Type `nslookup`, and press Enter.
- In nslookup interactive mode, type `set type=a` and press Enter.
- Type the target domain `github.com` and press Enter.
- Analyze the non-authoritative answer to obtain the IP address.
- Determine the authoritative name server using `set type=cname`.
- Type `github.com` to find the authoritative name server and mail server.
- Find the IP address of the authoritative name server using `set type=a`.

- Perform the same operations using NSLOOKUP online tool.
- Open a web browser and navigate to [NSLOOKUP](http://www.kloth.net/services/nslookup.php).
- Enter `github.com`, set Query to `A (IPv4 address)`, and click Look it up.
- Explore different query options such as AAAA (IPv6 address).

- You can use other DNS lookup tools like [DNSdumpster](https://dnsdumpster.com), [DNS Records](https://network-tools.com), etc., for extracting more DNS information.

#### Perform Reverse DNS Lookup using Reverse IP Domain Check and DNSRecon

- DNS lookup finds the IP addresses for a given domain, while reverse DNS lookup retrieves the domain name of a given IP address.

1. **Reverse IP Domain Check with YouGetSignal**

- Visit [YouGetSignal](https://www.yougetsignal.com).
- On the site, click on "Reverse IP Domain Check."
- Enter `github.com` in the Remote Address field and click Check. This reveals other domains hosted on the same server as github.com.
- This provides valuable information about domains sharing the server with the target.

2. **Reverse DNS Lookup with DNSRecon**

- Execute [DNSRecon](https://www.kali.org/tools/dnsrecon/) with the command `dnsrecon -r 192.30.255.0-192.30.255.255` to find DNS PTR records for the specified IP range.

#### Gather Information of Subdomains and DNS Records using SecurityTrails

- SecurityTrails is collect information about subdomains and DNS records of the target website.

- Visit [SecurityTrails](https://securitytrails.com/).
- In the search field, enter `github.com` and press Enter.
- Explore the DNS records section, including A records, AAAA records, MX records, NS records, SOA records, TXT records, and CNAME records.
- Switch to the Historical Data tab to view historical information about A, AAAA, MX, NS, SOA, and TXT records.
- Switch to the Subdomains tab to find a list of subdomains related to github.com.

- Additionally you can use DNSChecker and DNSdumpster for DNS footprinting.

### 8. Perform Network Footprinting

- Network footprinting is a crucial step in gathering network-related information about a target organization. As a professional ethical hacker, the objective is to collect data such as network range, traceroute details, TTL values, etc., to create a comprehensive map of the target network. This information serves as a foundation for understanding the network structure and is instrumental in planning and executing advanced attacks.

- Network footprinting involves accumulating data about a specific network environment, enabling ethical hackers to draw network diagrams and analyze the target network in detail for advanced attacks.

#### Locate the Network Range

- Locating the network range is a fundamental step in understanding the target network's structure. It provides insights into the network topology, live machines, and the control device and operating system used. In this task, we'll use the ARIN Whois database search tool to locate the network range.

- Visit [ARIN](https://www.arin.net/about/welcome/region).
- On the ARIN website, enter the IP address of the target organization (e.g., github.com with IP 192.30.255.113) in the search bar and click the Search button.
- Retrieve information about the network range, including network type, registration information, etc.

#### Perform Network Tracerouting in Windows and Linux Machines

- Network tracerouting is essential for identifying the path and hosts between the source and destination in a network. This process provides critical information, including the IP addresses of hosts along the route, enabling the mapping of the target organization's network topology. Traceroute assists in extracting details about network topology, trusted routers, firewall locations, and more.

1. **Windows Machine:**
   - Type `tracert github.com` and press Enter to view the hops made by packets.
   - Type `tracert /?` to view different options for the `tracert` command.
   - Type `tracert -h 5 github.com` to perform a trace with a maximum of 5 hops.

2. **Linux Machine:**
   - Type `traceroute github.com` and press Enter to view the network route.

- Optionally, use other traceroute tools like VisualRoute or Traceroute NG for additional network information.

---
### 9. Footprinting a Target using Various Tools

- Footprinting tools collect basic information about target systems, including IP location, routing, business details, contact information, DNS information, and more.

#### Footprinting a Target using Recon-ng

1. **Footprinting**

    - Launch Recon-ng by typing `recon-ng`.
    - Use `marketplace install all` to install available modules.
    - Execute `modules search` to view all available modules.
    - Create a workspace using `workspaces create FOOTPRINTING`.
    - Insert the target domain using `db insert domains` and `github.com`.
    - Load modules for network reconnaissance (`brute_hosts`, `Netcraft`, `Bing`).
    - Run `modules load brute` and `modules load recon/domains-hosts/brute_hosts`.
    - Execute `run` to harvest hosts information.
    - Perform a reverse lookup using `modules load reverse_resolve` and `run`.
    - View the harvested hosts with `show hosts`.
    - Prepare a report using `modules load reporting/html`.
    - Set report options (`FILENAME`, `CREATOR`, `CUSTOMER`).
    - Run the reporting module with `run`.

2. **Gathering Personnel Information**

    - Launch Recon-ng by typing `recon-ng`.
    - Create a new workspace with `workspaces create RECONNAISSANCE`.
    - Load the `whois_pocs` module with `modules load recon/domains-contacts/whois_pocs`.
    - Set the target domain with `options set SOURCE facebook.com`.
    - Run the module with `run` to extract contact details.
    - Load the `namechk` module with `modules load recon/profiles-profiles/namechk`.
    - Set the username for validation with `options set SOURCE MarkZuckerberg`.
    - Run the module with `run` to check for username existence.
    - Load the `profiler` module with `modules load recon/profiles-profiles/profiler`.
    - Set the source username with `options set SOURCE MarkZuckerberg`.
    - Run the module with `run` to find the profile URL.

3. **Extracting Subdomains and IP Addresses**

    - Launch Recon-ng by typing `recon-ng`.
    - To extract a list of subdomains and IP addresses associated with the target URL, load the `recon/domains-hosts/hackertarget` module.
    - Type the `modules load recon/domains-hosts/hackertarget` command and press Enter.
    - Type the `options set SOURCE github.com` command and press Enter.
    - Type the `run` command and press Enter. The `recon/domains-hosts/hackertarget` module searches for a list of subdomains and IP addresses associated with the target URL and returns the list of subdomains and their IP addresses.

- This comprehensive lab demonstrates the use of Recon-ng for footprinting by extracting network and personnel information from a target domain. The generated reports provide valuable insights for ethical hackers and penetration testers.

#### Footprinting a Target using OSRFramework

- Use domainfy to check existing domains with words and nicknames.

    ```bash
    domainfy -n [Domain Name] -t all
    # Example: domainfy -n github -t all
    ```

- Use searchfy to check a user's existence on social platforms.

    ```bash
    searchfy -q "target user name or profile name"
    # Example: searchfy -q "Tim Cook"
    ```

   Results:

    ```
    Github: timothyfcook, cookieguru
    KeyserverUbuntu: tim@openparadigms.com, ahughes2005
    ...
    ```

- Use other OSRFramework packages for more information.

   - `usufy`: Gathers registered accounts with given usernames.
   - `mailfy`: Gathers information about email accounts.
   - `phonefy`: Checks for the existence of a given series of phones.
   - `entify`: Extracts entities using regular expressions from provided URLs.

#### Footprinting a Target using BillCipher

- [BillCipher](https://github.com/GitHackTools/BillCipher) is an information gathering tool for a Website or IP address. It provides various functionalities such as DNS Lookup, Whois lookup, GeolIP Lookup, Subnet Lookup, Port Scanner, Page Links, Zone Transfer, HTTP Header, etc.

- Launch the BillCipher application by typing `python3 billcipher.py` in the terminal and pressing Enter.

- In the "Are you want to collect information of website or IP address?" option, type `website` and press Enter.

- Enter the target website URL (e.g., github.com) when prompted and press Enter.

- BillCipher will display various available options for gathering information regarding the target website.

- Choose an option by typing the corresponding number (e.g., `1` for DNS Lookup) and press Enter.

- Continue selecting options and gathering information as needed. For example, you can choose GeolIP Lookup by typing `3`.

- The results will be displayed. If prompted to continue, type `Yes` and press Enter.

- Repeat the process for other information gathering options like Subnet Lookup (`4`), Page Links (`6`), HTTP Header (`8`), and Host Finder (`9`).

- You can also use Website Copier (httrack) by choosing option `19`.

- After gathering information, type `No` when asked if you want to continue to exit BillCipher.

- Open the mirrored website in Firefox by navigating to the BillCipher folder (`Places` -> `Home Folder` -> `BillCipher` -> `websource` -> `github.com`) and opening `index.html` with Firefox.

#### Footprinting a Target using OSINT Framework

- [OSINT Framework](https://osintframework.com/) is an open-source intelligence gathering framework designed for security professionals. It automates footprinting, reconnaissance, OSINT research, and intelligence gathering, focusing on free tools and resources.

- Visit [OSINT Framework](https://osintframework.com/).
- Explore the OSINT tree on the left side, categorized for various footprinting activities.
- Click on categories like Username, Email Address, or Domain Name to reveal relevant tools.
- For instance, under `Username`, explore tools like `NameCheckr` by clicking on it.
- Navigate through the tools, explore options, and observe the results.
- Similarly, explore other categories like Domain Name and Metadata, checking tools such as Domain Dossier and FOCA.
- Utilize the tools provided by OSINT Framework to gather information.

---