# Social Engineering

## Introduction

- Social engineering is the art of manipulating individuals to divulge sensitive information, posing a significant threat to organizations.

- Despite robust security measures, organizations often fall victim to social engineering tactics. Cybercriminals exploit employees, the weakest link in information security.

## Objective
The objective is to employ social engineering techniques to:
- Sniff user/employee credentials
- Obtain personal details and organizational information
- Acquire usernames and passwords
- Perform and detect phishing attacks

## Social Engineering Overview

- Social engineering exploits human weakness to extract sensitive information, making even well-protected organizations susceptible. Impact includes economic losses, damage to goodwill, privacy loss, terrorism risks, lawsuits, and closures.

- Organizations may be vulnerable due to:
    - Insufficient security training
    - Unregulated access to information
    - Complex organizational structure
    - Non-existent or inadequate security policies

## Methods

#### 1. Perform Social Engineering
- Utilize social-engineering toolkit to sniff user credentials.

#### 2. Detect Phishing Attack
- Detect phishing using Netcraft.
- Detect phishing using PhishTank.

#### 3. Audit Organization's Security
- Audit organization's security against phishing attacks using OhPhish.

---

### 1. Perform Social Engineering Using Various Techniques

- Social engineering techniques exploit human, computer, or mobile vulnerabilities to gather sensitive information for fraudulent activities.

- As an ethical hacker or penetration tester, you aim to evaluate an organization's defenses by employing various social engineering techniques. This involves tricking users into divulging personal or confidential information, simulating real-world attacks.

**Overview of Social Engineering Techniques:**

- Social engineering attacks can be categorized into three types:
1. **Human-Based:** Utilizes human interaction for gathering sensitive information, including impersonation, vishing, and eavesdropping.
2. **Computer-Based:** Utilizes computers for extracting sensitive information, including phishing, spamming, and instant messaging.
3. **Mobile-Based:** Utilizes mobile applications for information extraction, including publishing malicious apps, repackaging legitimate apps, fake security applications, and SMiShing (SMS Phishing).

---

#### Sniff Credentials using the Social-Engineer Toolkit (SET)

- The Social-Engineer Toolkit (SET) is a potent open-source Python-driven tool designed for penetration testing through social engineering. It enables various attacks, including spear phishing, by crafting email messages with malicious attachments.

##### Steps

- Open the terminal and launch SET by typing `setoolkit`.
- Choose 'Social-Engineering Attacks,' then 'Website Attack Vectors,' and finally 'Credential Harvester Attack Method.'
- Select 'Site Cloner' and provide the IP address (10.10.1.13) and a target URL (e.g., http://github.com).
- Follow the prompts, and SET will clone the website for phishing.
- Compose a phishing email with a link to the cloned site.
- Send the email to a victim, attempting to trick them into clicking the malicious link.
- Once the victim interacts with the link, their credentials are harvested.
- Review the harvested credentials in the SET terminal.

---

#### Detect Phishing using PhishTank

- PhishTank serves as a free community platform for submitting, verifying, tracking, and sharing phishing data. Here, we can use PhishTank to detect phishing activities, emphasizing its role as a collaborative hub for anti-phishing information.

## Steps

- Launch PhishTank Website:
    - Visit [PhishTank](https://www.phishtank.com).

- Explore Recent Submissions:
    - Review the list of phishing websites under Recent Submissions.
    - Click on a phishing website ID to view detailed information.

- Verify Phishing Status:
    - Check if the site is flagged as a phish.
    - Navigate back to the PhishTank home page.

- Check Another Website:
    - In the "Found a phishing site?" text field, type a URL (e.g., be-ride.ru/confirm).
    - Click "Is it a phish?" button.

- Verify Result:
    - Confirm the phishing status of the entered website.
    
**Note:**

- PhishTank provides information on whether a submitted website is identified as a phishing site.
- Users can actively contribute by verifying and submitting suspected phishing sites.

---