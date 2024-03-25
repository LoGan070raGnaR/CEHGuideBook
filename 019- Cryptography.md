# Cryptography

## Introduction

Cryptography involves the study and application of techniques to conceal meaningful information in an unreadable format. In today's information-driven landscape, ensuring the security of sensitive data during online transmissions is crucial. Cryptography, encompassing cryptographic systems, plays a vital role in securing transactions, communications, and electronic processes.

## Objective

To explore encryption techniques, including generating hashes, calculating encrypted values, employing encrypting/decrypting methods, file and data encryption, creating self-signed certificates, performing email encryption, disk encryption, and cryptanalysis.

## Types of Cryptography

- **Symmetric Encryption:** Uses the same key for both encryption and decryption.
- **Asymmetric Encryption:** Utilizes different keys for encryption and decryption, known as public and private keys.

## Methods

#### 1. Encrypt Information
- Calculate One-Way Hashes using HashCalc
- Calculate MD5 Hashes using MD5 Calculator
- Calculate MD5 Hashes using HashMyFiles
- Perform Files and Text Message Encryption using CryptoForge
- Perform File Encryption using Advanced Encryption Package
- Encrypt and Decrypt Data using BCTextEncoder

#### 2. Create a Self-Signed Certificate
- Create and Use Self-Signed Certificates

#### 3. Perform Email Encryption
- Perform Email Encryption using Rmail

#### 4. Perform Disk Encryption
- Perform Disk Encryption using VeraCrypt
- Perform Disk Encryption using BitLocker Drive Encryption
- Perform Disk Encryption using Rohos Disk Encryption

#### 5. Perform Cryptanalysis using Various Tools
- Perform Cryptanalysis using CrypTool
- Perform Cryptanalysis using AlphaPeeler

---

### 1. Encrypt Information using Various Cryptography Tools

- System administrators leverage cryptography tools to encrypt data within their network, thwarting unauthorized modifications or misuse by attackers. These tools are versatile, offering capabilities to calculate or decrypt hash functions like MD4, MD5, SHA-1, SHA-256, etc.

- Cryptography tools transform plain text into cipher text using a key or encryption scheme, rendering data into a scrambled, unreadable code. This encrypted data is then transmitted securely across private or public networks.

#### Calculate One-way Hashes using HashCalc

- Hash functions play a crucial role in computing unique fixed-size bit string representations, known as message digests. These message digests, or one-way hashes, distill the information in a file into a fixed-length number, making it nearly impossible to find another file with the same hash value. [HashCalc](https://sourceforge.net/projects/hashcalc/) is a tool that supports various hash functions, including MD2, MD4, MD5, SHA1, SHA2 (SHA256, SHA384, SHA512), RIPEMD160, PANAMA, TIGER, CRC32, ADLER32, and those used in eDonkey and eMule.

1. Open HashCalc
   - Click the Search icon on the Desktop, type HashCalc, and open the application.

2. Prepare Text File
   - Create a new text file (e.g., Test.txt) on the Desktop.
   - Write some text (e.g., Hello World !!) and save the file.

3. Calculate Hashes
   - Select File in the Data Format field.
   - Click the ellipsis icon under the Data field and open the Test.txt file.
   - Ensure MD5, SHA1, RIPEMD160, and CRC32 hash functions are selected.
   - Click Calculate.
   - Note the calculated hash values.

4. Modify Text File
   - Open Test.txt, modify the content (e.g., Modified File ...!!!), and save.

5. Verify File Integrity
   - Open a new instance of HashCalc.
   - Check the hash values of Test.txt.
   - Observe changes in the hash values, demonstrating HashCalc's role in file integrity verification.

**Conclusion:** HashCalc proves valuable in computing one-way hashes and ensuring the integrity of files by detecting changes in hash values after modifications.


#### Calculate MD5 Hashes using MD5 Calculator

- MD5, a widely used cryptographic hash function, produces a 128-bit (16-byte) fingerprint or message digest of arbitrary-length input. MD5 plays a vital role in digital signature applications, file integrity checking, password storage, and various cryptographic scenarios. MD5 Calculator is a tool designed for calculating MD5 hashes, especially useful for large files, featuring a progress counter and facilitating easy hash copying to the clipboard.

1. MD5 Calculator Interface
   - Open MD5 Calculator, click "Add Files" in the MD5 Calculator window.
   - Open the Test.txt file from the Desktop.

2. Calculate MD5 Hash
   - Click "Calculate" to obtain the MD5 hash.
   - Copy the hash value.

3. Modify File
   - Open Test.txt, modify content (e.g., Hello World...!!!), and save.

4. Verify File Integrity
   - Paste the previous hash value in "Verify MD5 Value."
   - Click "Compare" to observe hash differences.
   - MD5 hash values before and after modification differ.

Note: In real-world scenarios, hash values are shared along with files to verify integrity after transmission.

#### Calculate MD5 Hashes using HashMyFiles

- HashMyFiles is a utility enabling the calculation of MD5 and SHA1 hashes for files, supporting easy copy to clipboard or saving into various file formats. This tool provides a user-friendly interface and integrates with Windows Explorer's context menu for convenient hash calculation.

1. Adding Folder
   - Launch [HashMyFiles.exe](https://www.nirsoft.net/utils/hash_my_files.html).
   - In HashMyFiles, click on File in the menu bar.
   - Select Add Folder from the drop-down list.

2. Selecting Folder
   - In the Select Folder pop-up, navigate to [Sample Files folder](Path to Sample Files folder) (or your preferred folder).
   - Click OK to confirm the selection.

3. Viewing Hashes
   - Observe a list of files in the folder along with MD5, SHA1, CRC32, etc., hash values.

4. Customizing Displayed Hash Functions
   - Click Options in the menu bar.
   - Choose Hash Types and unselect SHA-256, SHA-512, and SHA-384.

5. Refreshing Display
   - Click the Refresh icon ( ) to view the selected hash functions.

Note: You can also use other MD5 and MD6 hash calculators such as [MD6 Hash Generator](https://www.browserling.com), [All Hash Generator](https://www.browserling.com), [MD6 Hash Generator](https://convert-tool.com), and [md5 hash calculator](https://onlinehashtools.com) to calculate MD5 and MD6 hashes.
**Conclusion:** This task provides hands-on experience in calculating MD5 hashes with HashMyFiles, emphasizing its integration with Windows Explorer and customization features.

#### Perform File and Text Message Encryption using CryptoForge

**CryptoForge Installation**

- Install [CryptoForge.exe](https://www.cryptoforge.com/download/).
- Right-click the Confidential.txt file, choose Encrypt from the context menu.

**File Encryption**

1. Enter a passphrase in the CryptoForge Files dialog-box and click OK (e.g., qwerty@1234).

2. The file will be encrypted, and the old file will be automatically deleted.

3. Assume you shared the encrypted file through a network drive.

4. On the other machine, observe the encrypted file.

5. Double-click the encrypted file to decrypt it.

6. Enter the passphrase used for encryption in the dialog-box and click OK.

7. The file will be successfully decrypted.

**Text Message Encryption**

- Search and launch CryptoForge Text from the start menu.

1. Type a message, click Encrypt, and enter a passphrase in the CryptoForge Text dialog-box (e.g., test@123).

2. Save the file as Secret Message.cfd.

3. Assume you shared the encrypted message and the decryption password.

4. On the other machine, observe the encrypted message file.

5. Double-click the file to open CryptoForge Text.

6. Click Decrypt, enter the passphrase used for encryption, and click OK.

7. The message will be decrypted and displayed.

