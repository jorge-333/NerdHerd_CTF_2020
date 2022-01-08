# NerdHerd_CTF_2020

IFT475 Security Analysis
Capture The Flag - Assessment Report

## Table of Contents
1. [Executive Summary](#Executive-Summary)
	* [Assessment Overview](#Assessment-Overview)
	* [Attack Summary](#Attack-Summary)
2. [Attack Narrative](#Attack-Narrative)
	* [Reconnaissance](#Reconnaissance)
		* [Discovery](#Discovery)
	* [Enumeration](#Enumeration)
		* [Scanning](#Scanning)
		* [Vulnerability Assessment](#Vulnerability-Assessment)
	* [Exploitation](#Exploitation)
		* [Generate Reverse Shell Payload](#Generate-Reverse-Shell-Payload)
		* [Generate Event Listener](#Generate-Event_Listener)
		* [Attack in Action](#Attack-in-Action)
		* [Data Identification](#Data-Identification)
3. [Vulnerability Ratings](#Vulnerability-Ratings)
4. [Conclusion](#Conclusion)
5. [References](#Reference)

## Executive Summary
### Assessment Overview
This Assessment is for the NerdHerd Network, which was approached from the position of a malicious attacker infiltrating the NerdHerd CTF Networ, by leveraging a series of high to critical level vulnerabilities. I was able to gain a foothold into the network and gain access to sensitive organizational information /(Flag). Through this assessment I was able to evaluate the posture of the network security and identify a series of vulnerabilities that should be resolved as soon as possible.

This security assessment is built on a four-stage process that includes the following steps:

1.	Reconnaissance – In this stage we understand the goals of the assessment and the rules of engagement. We also blueprint the network and focus on discovering live host.

2.	Enumeration – In this stage we identify potential vulnerabilities and the different ways to exploit them.

3.	Exploitation – Confirm potential vulnerabilities through exploitation and perform additional discovery upon new access. 

4.	Reporting – Document all found vulnerabilities, exploits, and failed attempts

All of the tests performed are in accordance with the NIST SP 800-115 Technical Guide. 
### Attack Summary
This assessment took place on December 3rd, 2020 and it started with some basic reconnaissance work of the internal network. The results provided me with the IP address of a specific host on the network, which was then established to be the target of this assessment.

After the initial discovery of my target, a few different scans were run to enumerate what ports, services, OS versions, and vulnerabilities were present on the target. The results of this scans allowed me to identify some medium to critical level vulnerabilities in those services. Specifically, there was an outdated version of SMB running, which I was able to leverage to gain system access and full system privileges. 

Once the target was compromised the contents of the SAM database was captured. I also discovered a sensitive Database backup file with a list of user hashes. I was unable to crack the hash file, but this information under the wrong hands with the right tools could potentially gain the credentials of a user list. 

## Attack Narrative
### Reconnaissance
Tools Used: ARP-scan
#### Discovery
I first attempted to identify the host that were up and running, so the scope of the attack could be established. To do this I joined the Zero-tier network and ran the ARP-scan tool to find out what devices were live in the local subnet. This scan populated a list of the IP-Addresses in that subnet allowing me to pinpoint the target (Figure 1).

 
Figure 1 - ARP-scan reveals live host in local subnet.
### Enumeration
Tools Used: Nmap, Nessus
#### Scanning
After discovering the target’s address, I ran an Nmap scan to better understand the machine I was dealing with. This scan enumerated what ports, services, and OS versions were up and running (Figure 2). 

 
Figure 2 - Nmap Scan
#### Vulnerability Assessment
After gaining a better understanding of the target. A vulnerability scan was done to determine what vulnerabilities would be found for the services running on the target. 

This was done by running a Nessus Vulnerability Scan (Figure 3). 

 
Figure 3 - Nessus Scan

Once Nessus finished running, I analyzed the report which showed a few different vulnerabilities that can be leveraged to gain access. But, after further review I decided to focus on the unpatched SMB service running on the machine that requires no sign on.

SMB services have been known to have had a fair number of issues in the pass. I looked further into the SMB vulnerability by running an Nmap vulnerability script. 

The command below was used to run the SMB vulnerability scripts targeting port 139 and 445.
•	nmap -v -script smb-vuln* -p 139,445 10.242.111.189

 
Figure 4 - Nmap Vulnerability Scan

After analysis of the results from both scans, I decided that the SMB services running on the host was the best path to gain a foothold into the system. From the vulnerability reports I was able to determine that the system is vulnerable to the MS17-010 exploit which also doesn’t require SMB signing. This makes an exploit possible over SMB services. There is a well know exploit released in the Shadow Brokers NSA tool Disclosure that is called Eternal Blue. This exploit is known to exploit Microsoft’s implementation of the Server Message Block (SMB) protocol by sending a payload that allows the attacker to execute arbitrary code on the clients’ machine, giving access to the attacker.  
### Exploitation
Tools Used: AutoBlue-MS17-010, Metasploit

After some research and a few different attempts at exploiting this specific vulnerability, I was able to successfully gain access by utilizing the AutoBlue-MS17-010 exploit written by 3ndG4me. 

#### Generate Reverse Shell Payload
To generate a reverse shell payload, I ran the shell preparation script that came with the exploit. Following the prompts, I set the listening host and ports. Then I choose the type of shell and payload. (Figure 5)

•	Reverse Shell with msfvenom
•	LHOST to 10.242.63.69.
•	LPORT x64 to 4444
•	LPORT x86 to 4445
•	Meterpreter shell 
•	Staged Payload

 
Figure 5 - Reverse Shell Payload

After running the script and following the prompt, a shellcode binary file named sc_all.bin is created. This executable is what I’m going to be using to execute the targets machine to gain access to it through meterpreter.

#### Generate Event Listener
Then I setup the event listener which handles and listens to all incoming connections on my machine. To do this I ran the listener preparation script that came with the exploit and followed the prompts to set the listening host, listening ports, shell type, and payload type. (Figure 6)

•	LHOST to 10.242.63.69.
•	LPORT x64 to 4444
•	LPORT x86 to 4445
•	Meterpreter shell 
•	Staged Payload

 
Figure 6 - Event Listener

#### Attack in Action
After creating my executable and setting up the listener, it is now time to exploit the target. At this point I ran the eternal blue exploit (Figure 7) and we can see that the event listener picked up the connection and a session was established (Figure 8).

 
Figure 7 - MS17-010 Exploit

 
Figure 8 - Meterpreter Session Opened

I connected to the session that I established and begin to engage the system through meterpreter.  I ran the `getuid` command to determine if we needed to escalate privileges, but we have SYSTEM (Figure 9). 

 
Figure 9 - Meterpreter Session

#### Data Identification
I began to investigate the system for important organizational data that could be used against the company if there was a breach. First, I use the `hashdump` command to get the contents of the SAM database (Figure 10). The raw LANMAN/NTLM hashes can then be ran against a tool like John the Ripper to see if we can obtain login credentials.

 
Figure 10 - Hashdump

In search for more information, I used the `shell` command to open a standard shell on the targeted system. Once the shell was created, I navigated around the different directories in search for any sensitive organizational data. In doing this, I found the John Doe Desktop Directory with a file named `DB backup users.txt` (Figure 11). I downloaded and opened the file to find a list of different users’ hashes (Figure 12).

 
Figure 11 - Users Hash Text

 
Figure 12 - Hashes from the DB Backup users.txt

The information in this user’s backup file could be extremely sensitive and should not be sitting in the desktop folder where it was easily accessible. With this type of information, a password cracking attack can be utilized to gain login credentials for all or some of these individuals. The usernames can also be used to build a wordlist or find if they are part of any breach credentials that are currently exposed. 





### Vulnerability Ratings 





### Conclusion

In conclusion, a series of medium to critical level vulnerabilities were found while running this assessment. I was able to compromise the client’s system by leveraging the Eternal Blue exploit that took advantage of an unpatched version of SMB running on the targets OS. It is critical that this vulnerabilities and misconfigurations are fixed and patched as soon as possible. Doing this will improve the systems security posture, helping it prevent any future security breaches.  



### References


Casey Erdman, AutoBlue-MS17-010, (2017), GitHub repository, 
https://github.com/3ndG4me/AutoBlue-MS17-010 

Penetration Test Report. (2013, August 10). Retrieved from 
https://www.offensive-security.com/reports/sample-penetration-testing-report.pdf

MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption. (2018, May 30). Retrieved December 11, 2020, from
https://www.rapid7.com/db/modules/exploit/windows/smb/ms17_010_eternalblue/

Nessus Research. (2020, June 09). Retrieved December 11, 2020, from https://www.tenable.com/research




