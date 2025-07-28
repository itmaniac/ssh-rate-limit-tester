# ssh-rate-limit-tester
Test basic ssh login via password rate limit test, other than nmap, hydra, medusa, etc for Red Team Assignments. Python3 is required.

# Usage
command: python3 ssh-rate-limit.py -p <port_number> -uf <Username_Wordlist> -pf <Password_Wordlist> -n 1 -d 0.2 -t 4 <IP_Address>

<IP_Address>:Replace with the actual IP address or hostname of the SSH server you have permission to test.

-uf <Username_Wordlist>: Path to your username list file.

-pf <Password_Wordlist>: Path to your password list file.

-n 5: (Optional) Number of attempts for each username-password combination (defaults to 1).

-d 0.2: (Optional) Delay between each individual attempt in seconds (defaults to 0.1).

-t 4: (Optional) Connection/command timeout for each attempt in seconds (defaults to 5).

# Steps to execute:
To install Python 3 on Ubuntu, Kali, etc the basic command is:

$ sudo apt update

$ sudo apt install python3

Downloading & Changing file Permission:

$ git clone https://github.com/itmaniac/ssh-rate-limit-tester.git

$ cd ssh-rate-limit-tester

$ chmod +x ssh-rate-limit.py

SSH Rate Limit Test:

$ python3 ssh-rate-limit.py -p 22 -uf usernamelist.txt -pf passwordlist.txt -n 1 -d 0.2 -t 4 10.0.0.1

# Successful Execution Results:
Attempt 1 (User: 'root', Pass: 'webadmin', Combo Attempt: 1/1)... Authentication failed for root:webadmin in 0.28 seconds. Output: 'Warning: Permanently added '10.0.0.1' (RSA) to the list of known hosts.
root@10.0.0.1: Permission denied (password,publickey).'

# VirusTotal Scan Results:

<img width="1599" height="244" alt="image" src="https://github.com/user-attachments/assets/dd167a43-46ab-4463-9c1d-485ebaf6c616" />

# DISCLAIMER: 
This script is provided for EDUCATIONAL and LEGAL PENETRATION TESTING PURPOSES ONLY. 
The author does not condone or support any illegal or unauthorized use of this tool.

USAGE CONDITIONS:
1. You must have EXPLICIT WRITTEN PERMISSION from the system owner before testing any SSH service
2. Use only on systems you own or are legally authorized to test
3. Comply with all applicable local, national, and international laws
4. Never use this tool against production systems without proper authorization
5. Any credentials used must be test accounts or dummy credentials

By using this script, you agree that:
- You are solely responsible for any consequences of its use
- The author bears no liability for misuse or damages
- You will not use this tool for any malicious purposes

This tool simulates brute-force attempts and may trigger security alerts or account lockouts.
Use with caution and proper authorization at all times.
