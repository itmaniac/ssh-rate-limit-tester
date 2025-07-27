# ssh-rate-limit-tester
Test basic ssh login via password rate limit test, other than nmap, hydra, medusa, etc for Red Team Assignments. Python3 is required.

# Usage
command: ssh-rate-limit.py -p <port_number> -uf <Username_Wordlist> -pf <Password_Wordlist> -n 1 -d 0.2 -t 4 <IP_Address>

<IP_Address>:Replace with the actual IP address or hostname of the SSH server you have permission to test.

-uf <Username_Wordlist>: Path to your username list file.

-pf <Password_Wordlist>: Path to your password list file.

-n 5: (Optional) Number of attempts for each username-password combination (defaults to 1).

-d 0.2: (Optional) Delay between each individual attempt in seconds (defaults to 0.1).

-t 4: (Optional) Connection/command timeout for each attempt in seconds (defaults to 5).

# Steps to execute:
$ chmod +x ssh-rate-limit.py

$ python3 ssh-rate-limit.py -p 22 -uf usernamelist.txt -pf passwordlist.txt -n 1 -d 0.2 -t 4 10.0.0.1

# Successful Excution Example:
Attempt 1 (User: 'root', Pass: 'webadmin', Combo Attempt: 1/1)... Authentication failed for root:webadmin in 0.28 seconds. Output: 'Warning: Permanently added '10.0.0.1' (RSA) to the list of known hosts.
root@10.0.0.1: Permission denied (password,publickey).'
