# CEH-Bible
## It takes care of you during CEH Practical journey


### Tips for scanning/enumeration:
+ namp -sV HOST |Explaination: -sV: Probe open ports to determine service/version info
+ nmap -sCV HOST |Explaination: -sC: equivalent to --script=default
+ nmap -sV -script=vulners.nse HOST |Explaination: search for vulnerabilities
+ nmap -p- --min-rate=1000 -sV -sC -T4 HOST |Explaination: scan for all ports, with a min Packet ratio to send (to speed up), with an aggressive time (T4)
+ sudo nmap -sU -sV -sC IP |Explaination: perform an UDP scan, requires more time.
+ Always look for response headers
+ Enumerate subdomains (you can use gobuster)
+ If there is a DNS server, use it to search for domains. You can use DIG:
    +  DNS Reverse: dig @DNS_SERVER_IP -x IP_TO_REVERSE
    +  TRANSFER ZONE CHECK (you can guess a domain to check if it exists): dig axfr @DNS_SERVER_IP guesseddomain
+ Scan for .txt files
+ Don't forget to scan every dir you found
+ Don't forget to scan every API endpoint you found. Use different HTTP Methods too.
+ Identify what language/framework is used in the webApp. Use appropriate wordlist.
+ Using DIRB you can specify file extensions: "-X .php"
+ If you found an LFI or an Arbitrary File Read Vulnerability, you could read file: "../../../../../proc/self/environ" (same level of /etc/passwd) to read Enviroment Variables of the current process (there could be some sensitive information exposure)
+ Look for XSS, they could be used to reveal sensitive information by Server side

### Tips for Arbitrary File Read
+ Search for Vulnerable library used
+ Search for any unsecure deserialization
+ NodeJS:
 + index.js
 + server.js
 + main.js 

### Tips for 401-403 Error Bypass
[Full article](https://blog.vidocsecurity.com/blog/401-and-403-bypass-how-to-do-it-right/)
+ Change HTTP Method:
  + GET
  + HEAD
  + POST
  + PUT
  + DELETE
  + CONNECT
  + OPTIONS
  + TRACE
  + PATCH
  + FOO # non existant method also might work
+ User-Agent fuzzing
+ HTTP Headers fuzzing
+ Path Fuzzing and creative string literals.
  + /../
  + /...
  + /..%00
  + /..%01
  + /..%0a
  + /..%0d
  + /..%09
  + /~root
  + /~admin
  + /%20/
  + /%2e%2e/
  + /%252e%252e/
  + /%c0%af/
  + /%e0%80%af
+ Downgrade the protocol version.
+ HTTP request smuggling  

### Tips for API Testing:
+ Use different HTTP Methods
+ Even if API is REST (Content-Type: application/json), it could accept non-JSON payloads (Content-Type: application/x-www-form-urlencoded)
+ https://jwt.io/  Will help to craft and analyze tokens

### Tips for injection/fuzzing:
+ Changing the order of parameters could lead to a restriction bypass
+ Encode your payload
+ A form could handle dirrent type of requests. Try: Content-Type: application/json , Content-Type: application/x-www-form-urlencoded
+ Don't try only SQL injection, Try also NoSQL

### Tips for gaining access:
+ If there is a common well-known webApp, test for default credentials

### Tips for privilege escalation:
+ Find SUID: find / -perm -u=s -type f 2>/dev/null
+ Find executables runnable as Sudo by current User: sudo -l
  If there are any, check for their version and their CVE/exploits
  If they use relative paths, $PATH could be modified in order to execute a new file created by us.
+ Look for sensitive informations:
    + Search Files owned by the user: find / -uid UID -type f -ls 2>/dev/null | grep -v "/proc*"
    + Search Files with the name of the user in it: find / -name "*USER*" -type f -ls 2>/dev/null
    + Search Files with the word password in the home directory: grep -i password -R .
+ Look for process execution. Probably there could be some process running as root, and they could be exploitable: ps -ef --forest

### Tips for windows:
+ evil-winrm is a program to interact with RPC windows and other protocols

### Tips for Android
+ [PhoneSploit](https://github.com/AzeemIdrisi/PhoneSploit-Pro)

### Useful links while pentesting:
+ [Payloads for Common Vulnerabilities](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master).
+ [Wordlists](https://github.com/danielmiessler/SecLists)
+ [5k lines webapp Wordlist](https://github.com/Bo0oM/fuzz.txt/blob/master/fuzz.txt#L5329)
+ [Hash Identifier](https://hashes.com/en/tools/hash_identifier)
+ [Automated Privilege Escalation](https://github.com/carlospolop/PEASS-ng)
+ [Single PHP shell file](https://github.com/flozz/p0wny-shell)
+ [Reverse Shell Generator](https://www.revshells.com/)
+ [Useful Commands](https://github.com/xaferima/Certified-Ethical-Hacking-Practical-Tools/blob/main/Commands-4-tools-used)
+ [VERY GOOD TOOLS EXPLAINATION divided by CyberKill Chain phases](https://book.thegurusec.com/certifications/certified-ethical-hacker-practical/reconnaissance-footprinting)
  
### Useful links for learning:
+ [List of vulnerable Web App](https://www.theprohack.com/p/web-hacking-practice-list-of-vulnerable.html)
+ [IppSec Channel](https://www.youtube.com/@ippsec/featured)
+ [CEH Master Guide](https://github.com/CyberSecurityUP/Guide-CEH-Practical-Master)
