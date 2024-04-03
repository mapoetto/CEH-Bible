# CEH-Bible
## It takes care of you during CEH Practical journey


### Tips for scanning/enumeration:
+ Always look for response headers
+ Scan for .txt files
+ Identify what language/framework is used in the webApp. Use appropriate wordlist.
+ Using DIRB you can specify file extensions: "-X .php"

### Tips for gaining access:
+ If there is a common well-known webApp, test for default credentials

### Tips for privilege escalation:
+ Find SUID: find / -perm -u=s -type f 2>/dev/null
+ Find executables runnable as Sudo by current User: sudo -l

### Useful links while pentesting:
+ [Payloads for Common Vulnerabilities](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master).
+ [Wordlists](https://github.com/danielmiessler/SecLists)
+ [5k lines webapp Wordlist](https://github.com/Bo0oM/fuzz.txt/blob/master/fuzz.txt#L5329)
+ [Hash Identifier](https://hashes.com/en/tools/hash_identifier)
+ [Automated Privilege Escalation](https://github.com/carlospolop/PEASS-ng)
+ [Single PHP shell file](https://github.com/flozz/p0wny-shell)

### Useful links for learning:
+ [List of vulnerable Web App](https://www.theprohack.com/p/web-hacking-practice-list-of-vulnerable.html)
+ [IppSec Channel](https://www.youtube.com/@ippsec/featured)
