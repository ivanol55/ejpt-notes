# eJPT exam notes
----

## Introduction
## Penetration testing phases
### Information gathering
- the first and one of the most important phases of the process
- helps understanding attack surface, scope, target enumeration and have efficient targeted attacks
- check everything you can find
- information gathering helps you throw your darts to the correct targets with more precision for high value, high focus attacks
- information gathering is a cyclic process, meaning once you get access to new targets, add their information to your list

#### open source intelligence
- gather information open to the public that can help in an attack
- use social networks, public sites, company websites
- humans are the weakest link in security
- people's personal security posture can be a good entrypoint
- use this information to target and scope future attacks
- helps with phishing, impersonation, technical mapping, and tech stack identification
- Search on the most suitable places, like Instagram for advertising companies
- Connect different social networks to link missing data together
- LinkedIn can tell you who a company is working with to extend your information gathering
- Whois database information needs to be real and current, which can tell you someone's email, street address, technical contact, or full name of the person that owns the domain
- corporate websites usually have information about high value targets like executives
- knowing more about your target makes your future attack easier and more effective
- a couple of these leaks can lead you to discover patterns, like the use of name.surname@company.com as their email format

#### Subdomain enumeration
- widen the attack surface by finding any possible hidden sites or services on its main domain or doomains
- these subdomains may contain outdated applications, buggy exposed software or unsecured administrator interfaces you can exploit
- forgotten exposed resources are a very strong attack vector
- passive enumeration lets you explore existing subdomains without interacting with the target
- use search engines to look for unintentionally indexed resources by using `site: company.com` as a search query
- use sites that automate this discovery, like [dnsdumpster.com](https://dnsdumpster.com/)
- use local tools installed on your pentesting toolset, like `sublist3r`, although it is easily blocked by search engines like Google due to bot detection
- search for generated certificates and alternative names using [crt.sh](https://crt.sh/)

### Footprinting and scanning
#### Mapping a network
- after identifying the named targets we proceed to identify the network nodes running the system
- either local or remote networks need to be identified properly
- start by determining what hosts are up and running on the target scoped network
- **ping sweeping** will help identify running nodes on that often very large network range
- use tools like `fping` to scan the networks, like for example `fping -a -g 10.0.5.0/24`, or with a start and end address like `fping -a -g 10.0.5.4 10.0.5.57`
- supress the `Host unreachable` errors by piping `stderr` to `/dev/null`
- tools like `nmap` are the gold standard for advanced host discovery
- `nmap` supports plain ping scanning, like `nmap -sn 192.168.0.0/24`
- you can also use a file with IP's: `nmap -sn -iL ip-list.txt` by adding one IP or range per line
- other host discovery techniques are supported, like TCP connection requests, or UDP packet probes
- this will provide you with a narrowed down list of live hosts to which you can target your attacks towards

#### OS fingerprinting
- to get further information about the target hosts use OS fingerprinting
- send specific requests to live systems and analyze the responses
- after this you'll have a list of every live system on the network and what OS it might be running
- active fingerprinting can be done using `nmap`
- use the `-O` flag to try and identify what a target exactly is, like `nmap -Pn -O 192.168.1.99` (`-Pn` skips ping probing, as you have already confirmed the host is up)
- fine-tune and target your fingerprinting to get reliable target information

#### Port scanning
- once we know what nodes are available, we need to know what is in each of them
- check for open ports on the nodes and their associated services
- check for the software versions of the program running on that port, it will be helpful for exploitation
- create a list of what services are on each machine and what you can take advantadge from on them
- port scanners like `nmap` automate service identification and perform useful tasks like firewall checks
- port scanners identify open, closed and firewall-filtered ports by checking for behavior of the TCP/IP standard, like getting back an ACK or RST
- TCP scans are noisy on logs, so we can also use SYN scans, which analyzes the response but doesn't connect to the target

#### nmap
- all these tasks can be handled with nmap with the flags `-sT` (TCP connect scan), `-sS` (TCP SYN scan), or `-sV` (version detection scan)
- version detection scans work by parsing the `banner` sent back by an application
- if no banner gets back, `nmap` will send back different kinds of probes to try and guess the program listening on the port
- if you are positive pings are blocked and a machine is up, you can use the `-Pn` flag to force scanning without ping-sweeping the machine
- you can identify running hosts that have no ping response by scanning usually open ports like `80`, `443`, `22`, `25`, `8080` or `445`
- be prepared for firewall reconaissance, which can ge recognized with anomalous `nmap` results, like unidentifiable banner responses for versions or a `tcpwrapped` response on a well-known port
- the `--reason` flag on `nmap` will give you more information about why it thinks a port is closed
- remember to **scan ports higher than 1024** with the `-p` flag, some higher ports could be hiding important services and the default `nmap``scan only goes up to port 4096
- the `nmap` toolset has useful tools for information gathering with the `--script` flag, like `mongodb-info` to get information from a mongodb instance, `vuln` to scan a service for potential CVE's, or `mysql-*` to run all mysql scripts against an open mysql install

#### masscan
- `nmap` is a powerful but stealthy and slow tool
- `masscan` can be used to scan large networks very quickly, but at the cost of accuracy
- try performing host discovery with `masscan`, then get some details with `nmap`

### Vulnerability assessment
#### Vulnerability scanning and assessment
- sometimes a client only needs a vulnerability assessment rather than a penetration test
- we need to provide the know-how to fit the needs of the client to solve their problem
- a vulnerability scan is faster and has a lighter load on the infrastructure
- in this scenario you do not proceed to the exploitation phase
- for this task, specialized tools are used, **vulnerability scanners**
- these tools use a suite of integrated checks to automatically identify vulnerabilities, like port scanning, software version checks, common exploit testing, configuration file validation, windows registry entries
- the purpose is to find vulnerabilities and misconfigurations on the infrastructure
- the software is kept up to date with vulnerability database information as needed
- the more up to date the software is, the better
- examples are `OpenVAS`, `Nexpose` or `Nessus`
- if you need to test custom applications, a vulnerability scanner may not be enough and you will need to check for vulnerabilities manually through the code or through manual testing, depending on your scenario

#### Under the hood of vulnerability scanners
- vulnerability scanners like `Nessus` tend to work in a client-server setup which provide a web UI to configure and run scans
- the tools work by sending probes and scans to target machines and processing the results into actionable data
- steps are similar to the manual vulnerability scanning of a machine: first it checks if it's up and running, identifies what it's running and what ports it has open, and what potential vulnerabilities that software has
- it identifies these vulnerabilities by checking for the software versions against a vulnerability database
- the scanner checks if the vulnerability actually exists on the target system, a step that can be prone to false positives depending on the tests that it runs

### Web attacks
#### Manual web server fingerprinting
- web applications make up the vast majority of the internet-facing attack surface
- these applications run behind web servers, so knowing about this software is vital
- web server security tends to be overlooked, making it a good attack fector for penetration testers
- start by fingerprinting, find out exactly what web server is running the application
- find out the software distribution (`apache`, `nginx`, `iis`), its version, and the OS that's running underneath
- this fingerprinting can be manually done using `netcatp`, with a technique named *banner grabbing* by connecting to the target server and seeing what the server sends back
- connect with `netcat [target IP] [target port]` and send a HEAD HTTP request, like `HEAD / HTTP/1.0`
- the `Server:` response block will have the banner information you need
- `netcat` only support HTTP, not HTTPS. To connect to a server only accepting HTTPS, use `openssl s_client -connect [target IP]:[target TLS port]`
- system administrators can modify the banners to confuse you to make banner grabbing harder

#### Automated web server fingerprinting
- to avoid depending on banners alone, use more sophisticated and automated tools
- these tools are harder to trick by system administrators with banner modification
- a good tool to keep in mind is `httprint`, which will use signature-based techniques to identify webservers
- use it for example like `httprint -P0 -h [target host] -s /usr/share/httprint/signatures.txt`

#### HTTP verbs
- HTTP verbs are the actions a client or server are capable of performing in an exchange, like `HEAD`, `GET`, `PUT` or `POST`
- `GET` allows passing arguments through the URL into the webserver using the headers
- `POST` is used to submit form data, which has to be in the message body
- `HEAD` is similar to `GET`, but will only request the headers without the body to save on data transfer
- `PUT` is used to upload files into servers, very dangerous if  misconfigured to be vulnerable
- `DELETE` is used to delete files from servers, another dangerous directive if misconfigured
- `OPTIONS` can be used to see what HTTP verbs a server allows, which can vary depending on the queried hostname
- `REST API`s are a specific type of web application that rely heavily on all HTTP verbs
- they are used to retrieve and handle data through a web endpoint, like saving data to a database using `PUT`
- always verify if an endpoints accepting certain HTTP verbs are really vulnerable or they are working as intended, like verifying if the file you `PUT` actually exists
- to try exploiting HTTP endpoints, first enumerate what HTTP verbs are available
- to exploit delete you can just send a query with the file you want to delete using `netcat` or `openssl`, like `DELETE /path/to/resource.txt HTTP/1.0`
- to exploit `PUT`, first check the file size of your payload with `wc -m payload.php`, then use that size when sending the file into the web server, in this example sending a 20 character script:
```
$ netcat victim.site 80
PUT /payload.php HTTP/1.0
Content-type: text/html
Content-length: 20

<?php phpinfo(); ?>
```

#### Directories and file enumeration
- some sites or directories may be purposefully unindexed from search engines
- these directories usually hide useful information
- even if hidden from indexers, they will still be available to access
- these could contain new and untested features, backup files, testing information, developer notes... useful information for attacking
- this can give you access to sensitive information like backend database addresses, backup locations, feature test credentials and more
- use tools to enumerate or brute-force finding these hidden locations
- brute-forcing is very inefficient, time-consuming and noisy and should only be used as a last resort
- by knowing the common names for useful directories we can optimize our search
- search for common file extensions like `.old`, `.bak`, `.txt`
- the most common tool for this task is `dirbuster`, a java application for enumerating web resources
- set a target, set your dictionary and let `dirbuster` discover information for you
- a command-line alternative is `dirb`, you can run it with just `dirb [target URL]`

#### Google hacking
- active information gathering can be a log-noisy process
- use search engines to perform passive information collection and find hidden but indexed resources
- use [advanced search engine features](https://developers.google.com/custom-search/docs/xml_results) like searching for file extensions or searching for parameters inside of a URL or title
- combine advanced expressions to find exactly what you need
- some [pre-created searches](https://www.exploit-db.com/google-hacking-database) can give you a head start

#### Cross-site scripting
- this type of vulnerability lets an attacker take over control of some content on a web application
- targets the web application users
- allows modifying the site content at runtime
- injects malicious content that can steal private information, like the user session cookie for impersonation
- exists when the application uses unfiltered user input to buiild the application's output, like request headers, cookies, form inputs, and GET or POST parameters
- you can craft output HTML and JavaScript code to attack other application users
- this attack is hard to spot, as it is usually stealthy and runs on the background
- user impersonation, depending on the user, can lead to a complete site takeover
- to search for cross-site scripting opportunities, look for submitted parameters that appear on the page
- usually vulnerable elements are comments, user profiles, and forum posts
- test first by injecting harmless values, like `i` or `pre` html tags to see if they are executed
- these attacks can be *reflected* (sent with the request, like the example above, by posting a link on social media that executes the crafted request), *persistent* (stored on the web server that is run when a user loads the page) or *DOM-based*
- use automated tools to check for these attacks, like `xsser`: `xsser --url '[potentially vulnerable site]' -p '[parameters to send into the request]'`
- xsser can even automatically test for common exploits: `xsser --url '[potentially vulnerable site]' -p '[parameters to send into the request]' --auto`
- Or try sending a custom crafted payload: `xsser --url '[potentially vulnerable site]' -p '[parameters to send into the request]' --Fp "<script>alert(1)</script>"` 
- these are `POST` requests for forms. If the vulnerable target is a `GET` request, just remove the `-p` flag and pass the entire url to the `--url` flag

#### SQL Injections
- most web applications use some kind of backend database to store their data
- applications interact with backends using `SQL` queries
- SQL injection attacks allow us to access data on the backend using especially crafted application requests
- usually you need to connect to a database and authenticate to access data, but web applications already have authentication built-in to query data
- we can use parameter-dependant web application endpoints, like a product listing or a search, to add in our especially crafted SQL statement and access data
- several attack types exist, like comparation attacks that add `OR 'a' = 'a'`, or `UNION` statements to add a second query, which allows us to query any data we want
- to perform SQL injection we need to find a vulnerable endpoint, we should check all supplied user inputs on the site, like `GET` or `POST` HTTP request parameters, or HTTP Headers
- keep in mind not only `SELECT` statements are available, but any action that could be performed by the user, like deleting the database, is available to the executing user
- especially crafting SQL injections is hard, we can use automated tools to find vulnerable endpoints, like `sqlmap`
- the tool's syntax is simple: `sqlmap -u [target URL] -p [injectable parameter] [extra options]`
- This defaults to `GET` requests, you can send a `POST` instead by using `--data=[POST data]`

### System attacks
#### Malware and backdoors 
- software used to misuse a computer system to cause a denial of service, spy on users or get unauthorized control over systems
- usually used by cybercriminals
- can be sometimes used in a cybersecurity engagement
- classified based on its behavior
- very useful kinds of malware tools are backdoors, which allow you to stealthily connect to the target once it's infected
- connecting in reverse (from the target to the pentester's machine) will avoid firewall blocks and raise less alarms
- rootkits allow attackers to get privileged access to system resources
- bootkits circumvent OS protection by running during the bootstrap phase before the system can protect itself

#### Password attacks
- passwords are usually the only security mesure in exposed services like a web application or a vulnerable remote instance
- passwords are usually stored in files or databases, which if stored in cleartext can be very useful for exploitation and access
- even if hashed or encrypted, sometimes passwords can be cracked, ro restored to cleartext by brute-forcing them
- it's a process of guessing all combination until the matching one is found
- we can also use dictionary attacks with probable or weak largely used passwords
- automated tools exist to make the process faster, like `john the ripper` provided a list of hashes, it is an extremely fast tool thanks to the heavy use of parallelization
- we convert the hashes and users into a format `john` understands, like using `unshadow` to merge `/etc/passwd` and `/etc/shadow` and pass it into the tool to try to crack passwords
- view the results with `john --show [original hash file]`
- we can also provide a caracking wordlist for a dictionary attack with the `--wordlist` flag
- to detect variations like `p@ssw0rd` use dictionary mangling, enabled with the `--rules` flag

#### Buffer overflow attacks
- many exploits available leverage a buffer overflow vulnerability in software
- this attack writes commands outside of its memory bounds to change application behavior
- this allows an attacker to write arbitrary code into the computer's RAM
- writing buffer overflow attacks requires deep knowledge of comupting and applications
- we can use already developed exploits through the `metasploit framework` covered at the end of this course

### Network attacks
#### Authentication cracking 
- sometimes you don't have access to password hashes
- performing pure network brute-force attacks is slow and inefficient because of the communication time it takes to test remote authentication
- because of this, network-based password guessing relies on dictionary attacks
- most tools use a list of default usernames and easy passwords
- you can install password lists on kali with the `seclists` package, which will add the lists to `/usr/share/seclists/Passwords/`
- various tools can be leveraged to automate authentication cracking, the most frequent being `hydra`, which includes many modules to automatically try to crack different protocols
- choose the module with the -U flag, like `hydra -U rdp` to try cracking RDP credentials
- basic usage goes as `hydra -L [user list] -P [password list] [service]://[target server] [options]` (the `service` format replaces the `-U` flag)
- you can also use other tools, like `nmap`'s ssh bruteforce script: `nmap -p [ssh socket port] --script ssh-brute --script-args userdb=[user list file] [target]`
- there's a metasploit module too, `auxiliary/scanner/ssh/ssh_login`, it's useful to try to crack root user access by setting `USERPASS_FILE` to `/usr/share/wordlists/metasploit/root_userpass.txt`, but remember to set `verbose` to `true` and `STOP_ON_SUCCESS` to `true`
- an example on using local hashes to crack passwords with `john the ripper` is `john [hash file] --wordlist=[wordlist]`, and usually you pass in the `seclists` package wordlist
- several tools are available to convert almost any hash file to `john`-consumable format as python scripts under `/usr/share/john/`

#### Windows shares
- Windows is one of the most used desktop operating systems especially on enterprise networks
- a pentester needs to be able to exploit its vulnerabilities
- tends to be used for authentication, file sharing and printer management
- resource sharing on these environments are based on `NetBIOS`
- when a computer gets a `NetBIOS` query it can answet with its hostname, NetBIOS name, Domain and network shares
- these shares can be very dangerous when used improperly
- there are also some special administrative shares for Windows administrators to access drives or windows installation directories
- a historical vulnerability leveraging windows shares is called `null session`

#### Null sessions
- used to enumerate information about passwords, system users, system groups and running system processes
- `null sessions` are remotely exploitable
- modern systems are not vulnerable to null session attacks, but legacy installations are still an important attack vector
- this attack lets us connect to an Administrative share without the need of authentication
- first step is share enumeration. we can use some built-in tools, like `nbstat` on windows (`nbstat -A [target host]`) to identify if the target has any network shares and `NET VIEW [target host]` to view its available network shares
- on Linux we'll use the `samba` tool suite, following the same steps as before, displaying network share availability with `nmblookup -A [target host]` and looking at available shares with `smbclient -L //[target host] -N`, with the perk that this tool also displays the administrative shares
- once we know the target has these shares, we can use a null session attack to access the administrative shares on it, with `NET USE \\[target host]\[administrative share] '' /u:''` on windows, or `smbclient //[target host]/[administrative share] -N` on linux
- keep in mind this only works with the `IPC$` administrative share, not the drive access share
- this task can be automated with tools like `enum` on windows (`enum -S [target host]` to enumerate shares, `-U` to enumerate users, `-P` to attempt an attack), or `enum4linux` on the linux side, with the same usage as the `enum` windows tool, plus more features
- get target info with `enum4linux -n [target host]`, then list shares on the host with `enum4linux -S [target host]`. you can then access the files with `smbclient //[target host]/[share] -N`
- navigate the samba share with `cd [directory]`, download files with `get [file]`
- an alternative tool is `smbmap`, very simple to use to enumerate: `smbmap -H [target host]`
- try all shares, even if they don't report as public. Sometimes null sessions will just log you in!
- combine `smbmap -H` and `enum4linux -U`, as some users may have non-discoverable shares you're missing
- some shares may need bruteforcing from time to time in terms of naming. you can search from a wordlist by using `enum4linux -s [wordlist] [target host]`
- `nmap` also has samba information enumeration and attack tools with scripts like `smb-enum-shares`, `smb-enum-users` or `smb-brute`
- for a linux host the most effective tool order is `enum4linux -n [target host]`, `enum4linux -S [target host]`, test connecting to all shares with `smbclient //[target host]/[share] -N`, enumerate users with `enum4linux -U [target host]`, try `smbclient //[target host]/[discovered user name] -N`, and finally maybe bruteforcing common share names with `enum4linux -s [wordlist] [target host]`
- if shares are password-protected, maybe you can complement this with the password cracking section to get user share access!

#### ARP poisoning
- powerful attack used to intercept network traffic
- switching communication uses the ARP cache table to route local packets
- if we can manipulate the ARP table, we can receive traffic destined to other hosts
- if both parties involved in communication are manipulated, we perform a man-in-the-middle attack
- we do this by sending gratuitous ARP replies until hosts learn that we're the ARP host they're looking for thanks to race conditions
- this attack can be made larger by impersonating a router and capturing the traffic on the entire network
- this can be automated with available tools for `ARP Spoofing` in the `Dsniff` package, of which we will specifically use `arpspoof`
- before using this tool we need to enable traffic forwarding with `echo 1 > /proc/sys/net/ipv4/ip_forward`
- after this we run `arpspoof -i [interface] -t [target] -r [host]`, where `interface` is the network interface ID we want to use to send ARP spoofing traffic, and `target` and `host` are the victim IP addresses we want to into man-in-the-middle
- after this, run `wireshark` and look at the intercepted traffic

#### Metasploit
#### Meterpreter
