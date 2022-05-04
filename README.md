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
#### Web server fingerprinting
#### HTTP verbs 
#### Directories and file enumeration
#### Google hacking
#### Cross-site scripting
#### SQL Injections

### System attacks
#### Malware and backdoors 
#### Password attacks
#### Buffer overflow attacks

### Network attacks
#### Authentication cracking 
#### Windows shares
#### Null sessions
#### ARP poisoning
#### Metasploit
#### Meterpreter
