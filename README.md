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

### Vulnerability assessment
#### Vulnerability scanning and assessment
#### Under the hood of vulnerability scanners

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
