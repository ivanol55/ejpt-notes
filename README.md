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
