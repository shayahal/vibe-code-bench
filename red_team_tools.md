# Red-Teaming Tools Reference

A comprehensive list of the best red-teaming and web security testing tools available. This reference guide includes tools for web application security, network security, exploitation, reconnaissance, and more.

## Table of Contents

- [Web Application Security](#web-application-security)
- [Vulnerability Scanners](#vulnerability-scanners)
- [Exploitation Frameworks](#exploitation-frameworks)
- [Network Security](#network-security)
- [Reconnaissance & OSINT](#reconnaissance--osint)
- [Password Testing](#password-testing)
- [Social Engineering](#social-engineering)
- [Post-Exploitation](#post-exploitation)
- [Mobile Security](#mobile-security)
- [API Security](#api-security)
- [Container & Cloud Security](#container--cloud-security)
- [Fuzzing Tools](#fuzzing-tools)
- [Payload Generation](#payload-generation)
- [Command & Control](#command--control)

---

## Web Application Security

### Burp Suite
**Type**: Web Proxy & Security Testing Platform  
**License**: Commercial (Free Community Edition available)  
**Description**: Industry-standard web application security testing tool. Features include:
- Intercepting proxy for manual testing
- Automated scanner for vulnerability detection
- Intruder for fuzzing and brute-forcing
- Repeater for manual request manipulation
- Extensions ecosystem for custom functionality

**Use Cases**: 
- Manual web application testing
- API security testing
- Authentication bypass testing
- Session management testing

**Website**: https://portswigger.net/burp

### OWASP ZAP (Zed Attack Proxy)
**Type**: Web Application Security Scanner  
**License**: Open Source (Apache 2.0)  
**Description**: Free, open-source web application security scanner. Features:
- Automated scanning
- Manual testing tools
- REST API for integration
- CI/CD integration support
- Active and passive scanning

**Use Cases**:
- Automated vulnerability scanning
- CI/CD pipeline integration
- Learning web security
- Free alternative to Burp Suite

**Website**: https://www.zaproxy.org/

### SQLMap
**Type**: SQL Injection Exploitation Tool  
**License**: Open Source  
**Description**: Automated tool for detecting and exploiting SQL injection flaws. Features:
- Multiple database support (MySQL, PostgreSQL, MSSQL, Oracle, etc.)
- Multiple injection techniques
- Database enumeration
- Data exfiltration
- File system access

**Use Cases**:
- SQL injection testing
- Database enumeration
- Data extraction demonstrations
- Post-exploitation database access

**Website**: https://sqlmap.org/

### XSSer
**Type**: XSS Exploitation Framework  
**License**: Open Source  
**Description**: Automated framework for detecting and exploiting XSS vulnerabilities. Features:
- Multiple XSS vectors
- Payload encoding/obfuscation
- POST/GET support
- Cookie injection
- Code injection

**Use Cases**:
- XSS vulnerability testing
- Cross-site scripting exploitation
- Cookie theft demonstrations

**GitHub**: https://github.com/epsylon/xsser

### XSStrike
**Type**: XSS Detection & Exploitation Suite  
**License**: Open Source  
**Description**: Advanced XSS detection suite with multiple detection algorithms. Features:
- Multiple parsing engines
- Payload generator
- Fuzzing engine
- Context-aware payload generation
- WAF detection and bypass

**Use Cases**:
- Advanced XSS testing
- WAF bypass techniques
- Context-aware payload generation

**GitHub**: https://github.com/s0md3v/XSStrike

### Commix
**Type**: Command Injection Exploitation Tool  
**License**: Open Source  
**Description**: Automated tool for detecting and exploiting command injection vulnerabilities. Features:
- Multiple injection techniques
- Shell access
- File system access
- Multiple OS support

**Use Cases**:
- Command injection testing
- OS command execution
- File system access

**GitHub**: https://github.com/commixproject/commix

### NoSQLMap
**Type**: NoSQL Injection Tool  
**License**: Open Source  
**Description**: Automated tool for detecting and exploiting NoSQL injection vulnerabilities. Features:
- MongoDB support
- CouchDB support
- Data extraction
- Authentication bypass

**Use Cases**:
- NoSQL injection testing
- MongoDB security testing
- NoSQL database enumeration

**GitHub**: https://github.com/codingo/NoSQLMap

---

## Vulnerability Scanners

### Nessus
**Type**: Vulnerability Scanner  
**License**: Commercial  
**Description**: Comprehensive vulnerability scanner with extensive plugin library. Features:
- Network vulnerability scanning
- Web application scanning
- Compliance checking
- Configuration auditing

**Use Cases**:
- Enterprise vulnerability assessment
- Compliance auditing
- Network security scanning

**Website**: https://www.tenable.com/products/nessus

### OpenVAS
**Type**: Vulnerability Scanner  
**License**: Open Source  
**Description**: Open-source vulnerability scanner and manager. Features:
- Network vulnerability scanning
- Web application testing
- Configuration auditing
- Report generation

**Use Cases**:
- Free vulnerability scanning
- Network security assessment
- Compliance checking

**Website**: https://www.openvas.org/

### Nikto
**Type**: Web Server Scanner  
**License**: Open Source  
**Description**: Web server vulnerability scanner. Features:
- Server misconfiguration detection
- Outdated software detection
- Multiple server support
- Plugin system

**Use Cases**:
- Web server security scanning
- Misconfiguration detection
- Quick security checks

**Website**: https://cirt.net/Nikto2

### WPScan
**Type**: WordPress Security Scanner  
**License**: Open Source  
**Description**: WordPress vulnerability scanner. Features:
- Plugin vulnerability detection
- Theme vulnerability detection
- User enumeration
- Brute-force capabilities

**Use Cases**:
- WordPress security testing
- Plugin/theme vulnerability detection
- WordPress site assessment

**Website**: https://wpscan.com/

### Nuclei
**Type**: Vulnerability Scanner  
**License**: Open Source  
**Description**: Fast vulnerability scanner with extensive template library. Features:
- YAML-based templates
- Multiple protocol support
- High performance
- Community templates

**Use Cases**:
- Fast vulnerability scanning
- Custom vulnerability detection
- Large-scale scanning

**GitHub**: https://github.com/projectdiscovery/nuclei

---

## Exploitation Frameworks

### Metasploit Framework
**Type**: Exploitation Framework  
**License**: Open Source (Community) / Commercial (Pro)  
**Description**: Most popular penetration testing framework. Features:
- Extensive exploit database
- Payload generation
- Post-exploitation modules
- Auxiliary modules
- Meterpreter payload

**Use Cases**:
- Exploitation testing
- Post-exploitation
- Payload generation
- Proof of concept development

**Website**: https://www.metasploit.com/

### Cobalt Strike
**Type**: Adversary Simulation Platform  
**License**: Commercial  
**Description**: Advanced threat emulation platform. Features:
- Beacon payload
- Team server
- Post-exploitation capabilities
- Reporting and logging
- Malleable C2 profiles

**Use Cases**:
- Red team operations
- Adversary simulation
- Advanced persistent threat simulation

**Website**: https://www.cobaltstrike.com/

### Empire
**Type**: Post-Exploitation Framework  
**License**: Open Source  
**Description**: PowerShell and Python post-exploitation agent. Features:
- PowerShell agents
- Python agents
- Modular architecture
- Stagers and listeners

**Use Cases**:
- Post-exploitation
- Windows environment testing
- Lateral movement simulation

**GitHub**: https://github.com/BC-SECURITY/Empire

### Covenant
**Type**: .NET Command & Control Framework  
**License**: Open Source  
**Description**: .NET-based C2 framework. Features:
- .NET agents
- Grunts (agents)
- Listeners
- Launchers
- Tasking system

**Use Cases**:
- .NET-based red team operations
- Windows post-exploitation
- C2 framework development

**GitHub**: https://github.com/cobbr/Covenant

---

## Network Security

### Wireshark
**Type**: Network Protocol Analyzer  
**License**: Open Source  
**Description**: World's foremost network protocol analyzer. Features:
- Deep packet inspection
- Protocol dissection
- Live capture
- Offline analysis
- Extensive protocol support

**Use Cases**:
- Network traffic analysis
- Protocol analysis
- Troubleshooting
- Security incident investigation

**Website**: https://www.wireshark.org/

### Nmap
**Type**: Network Scanner  
**License**: Open Source  
**Description**: Network discovery and security auditing tool. Features:
- Host discovery
- Port scanning
- Service detection
- OS detection
- Scriptable with NSE

**Use Cases**:
- Network reconnaissance
- Port scanning
- Service enumeration
- Network mapping

**Website**: https://nmap.org/

### Masscan
**Type**: Port Scanner  
**License**: Open Source  
**Description**: Ultra-fast port scanner. Features:
- Very high speed
- Internet-scale scanning
- TCP/UDP support
- Banner grabbing

**Use Cases**:
- Large-scale port scanning
- Internet-wide scanning
- Fast reconnaissance

**GitHub**: https://github.com/robertdavidgraham/masscan

### Responder
**Type**: LLMNR/NBT-NS/MDNS Poisoner  
**License**: Open Source  
**Description**: LLMNR, NBT-NS, and MDNS poisoner. Features:
- Credential harvesting
- SMB relay
- HTTP server
- Multiple protocol support

**Use Cases**:
- Network poisoning attacks
- Credential harvesting
- SMB relay attacks

**GitHub**: https://github.com/lgandx/Responder

### Impacket
**Type**: Network Protocol Library  
**License**: Open Source  
**Description**: Collection of Python classes for network protocols. Features:
- SMB, MSRPC, LDAP implementations
- Kerberos support
- Multiple attack tools
- Protocol manipulation

**Use Cases**:
- Windows network protocol testing
- Kerberos attacks
- SMB attacks
- Active Directory testing

**GitHub**: https://github.com/fortra/impacket

---

## Reconnaissance & OSINT

### Recon-ng
**Type**: Web Reconnaissance Framework  
**License**: Open Source  
**Description**: Full-featured web reconnaissance framework. Features:
- Module-based architecture
- Multiple data sources
- API integrations
- Report generation

**Use Cases**:
- OSINT gathering
- Target reconnaissance
- Information gathering
- Social media reconnaissance

**GitHub**: https://github.com/lanmaster53/recon-ng

### theHarvester
**Type**: OSINT Tool  
**License**: Open Source  
**Description**: Tool for gathering subdomain names, emails, IPs, and more. Features:
- Multiple data sources
- Subdomain discovery
- Email harvesting
- Employee discovery

**Use Cases**:
- Subdomain enumeration
- Email harvesting
- OSINT gathering
- Target reconnaissance

**GitHub**: https://github.com/laramies/theHarvester

### Shodan
**Type**: Search Engine for Internet-Connected Devices  
**License**: Commercial (Free tier available)  
**Description**: Search engine for internet-connected devices. Features:
- Device search
- Vulnerability search
- Filtering capabilities
- API access

**Use Cases**:
- Internet device discovery
- Vulnerability research
- IoT device discovery
- Service enumeration

**Website**: https://www.shodan.io/

### Amass
**Type**: Subdomain Enumeration Tool  
**License**: Open Source  
**Description**: In-depth subdomain enumeration tool. Features:
- Multiple data sources
- DNS enumeration
- Certificate transparency
- Active/passive modes

**Use Cases**:
- Subdomain discovery
- Attack surface mapping
- DNS enumeration

**GitHub**: https://github.com/owasp-amass/amass

### Maltego
**Type**: Link Analysis & Data Mining Tool  
**License**: Commercial (Free Community Edition)  
**Description**: Visual link analysis tool. Features:
- Graph-based visualization
- Multiple transforms
- Data integration
- Relationship mapping

**Use Cases**:
- Link analysis
- Relationship mapping
- OSINT visualization
- Investigation

**Website**: https://www.maltego.com/

### SpiderFoot
**Type**: OSINT Automation Tool  
**License**: Open Source  
**Description**: Open-source intelligence automation tool. Features:
- 200+ modules
- Multiple data sources
- Web interface
- API support

**Use Cases**:
- Automated OSINT
- Threat intelligence
- Investigation automation

**Website**: https://www.spiderfoot.net/

---

## Password Testing

### Hashcat
**Type**: Password Recovery Tool  
**License**: Open Source  
**Description**: Advanced password recovery tool. Features:
- GPU acceleration
- Multiple hash types
- Rule-based attacks
- Distributed cracking

**Use Cases**:
- Password hash cracking
- Password strength testing
- Hash analysis

**Website**: https://hashcat.net/hashcat/

### John the Ripper
**Type**: Password Cracker  
**License**: Open Source  
**Description**: Fast password cracker. Features:
- Multiple hash formats
- Wordlist attacks
- Rule-based attacks
- Incremental mode

**Use Cases**:
- Password cracking
- Hash analysis
- Password policy testing

**Website**: https://www.openwall.com/john/

### Hydra
**Type**: Network Login Cracker  
**License**: Open Source  
**Description**: Parallelized login cracker. Features:
- Multiple protocol support
- Parallel attacks
- Flexible attack modes
- Service-specific modules

**Use Cases**:
- Brute-force attacks
- Password spraying
- Credential testing

**GitHub**: https://github.com/vanhauser-thc/thc-hydra

### Medusa
**Type**: Parallel Login Cracker  
**License**: Open Source  
**Description**: Fast, parallel, modular login brute-forcer. Features:
- Multiple protocol support
- Parallel processing
- Flexible input
- Module-based

**Use Cases**:
- Brute-force attacks
- Credential testing
- Password policy validation

**Website**: http://foofus.net/goons/jmk/medusa/medusa.html

---

## Social Engineering

### Social-Engineer Toolkit (SET)
**Type**: Social Engineering Framework  
**License**: Open Source  
**Description**: Toolkit for social engineering attacks. Features:
- Phishing campaigns
- Credential harvesting
- Malicious file generation
- Website cloning

**Use Cases**:
- Phishing simulation
- Social engineering testing
- Security awareness training

**GitHub**: https://github.com/trustedsec/social-engineer-toolkit

### Gophish
**Type**: Phishing Framework  
**License**: Open Source  
**Description**: Open-source phishing framework. Features:
- Email campaigns
- Landing pages
- Campaign tracking
- User management

**Use Cases**:
- Phishing campaigns
- Security awareness training
- Email security testing

**Website**: https://getgophish.com/

### BeEF (Browser Exploitation Framework)
**Type**: Browser Exploitation Framework  
**License**: Open Source  
**Description**: Browser exploitation framework. Features:
- Browser hooking
- Post-exploitation modules
- Command execution
- Social engineering

**Use Cases**:
- Browser exploitation
- XSS post-exploitation
- Client-side attacks

**Website**: https://beefproject.com/

---

## Post-Exploitation

### BloodHound
**Type**: Active Directory Analysis Tool  
**License**: Open Source  
**Description**: Graph-based Active Directory analysis tool. Features:
- Attack path visualization
- Privilege escalation paths
- Domain mapping
- Relationship analysis

**Use Cases**:
- Active Directory security testing
- Privilege escalation
- Attack path discovery

**GitHub**: https://github.com/BloodHoundAD/BloodHound

### Mimikatz
**Type**: Credential Extraction Tool  
**License**: Open Source  
**Description**: Tool for extracting credentials from Windows. Features:
- Credential dumping
- Pass-the-hash
- Pass-the-ticket
- Kerberos attacks

**Use Cases**:
- Credential extraction
- Windows post-exploitation
- Kerberos attacks

**GitHub**: https://github.com/gentilkiwi/mimikatz

### PowerSploit
**Type**: PowerShell Post-Exploitation Framework  
**License**: Open Source  
**Description**: PowerShell modules for post-exploitation. Features:
- Code execution
- Persistence
- Privilege escalation
- Reconnaissance

**Use Cases**:
- Windows post-exploitation
- PowerShell attacks
- Persistence mechanisms

**GitHub**: https://github.com/PowerShellMafia/PowerSploit

### LaZagne
**Type**: Credential Recovery Tool  
**License**: Open Source  
**Description**: Credential recovery tool for multiple platforms. Features:
- Multiple OS support
- Multiple application support
- Password recovery
- Hash extraction

**Use Cases**:
- Credential recovery
- Password extraction
- Post-exploitation

**GitHub**: https://github.com/AlessandroZ/LaZagne

---

## Mobile Security

### MobSF (Mobile Security Framework)
**Type**: Mobile Security Testing Framework  
**License**: Open Source  
**Description**: Automated mobile security testing framework. Features:
- Static analysis
- Dynamic analysis
- API security testing
- Multiple platform support

**Use Cases**:
- Mobile app security testing
- iOS/Android analysis
- API security testing

**GitHub**: https://github.com/MobSF/Mobile-Security-Framework-MobSF

### Frida
**Type**: Dynamic Instrumentation Toolkit  
**License**: Open Source  
**Description**: Dynamic instrumentation toolkit. Features:
- Runtime manipulation
- API hooking
- Script injection
- Multiple platform support

**Use Cases**:
- Dynamic analysis
- Runtime manipulation
- Reverse engineering

**Website**: https://frida.re/

### APKiD
**Type**: Android Application Identifier  
**License**: Open Source  
**Description**: Android application packer, protector, and obfuscator detector. Features:
- Packer detection
- Obfuscator detection
- Compiler detection
- Multiple tool detection

**Use Cases**:
- Android app analysis
- Packer detection
- Obfuscation detection

**GitHub**: https://github.com/rednaga/APKiD

---

## API Security

### Postman
**Type**: API Testing Tool  
**License**: Commercial (Free tier available)  
**Description**: API development and testing platform. Features:
- API testing
- Collection management
- Automated testing
- Documentation

**Use Cases**:
- API security testing
- API development
- Endpoint testing

**Website**: https://www.postman.com/

### REST-Attacker
**Type**: API Security Testing Tool  
**License**: Open Source  
**Description**: Automated REST API security testing tool. Features:
- OWASP API Top 10 testing
- Automated attacks
- Vulnerability detection
- Report generation

**Use Cases**:
- REST API security testing
- OWASP API Top 10 validation
- API vulnerability detection

**GitHub**: https://github.com/optiv/rest-attacker

### Kiterunner
**Type**: API Endpoint Discovery Tool  
**License**: Open Source  
**Description**: Context-aware content discovery tool. Features:
- API endpoint discovery
- Content discovery
- Context-aware requests
- Multiple methods

**Use Cases**:
- API endpoint discovery
- Content discovery
- Hidden endpoint finding

**GitHub**: https://github.com/assetnote/kiterunner

---

## Container & Cloud Security

### Trivy
**Type**: Container Security Scanner  
**License**: Open Source  
**Description**: Comprehensive security scanner for containers. Features:
- Vulnerability scanning
- Misconfiguration detection
- Multiple formats support
- CI/CD integration

**Use Cases**:
- Container security scanning
- Image vulnerability detection
- CI/CD security

**GitHub**: https://github.com/aquasecurity/trivy

### CloudSploit
**Type**: Cloud Security Posture Management  
**License**: Commercial (Open source version available)  
**Description**: Cloud security scanning tool. Features:
- Multi-cloud support
- Misconfiguration detection
- Compliance checking
- Continuous monitoring

**Use Cases**:
- Cloud security assessment
- Misconfiguration detection
- Compliance validation

**Website**: https://cloudsploit.com/

### Pacu
**Type**: AWS Exploitation Framework  
**License**: Open Source  
**Description**: AWS exploitation framework. Features:
- AWS-specific attacks
- Privilege escalation
- Persistence
- Data exfiltration

**Use Cases**:
- AWS security testing
- Cloud exploitation
- AWS post-exploitation

**GitHub**: https://github.com/RhinoSecurityLabs/pacu

---

## Fuzzing Tools

### AFL (American Fuzzy Lop)
**Type**: Fuzzing Tool  
**License**: Open Source  
**Description**: Security-oriented fuzzer. Features:
- Coverage-guided fuzzing
- Instrumentation
- Crash detection
- High performance

**Use Cases**:
- Binary fuzzing
- Vulnerability discovery
- Crash detection

**Website**: http://lcamtuf.coredump.cx/afl/

### wfuzz
**Type**: Web Application Fuzzer  
**License**: Open Source  
**Description**: Web application fuzzer. Features:
- Parameter fuzzing
- Header fuzzing
- Multiple injection points
- Custom payloads

**Use Cases**:
- Web application fuzzing
- Parameter testing
- Directory brute-forcing

**GitHub**: https://github.com/xmendez/wfuzz

### ffuf
**Type**: Web Fuzzer  
**License**: Open Source  
**Description**: Fast web fuzzer. Features:
- High performance
- Multiple modes
- Filtering options
- Recursion support

**Use Cases**:
- Web fuzzing
- Directory brute-forcing
- Parameter fuzzing

**GitHub**: https://github.com/ffuf/ffuf

### Boofuzz
**Type**: Network Protocol Fuzzer  
**License**: Open Source  
**Description**: Network protocol fuzzing framework. Features:
- Protocol fuzzing
- Mutation-based fuzzing
- Session management
- Crash detection

**Use Cases**:
- Network protocol fuzzing
- Vulnerability discovery
- Protocol testing

**GitHub**: https://github.com/jtpereyda/boofuzz

---

## Payload Generation

### MSFVenom
**Type**: Payload Generator  
**License**: Open Source (Part of Metasploit)  
**Description**: Metasploit payload generator. Features:
- Multiple payload types
- Encoding options
- Platform selection
- Format options

**Use Cases**:
- Payload generation
- Shellcode creation
- Exploit development

**Documentation**: Part of Metasploit Framework

### Veil
**Type**: Payload Generator  
**License**: Open Source  
**Description**: AV-evasion payload generator. Features:
- AV evasion
- Multiple payload types
- Encoding options
- Framework integration

**Use Cases**:
- AV evasion
- Payload generation
- Bypass testing

**GitHub**: https://github.com/Veil-Framework/Veil

### TheFatRat
**Type**: Payload Generator  
**License**: Open Source  
**Description**: Easy exploit generator. Features:
- Multiple payload types
- AV evasion
- Backdoor generation
- Listener integration

**Use Cases**:
- Payload generation
- Backdoor creation
- AV evasion

**GitHub**: https://github.com/Screetsec/TheFatRat

---

## Command & Control

### Sliver
**Type**: C2 Framework  
**License**: Open Source  
**Description**: Go-based C2 framework. Features:
- Multiple protocols
- Malleable profiles
- Multiplayer support
- Extensible

**Use Cases**:
- Red team operations
- C2 framework
- Post-exploitation

**GitHub**: https://github.com/BishopFox/sliver

### Mythic
**Type**: C2 Framework  
**License**: Open Source  
**Description**: Cross-platform C2 framework. Features:
- Multiple agents
- Web interface
- Extensible architecture
- API support

**Use Cases**:
- C2 operations
- Red team operations
- Post-exploitation

**GitHub**: https://github.com/its-a-feature/Mythic

---

## Additional Resources

### PayloadsAllTheThings
**Type**: Payload Collection  
**License**: Open Source  
**Description**: Comprehensive list of payloads and bypasses. Features:
- XSS payloads
- SQL injection payloads
- Command injection payloads
- File upload bypasses
- And much more

**Use Cases**:
- Payload reference
- Bypass techniques
- Learning resource

**GitHub**: https://github.com/swisskyrepo/PayloadsAllTheThings

### SecLists
**Type**: Security Testing Lists  
**License**: Open Source  
**Description**: Collection of multiple types of lists for security testing. Features:
- Username lists
- Password lists
- Payload lists
- Fuzzing dictionaries

**Use Cases**:
- Security testing
- Wordlists
- Payloads

**GitHub**: https://github.com/danielmiessler/SecLists

### OWASP Testing Guide
**Type**: Testing Methodology  
**License**: Open Source  
**Description**: Comprehensive web application security testing guide. Features:
- Testing methodology
- Vulnerability descriptions
- Testing techniques
- Best practices

**Use Cases**:
- Testing methodology
- Learning resource
- Reference guide

**Website**: https://owasp.org/www-project-web-security-testing-guide/

---

## Tool Integration Recommendations

When building a red-teaming agent, consider integrating:

1. **Burp Suite / OWASP ZAP** - For web application testing
2. **SQLMap** - For SQL injection testing
3. **Nmap** - For network reconnaissance
4. **Metasploit** - For exploitation
5. **Nuclei** - For fast vulnerability scanning
6. **Recon-ng** - For OSINT gathering
7. **Hashcat** - For password cracking
8. **BloodHound** - For Active Directory analysis

---

## Legal Disclaimer

⚠️ **IMPORTANT**: These tools are for authorized security testing only. Always ensure you have explicit written permission before testing any system. Unauthorized access to computer systems is illegal and may result in criminal prosecution.

---

## Contributing

This list is maintained as a reference. If you know of additional tools that should be included, please contribute!

---

*Last Updated: 2024*

