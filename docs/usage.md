🛠️ NetVanguard Operational Guide
This document provides detailed instructions on how to operate the NetVanguard v1.0.1 framework for advanced security auditing and network analysis.

1. Advanced Network Discovery (Nmap Engine)
To initiate a multi-vector vulnerability scan, use the tactical dashboard or the CLI bridge.

Stealth Mode: netvanguard --scan --timing T0 (Optimized for IDS evasion)

Vulnerability Detection: NSE (Nmap Scripting Engine) scripts are automatically triggered based on the target fingerprint.

2. Passive Intelligence (OSINT)
NetVanguard integrates with global intelligence databases to gather information without direct interaction.

Shodan Analysis: Direct API tunneling to retrieve historical banner information.

DNS Recon: Automated subdomain enumeration using internal asynchronous resolvers.

3. Traffic Analysis & Sniffing
The system utilizes libpcap for low-level packet capture.

Promiscuous Mode: Activated automatically during local network audits.

Protocol Dissection: Real-time analysis of TCP/UDP streams for plaintext sensitive data.

4. Privilege Escalation (PrivEsc)
The Linux Auditor module checks for:

Misconfigured SUID/GUID binaries.

Writable /etc/passwd or /etc/shadow files.

Kernel version matching against local exploit databases.

5. Deployment Options
Docker: docker compose up --build (Recommended for isolated environments)

Native Rust: cargo run --release (Requires libpcap-dev on host system)
