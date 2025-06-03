URL-Related Indicators of Compromise (IOCs)
URL-based IOCs are commonly used to detect and block access to malicious domains, phishing sites, and command-and-control (C2) infrastructure. These indicators help security teams proactively identify threats based on known suspicious or confirmed harmful URLs.

Key Use Cases for URL IOCs:

Detecting phishing attempts embedded in emails or web content.

Blocking access to malicious websites in real time.

Correlating threat intelligence with observed network traffic.

Recommended Resources for Monitoring and Validating Malicious URLs:

🔗 OpenPhish -> https://openphish.com/
A widely used threat intelligence feed providing automated and manually verified phishing URLs. Ideal for integration with SIEM/SOAR platforms for real-time threat detection.

🔗 PhishLabs -> https://www.phishlabs.com/
Offers enterprise-level phishing threat intelligence and takedown services. Useful for gaining insights into phishing campaigns, tactics, and infrastructure.

🔗 PhishTank -> https://www.phishtank.com/
A community-based site where users submit and verify suspected phishing URLs. It’s a useful crowdsourced feed to enrich IOC databases.

File and File Hash IOCs
File-based IOCs help identify known malware, ransomware, and other malicious files using cryptographic hashes such as MD5, SHA-1, and SHA-256.

Use Cases for File/File Hash IOCs:

Scanning attachments or downloaded files for known threats.

Enriching SIEM alerts with hash-based threat intelligence.

Investigating endpoint or network activity post-compromise.

Common Hash Lookup and Analysis Tools:

VirusTotal (https://www.virustotal.com/) – Upload and analyze files or hash values against a large database of AV engines and threat intelligence sources.

Hybrid Analysis (https://www.hybrid-analysis.com) – Dynamic analysis of suspicious files with detailed behavioral reports.

Malshare (https://www.malshare.com) / MalwareBazaar (https://bazaar.abuse.ch) – Repositories of known malware samples and associated metadata for security research.
