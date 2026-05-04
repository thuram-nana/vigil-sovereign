# MITRE ATT&CK Enterprise — Web Application Adversary Coverage

This is **not** a generic ATT&CK checklist — it's a tailoring of
ATT&CK Enterprise techniques to the contexts CRUCIBLE engagements
typically encounter (web/API/cloud/mobile). Use it for:

1. **EMULATE-mode engagements** where the goal is to demonstrate end-to-end attack chains.
2. **Coverage analysis** — confirming the engagement exercises the same techniques real adversaries use against this asset class.
3. **Detection mapping** — when defensive recommendations need to point at the technique a control would block.

Techniques marked ★ are the most common in cloud-hosted SaaS post-compromise. Coverage is *aspirational* for any single engagement — apply with judgment.

---

## TA0043 — Reconnaissance

- [ ] **T1592** Gather Victim Host Information → `01-passive-recon.md`
- [ ] **T1589** Gather Victim Identity Information → `01-passive-recon.md`
- [ ] **T1590** Gather Victim Network Information → `01-passive-recon.md`
- [ ] **T1591** Gather Victim Org Information → `01-passive-recon.md`
- [ ] **T1593** Search Open Websites/Domains → `01-passive-recon.md`
- [ ] **T1594** Search Victim-Owned Websites → `01-passive-recon.md`
- [ ] ★ **T1595** Active Scanning (.001 Scanning IP, .002 Vuln Scanning, .003 Wordlist Scanning) → `02-active-recon.md`, `03-attack-surface-mapping.md`

## TA0042 — Resource Development

- [ ] **T1583** Acquire Infrastructure (.006 Web Services for typosquat / phishing-host) → ENGAGEMENT prep
- [ ] **T1585** Establish Accounts (.001 Social Media, .002 Email Accounts) → if EMULATE phishing in scope
- [ ] **T1588** Obtain Capabilities (.001 Malware, .002 Tool, .005 Exploits) → ENGAGEMENT prep

## TA0001 — Initial Access

- [ ] ★ **T1190** Exploit Public-Facing Application → `04-web-application.md`, `05-api-security.md`, `08-injection.md`
- [ ] **T1133** External Remote Services → `12-network-infrastructure.md` (VPN, RDP, SSH bastion)
- [ ] ★ **T1078** Valid Accounts (.004 Cloud Accounts) → `06-authentication-identity.md`, `13-cloud-native.md`
- [ ] **T1566** Phishing (.001 Spearphishing Attachment, .002 Spearphishing Link, .003 via Service) → EMULATE-only
- [ ] **T1199** Trusted Relationship → `15-cicd-supply-chain.md`, `19-sso-federated.md`
- [ ] **T1195** Supply Chain Compromise (.002 Software Supply Chain) → `15-cicd-supply-chain.md`

## TA0002 — Execution

- [ ] ★ **T1059** Command and Scripting Interpreter (.004 Unix Shell, .006 Python, .007 JavaScript) → `08-injection.md`, `21-post-exploitation.md`
- [ ] **T1106** Native API → applicable if RCE achieved
- [ ] **T1204** User Execution (.001 Malicious Link, .002 Malicious File) → EMULATE-only

## TA0003 — Persistence

- [ ] **T1505** Server Software Component (.003 Web Shell, .004 IIS, .005 SQL Stored Procedures) → `21-post-exploitation.md`
- [ ] **T1098** Account Manipulation (.001 Cloud Account, .003 Add Office 365 Global Admin Role, .005 Device Reg) → `13-cloud-native.md`, `21-post-exploitation.md`
- [ ] **T1136** Create Account (.001 Local, .003 Cloud) → `21-post-exploitation.md`
- [ ] **T1556** Modify Authentication Process (.001 Domain Controller, .003 Pluggable Auth Modules, .006 MFA) → `21-post-exploitation.md`
- [ ] ★ **T1078** Valid Accounts (persistent) → `21-post-exploitation.md`

## TA0004 — Privilege Escalation

- [ ] ★ **T1068** Exploitation for Privilege Escalation → `21-post-exploitation.md`
- [ ] **T1548** Abuse Elevation Control Mechanism (.001 Setuid/Setgid, .003 Sudo, .005 Temporary Elevated Cloud Access) → `21-post-exploitation.md`, `13-cloud-native.md`
- [ ] **T1611** Escape to Host (container breakout) → `14-container-kubernetes.md`
- [ ] **T1134** Access Token Manipulation → `06-authentication-identity.md`, `13-cloud-native.md`
- [ ] ★ **T1078** Valid Accounts (escalation) → `07-authorization.md`

## TA0005 — Defense Evasion

- [ ] **T1027** Obfuscated Files or Information → `21-post-exploitation.md` (web shell obfuscation)
- [ ] **T1140** Deobfuscate/Decode Files → not applicable in offensive direction
- [ ] **T1070** Indicator Removal (.001 Clear Win Event Log, .002 Clear Linux Mac Sys Log, .004 File Deletion, .006 Timestomp) → EMULATE-only, with explicit authorization
- [ ] **T1562** Impair Defenses (.001 Disable / Modify Tools, .004 Disable / Modify System Firewall, .008 Disable Cloud Logs) → EMULATE-only
- [ ] **T1550** Use Alternate Authentication Material (.001 App Access Token, .002 Pass the Hash, .003 Pass the Ticket, .004 Web Session Cookie) → `06-authentication-identity.md`, `21-post-exploitation.md`
- [ ] **T1218** System Binary Proxy Execution (LOLBINS) → `21-post-exploitation.md`

## TA0006 — Credential Access

- [ ] **T1110** Brute Force (.001 Password Guessing, .002 Password Cracking, .003 Password Spraying, .004 Credential Stuffing) → `06-authentication-identity.md`
- [ ] ★ **T1552** Unsecured Credentials (.001 Credentials In Files, .002 Credentials in Registry, .004 Private Keys, .006 Group Policy Preferences, .007 Container API) → `15-cicd-supply-chain.md`, `20-source-code-review.md`, `21-post-exploitation.md`
- [ ] ★ **T1555** Credentials from Password Stores → `21-post-exploitation.md`
- [ ] ★ **T1539** Steal Web Session Cookie → `09-client-side.md`, `21-post-exploitation.md`
- [ ] **T1606** Forge Web Credentials (.001 Web Cookies, .002 SAML Tokens) → `06-authentication-identity.md`, `19-sso-federated.md`
- [ ] **T1557** Adversary-in-the-Middle (.001 LLMNR/NBT-NS Poisoning, .002 ARP Cache Poisoning, .003 DHCP Spoofing) → internal-only
- [ ] ★ **T1212** Exploitation for Credential Access → `08-injection.md` (SQLi → password hash dump)
- [ ] **T1003** OS Credential Dumping (.007 Proc Filesystem, .008 /etc/passwd and /etc/shadow) → `21-post-exploitation.md`

## TA0007 — Discovery

- [ ] **T1087** Account Discovery (.001 Local, .002 Domain, .004 Cloud) → `06-authentication-identity.md`, `21-post-exploitation.md`
- [ ] **T1083** File and Directory Discovery → `21-post-exploitation.md`
- [ ] **T1057** Process Discovery → `21-post-exploitation.md`
- [ ] **T1018** Remote System Discovery → `21-post-exploitation.md`
- [ ] **T1046** Network Service Discovery → `02-active-recon.md`
- [ ] **T1135** Network Share Discovery → internal-only
- [ ] ★ **T1538** Cloud Service Dashboard → `13-cloud-native.md`
- [ ] **T1526** Cloud Service Discovery → `13-cloud-native.md`
- [ ] ★ **T1580** Cloud Infrastructure Discovery → `13-cloud-native.md`
- [ ] **T1613** Container and Resource Discovery → `14-container-kubernetes.md`
- [ ] **T1619** Cloud Storage Object Discovery → `13-cloud-native.md`

## TA0008 — Lateral Movement

- [ ] **T1021** Remote Services (.001 RDP, .002 SMB, .004 SSH, .005 VNC, .007 Cloud Services) → `21-post-exploitation.md`
- [ ] ★ **T1550** Use Alternate Authentication Material (cookies, tokens) → `21-post-exploitation.md`
- [ ] **T1210** Exploitation of Remote Services → `21-post-exploitation.md`
- [ ] **T1534** Internal Spearphishing → EMULATE-only

## TA0009 — Collection

- [ ] ★ **T1213** Data from Information Repositories (.001 Confluence, .002 Sharepoint, .003 Code Repositories) → `21-post-exploitation.md`
- [ ] **T1005** Data from Local System → `22-data-exfiltration-impact.md`
- [ ] **T1039** Data from Network Shared Drive → `22-data-exfiltration-impact.md`
- [ ] **T1530** Data from Cloud Storage Object → `13-cloud-native.md`, `22-data-exfiltration-impact.md`
- [ ] ★ **T1213** Data from Information Repositories → `22-data-exfiltration-impact.md`
- [ ] **T1119** Automated Collection → `22-data-exfiltration-impact.md`
- [ ] **T1602** Data from Configuration Repository → `13-cloud-native.md`
- [ ] **T1074** Data Staged → `22-data-exfiltration-impact.md`

## TA0011 — Command and Control

- [ ] **T1071** Application Layer Protocol (.001 Web, .003 Mail, .004 DNS) → EMULATE-only
- [ ] **T1095** Non-Application Layer Protocol → EMULATE-only
- [ ] **T1572** Protocol Tunneling → EMULATE-only
- [ ] **T1573** Encrypted Channel → EMULATE-only
- [ ] **T1090** Proxy → EMULATE-only

## TA0010 — Exfiltration

- [ ] ★ **T1041** Exfiltration Over C2 Channel → `22-data-exfiltration-impact.md`
- [ ] **T1011** Exfiltration Over Other Network Medium → `22-data-exfiltration-impact.md`
- [ ] ★ **T1567** Exfiltration Over Web Service (.002 Cloud Storage, .003 Text Storage) → `22-data-exfiltration-impact.md`
- [ ] **T1048** Exfiltration Over Alternative Protocol → `22-data-exfiltration-impact.md`
- [ ] **T1029** Scheduled Transfer → `22-data-exfiltration-impact.md`

## TA0040 — Impact

- [ ] **T1485** Data Destruction → EMULATE-only with explicit authorization
- [ ] **T1486** Data Encrypted for Impact → EMULATE-only with explicit authorization
- [ ] **T1565** Data Manipulation (.001 Stored, .002 Transmitted, .003 Runtime) → `10-business-logic.md`, `22-data-exfiltration-impact.md`
- [ ] **T1499** Endpoint Denial of Service (.001-.004) → DOS rarely in scope
- [ ] **T1498** Network Denial of Service → DOS rarely in scope
- [ ] **T1496** Resource Hijacking → `13-cloud-native.md` (cryptojacking via SSRF)
- [ ] **T1531** Account Access Removal → EMULATE-only with explicit authorization
- [ ] **T1657** Financial Theft → `10-business-logic.md`, `race/race-balance.py`

---

## Cloud Sub-Matrix Highlights

For cloud-hosted targets (most CRUCIBLE engagements):

- **T1078.004** Valid Accounts: Cloud Accounts
- **T1098.001** Account Manipulation: Additional Cloud Credentials
- **T1098.003** Account Manipulation: Add Office 365 Global Admin Role
- **T1098.005** Account Manipulation: Device Registration
- **T1538** Cloud Service Dashboard
- **T1526** Cloud Service Discovery
- **T1580** Cloud Infrastructure Discovery
- **T1619** Cloud Storage Object Discovery
- **T1530** Data from Cloud Storage
- **T1552.005** Cloud Instance Metadata API (the IMDS attack)
- **T1059.009** Cloud API
- **T1496** Resource Hijacking (cryptomining via stolen creds)
- **T1578** Modify Cloud Compute Infrastructure
- **T1213.003** Data from Code Repositories

## Container Sub-Matrix Highlights

- **T1610** Deploy Container
- **T1613** Container and Resource Discovery
- **T1611** Escape to Host
- **T1525** Implant Internal Image
- **T1552.007** Container API credentials

---

## Mapping in Reports

For each finding's "Attack chain" section (in `finding.md`), label
each step with its ATT&CK technique ID. This:
1. Maps offense → defense in language SOC teams already use.
2. Lets the client check coverage in their detection backlog.
3. Ties chains across findings into recognizable adversary patterns.

Example chain labelled:
```
T1595.003 wordlist scan → /admin/ found
T1110.001 password guessing → admin/admin works
T1078 valid accounts → admin login persists
T1505.003 web shell uploaded
T1083 file discovery → DB credentials in /etc/app.conf
T1213.003 source code accessed via shell
T1567.002 git push to attacker-controlled remote
```
