# Lab 4 — Risk-Based Vulnerability Prioritisation

> **Subject:** Vulnerability Analysis (IKB21403)
> **Lab Type:** Advanced
> **Target Machine:** Metasploitable2
> **Target IP:** `192.168.56.104`
> **Scan Source:** Tenable Nessus Essentials — Report dated Sat, 06 Jun 2026
> **Student:** aienfrzna


## 1. Objective

> **Teach risk, not severity.**

The Nessus scan against `192.168.56.104` returned 110 vulnerabilities across 8 Critical, 4 High, 18 Medium, 7 Low, and 73 Informational findings. Sorting this list by CVSS alone does not produce a usable remediation plan — a CVSS 10.0 finding with no direct exploit path should not necessarily be patched before a CVSS 6.5 finding that requires only a passive network sniffer.

This lab applies a structured three-factor risk scoring model to five selected vulnerabilities and produces a prioritised remediation list that reflects actual danger in this specific lab environment, not theoretical severity.

---

## 2. Scoring Methodology

Each vulnerability is scored independently across three dimensions on a 1 to 5 scale. The three scores are summed to produce a **Risk Total (maximum: 15)**.

### Exploitability (1-5)

| Score | Criteria |
|-------|----------|
| 1 | No public exploit exists; highly complex conditions required |
| 2 | Exploit exists but requires multi-step setup or chained conditions |
| 3 | Public exploit available with moderate skill or preparation |
| 4 | Easy exploitation using publicly available tools or frameworks |
| 5 | Trivial — single command or passively observed; no credentials required |

### Impact (1-5)

| Score | Criteria |
|-------|----------|
| 1 | Informational only — no direct harm |
| 2 | Minor disruption or partial information disclosure |
| 3 | Credential capture, limited access, or denial of service |
| 4 | Significant data access, partial system control, or session compromise |
| 5 | Full system compromise — root/admin RCE, complete data loss, or unrecoverable damage |

### Exposure (1-5)

| Score | Criteria |
|-------|----------|
| 1 | Completely isolated — no network path to service |
| 2 | Heavily segmented internal network |
| 3 | Internal network with conditional access |
| 4 | Directly reachable from Kali on the lab network (192.168.56.x) |
| 5 | Internet-facing — publicly accessible without tunnelling |

> Lab context: All services on Metasploitable2 at `192.168.56.104` are reachable directly from Kali on the same host-only network segment. No service is internet-facing. The maximum realistic Exposure score for this host is 4.

---

## 3. Five Vulnerabilities Selected from Nessus Report

Five vulnerabilities were selected from the full Nessus report to span a range of severity levels, categories, and exploit profiles. The selection deliberately includes one Medium CVSS finding to satisfy the lab requirement of comparing Medium versus High.

| # | Vulnerability | Plugin | CVSS v3.0 | Nessus Severity | Category |
|---|--------------|--------|-----------|----------------|----------|
| 1 | Bind Shell Backdoor Detection | 51988 | 9.8 | Critical | Backdoor / Service |
| 2 | VNC Server 'password' Password | 61708 | 10.0 | Critical | Authentication |
| 3 | Apache Tomcat AJP Connector Request Injection (Ghostcat) | 134862 | 9.8 | Critical | Web Application |
| 4 | NFS Shares World Readable | 42256 | 7.5 | High | File System |
| 5 | Unencrypted Telnet Server | 42263 | 6.5 | Medium | Service / Protocol |

---

## 4. Risk Scoring Table

| # | Vulnerability | CVSS | Exploitability (1-5) | Impact (1-5) | Exposure (1-5) | Risk Total |
|---|--------------|------|---------------------|-------------|---------------|-----------|
| 1 | Bind Shell Backdoor Detection | 9.8 | 5 | 5 | 4 | **14** |
| 2 | VNC Server 'password' Password | 10.0 | 5 | 5 | 4 | **14** |
| 3 | Apache Tomcat AJP — Ghostcat | 9.8 | 4 | 4 | 4 | **12** |
| 4 | Unencrypted Telnet Server | 6.5 | 5 | 3 | 4 | **12** |
| 5 | NFS Shares World Readable | 7.5 | 4 | 3 | 4 | **11** |

### Final Priority Ranking

```
Rank 1  Bind Shell Backdoor Detection          Risk Score: 14  CVSS: 9.8  Critical
Rank 2  VNC Server 'password' Password         Risk Score: 14  CVSS: 10.0 Critical
Rank 3  Apache Tomcat AJP — Ghostcat           Risk Score: 12  CVSS: 9.8  Critical
Rank 4  Unencrypted Telnet Server              Risk Score: 12  CVSS: 6.5  Medium
Rank 5  NFS Shares World Readable              Risk Score: 11  CVSS: 7.5  High
```

Key observations from this ranking:
- The CVSS 10.0 finding (VNC) ranks second, not first — because the Bind Shell is confirmed exploited by the scanner itself
- The CVSS 6.5 Medium finding (Telnet) scores equal to the CVSS 9.8 Critical (Ghostcat)
- The CVSS 7.5 High finding (NFS) ranks last despite its higher severity label than Telnet
- A CVSS-sorted list would produce a completely different and less accurate priority order

---

## 5. Individual Justifications

### Rank 1 — Bind Shell Backdoor Detection

**Plugin:** 51988 | **CVSS:** 9.8 | **Port:** 1524/tcp (wild_shell) | **Risk Score: 14**

**Exploitability — 5/5**
Connecting to port 1524 with a single netcat command immediately delivers a root-level interactive shell with no credentials, no exploit framework, and no special conditions. The Nessus scanner itself demonstrated this by executing the `id` command remotely during the scan and receiving `uid=0(root) gid=0(root) groups=0(root)` as output. Exploitation requires one command and completes in under one second.

**Impact — 5/5**
The attacker receives immediate and unrestricted root access to the entire system. All files, processes, credentials stored on disk, network connections, and configuration data are fully accessible. The attacker can read, modify, or destroy any data, install persistent access mechanisms, or use the host as a pivot point into other systems on the network.

**Exposure — 4/5**
Port 1524 is confirmed open and directly reachable from Kali on the `192.168.56.x` host-only network. There are no firewall rules or authentication layers between Kali and this port. The service is not internet-facing, which limits the score to 4.

**Conclusion:** This is the highest-priority finding on the host. A confirmed active backdoor with root-level command execution proven by the scanner is an active incident, not a scheduled patch item. Before any other remediation takes place, this finding must be treated as evidence of compromise. The host should be isolated, forensically examined, and rebuilt.

---

### Rank 2 — VNC Server 'password' Password

**Plugin:** 61708 | **CVSS:** 10.0 | **Port:** 5900/tcp (VNC) | **Risk Score: 14**

**Exploitability — 5/5**
The VNC service is protected by the password "password" — one of the most commonly attempted credentials in any brute force or default credential attack. No exploit framework, vulnerability, or code execution technique is required. An attacker connects with any VNC client and enters the default credential. The Nessus plugin confirmed successful authentication using this password during the scan.

**Impact — 5/5**
VNC provides full graphical desktop access to the remote system. The attacker sees and controls the desktop as a logged-in user — including running applications, accessing files, opening terminals, and reading any data displayed on screen. From a VNC session, an attacker can open a terminal and gain root access trivially on an unpatched and EOL host such as this one.

**Exposure — 4/5**
The VNC service is reachable from Kali on the lab network. VNC operates over TCP and requires no prior network-layer authentication to reach the login prompt. The service is internal only, limiting the score to 4.

**Conclusion:** This finding ties with the Bind Shell at a risk score of 14. VNC ranks second because accessing it requires entering a password — one step more than connecting to an open backdoor. Both findings demand immediate parallel remediation. The VNC password must be changed to a strong credential immediately, or the service disabled entirely if remote graphical access is not operationally required.

---

### Rank 3 — Apache Tomcat AJP Connector Request Injection (Ghostcat)

**Plugin:** 134862 | **CVSS:** 9.8 | **VPR:** 8.9 | **EPSS:** 0.9447 (94.47%) | **Risk Score: 12**

**Exploitability — 4/5**
Ghostcat carries an EPSS score of 94.47%, indicating it is being exploited in the wild at a very high rate. Public exploit code is widely available across multiple frameworks. The AJP connector on port 8009 allows an unauthenticated attacker to read arbitrary files from the web application directory, including `WEB-INF/web.xml` which may expose credentials. Where file upload is possible, the vulnerability escalates to Remote Code Execution. Exploitation requires more setup than a single command, earning a score of 4 rather than 5.

**Impact — 4/5**
The baseline impact is arbitrary file read within the web application, potentially exposing credentials and configuration data. With file upload capability, impact extends to full RCE as the Tomcat service account. On this EOL host without privilege separation, RCE via Tomcat likely escalates to root. The impact score does not reach 5 because file read alone — without upload capability — does not guarantee full system compromise.

**Exposure — 4/5**
The AJP connector is reachable from Kali on the lab network, confirmed by Plugin 21186 (AJP Connector Detection) in the same Nessus report. The service is internal only.

**Conclusion:** Ghostcat ranks third based on its exceptional EPSS score of 94.47% and VPR of 8.9, which signal active real-world exploitation pressure. Despite tying in risk score with the Telnet finding, Ghostcat ranks higher because its maximum impact ceiling (RCE leading to root) is significantly greater than Telnet's (credential capture). When two findings share a risk total, the finding with the higher impact ceiling takes the higher rank.

---

### Rank 4 — Unencrypted Telnet Server

**Plugin:** 42263 | **CVSS:** 6.5 | **Port:** 23/tcp | **Risk Score: 12**

**Exploitability — 5/5**
Telnet transmits all session data — usernames, passwords, and commands — in cleartext with no encryption. An attacker on the same network segment can passively capture all Telnet traffic using a standard packet sniffer (Wireshark, tcpdump) without sending a single packet to the target. This attack is completely passive, requires no interaction with the victim system, produces no log entries on the target, and succeeds the moment any user authenticates over Telnet. There is no lower barrier to exploitation than observing unencrypted traffic.

**Impact — 3/5**
The immediate impact is credential capture for any user authenticating over Telnet. Captured credentials may be reused across SSH, web applications, databases, or other services — enabling lateral movement. The impact does not reach level 4 or 5 because the attacker requires captured credentials to escalate further, rather than receiving immediate system access directly from the exploit.

**Exposure — 4/5**
Port 23 is confirmed open by the Nessus report (Plugin 10281 — Telnet Server Detection). The service is directly reachable from Kali on the `192.168.56.x` network. Passive sniffing is viable from any host on this segment.

**Conclusion:** This is the primary example of CVSS failing to represent real risk. A CVSS 6.5 Medium finding achieves a risk score of 12, equal to the CVSS 9.8 Critical Ghostcat finding, because its exploitability is trivially passive in this flat lab network. Under CVSS-only ordering, this finding would rank last. Under risk-based ordering, it ties for third. See Section 7 for the full case study.

---

### Rank 5 — NFS Shares World Readable

**Plugin:** 42256 | **CVSS:** 7.5 | **Port:** 2049/tcp (NFS) | **Risk Score: 11**

**Exploitability — 4/5**
NFS shares are exported without access controls, meaning any client can enumerate and mount them without authentication. Exploitation requires two commands: `showmount -e 192.168.56.104` to list exported shares, then `mount -t nfs 192.168.56.104:/share /mnt/point` to mount. This is straightforward with standard Linux tools, but it is an active operation that generates network traffic and may appear in logs — unlike the passive Telnet sniff.

**Impact — 3/5**
The impact depends entirely on the content of the exported shares. In the worst case, SSH private keys, password hashes, or application credentials are exposed, enabling full system compromise. In a lower-risk case, the shares contain only application logs or web content with no sensitive value. Because the impact is conditional rather than guaranteed, it scores 3 rather than 4 or 5.

**Exposure — 4/5**
The NFS service is reachable from Kali on the lab network. Plugin 10437 (NFS Share Export List) in the Nessus report confirms that share exports are visible and accessible without authentication.

**Conclusion:** NFS World Readable ranks last in this group because its impact is conditional on what the exported shares contain. An analyst cannot assign maximum impact without first auditing the share contents. If the shares are found to contain credential files or SSH keys, this finding should be immediately reprioritised. The recommended first step is a share content audit before assigning a final remediation window.

---

## 6. Remediation Priority List

| Priority | Vulnerability | Risk Score | Recommended Action | Timeframe |
|----------|--------------|-----------|-------------------|-----------|
| 1 | Bind Shell Backdoor Detection | 14 | Treat as active compromise — isolate host, terminate process on port 1524, investigate origin, rebuild OS | Immediate |
| 2 | VNC Server 'password' Password | 14 | Change VNC password to a strong credential immediately; disable VNC service if not operationally required | Immediate |
| 3 | Apache Tomcat AJP — Ghostcat | 12 | Disable AJP connector in `server.xml` if unused; configure secret attribute if AJP is required; upgrade Tomcat | Within 24 hours |
| 4 | Unencrypted Telnet Server | 12 | Disable Telnet (port 23); replace all Telnet-based administration with SSH; enforce SSH-only policy | Within 24 hours |
| 5 | NFS Shares World Readable | 11 | Audit exported share contents immediately; apply IP-based access controls in `/etc/exports`; restrict to specific client IPs | Scheduled |

### Priority Resolution Notes

**Ranks 1 and 2 (tied at 14):** Bind Shell ranks first because the scanner confirmed active exploitation — it executed a command and received a root shell during the automated scan. VNC requires a password entry step. Both must be treated as immediate actions executed in parallel.

**Ranks 3 and 4 (tied at 12):** Ghostcat ranks above Telnet because its impact ceiling (RCE) exceeds Telnet's (credential capture). In practice, Telnet remediation — disabling a single service — will complete faster than Tomcat reconfiguration and should be executed first despite the lower rank, as it is lower effort and removes an active credential exposure risk.

**Rank 5:** A content audit of the NFS exports must occur before the final remediation window is set. If sensitive files are found, this finding should be moved to the immediate tier.

---

## 7. Case Study — Medium CVSS Outranking a High

### The Comparison

| | Unencrypted Telnet Server | NFS Shares World Readable |
|-|--------------------------|--------------------------|
| CVSS Score | 6.5 (Medium) | 7.5 (High) |
| Risk Score | 12 | 11 |
| Exploitability | 5/5 | 4/5 |
| Impact | 3/5 | 3/5 |
| Exposure | 4/5 | 4/5 |
| Final Rank | 4th | 5th (last) |

### Why the Medium CVSS Outranks the High CVSS

By CVSS score, NFS Shares World Readable (7.5 High) should be prioritised above Unencrypted Telnet Server (6.5 Medium). In this lab environment, that ordering is incorrect.

**Telnet (CVSS 6.5) scores higher because of exploitability:**

Capturing Telnet credentials requires no interaction with the target, no authentication attempt, and no exploit. An attacker running Wireshark on the `192.168.56.x` network observes all Telnet traffic in cleartext passively. The attack is silent, generates no target-side log entries, and succeeds automatically whenever any user authenticates over Telnet. Exploitability is 5 — the maximum.

**NFS (CVSS 7.5) scores lower because exploitation is active:**

Exploiting NFS requires actively enumerating exports with `showmount` and mounting with the `mount` command. Both actions are auditable — they generate network traffic to port 2049 and may appear in NFS server logs. Additionally, the impact depends on what the shares contain. If the shares hold only non-sensitive application data, the actual harm from a successful mount is minimal. Exploitability is 4 and impact is conditional, producing a lower risk total.

**Why CVSS does not capture this difference:**

The CVSS scoring system assigns Attack Complexity and Attack Vector based on the vulnerability mechanism in isolation. Both Telnet and NFS are scored as network-accessible with low attack complexity — an accurate description of the mechanism. However, CVSS does not differentiate between an attack that is passive and invisible versus one that is active and auditable. In an environment with network monitoring and IDS, the NFS mount would generate an alert. The Telnet credential capture would not. Risk-based scoring captures this operational distinction; CVSS does not.

**The general principle this illustrates:**

A finding rated Medium CVSS can outrank a High CVSS when its real-world exploitability is higher in the specific environment. CVSS is a property of the vulnerability. Risk score is a property of the vulnerability in your environment. The same finding can carry entirely different priority levels depending on network topology, monitoring capability, and asset context.

---

## 8. Key Learning — Risk vs Severity

### CVSS-Sorted Order vs Risk-Sorted Order

CVSS-only priority order for these five findings:

```
1. VNC 'password' Password          CVSS 10.0  Critical
2. Bind Shell Backdoor              CVSS  9.8  Critical
2. Ghostcat (AJP)                   CVSS  9.8  Critical
4. NFS Shares World Readable        CVSS  7.5  High
5. Unencrypted Telnet Server        CVSS  6.5  Medium
```

Risk-based priority order produced in this lab:

```
1. Bind Shell Backdoor              Risk 14   CVSS  9.8  Critical
2. VNC 'password' Password          Risk 14   CVSS 10.0  Critical
3. Ghostcat (AJP)                   Risk 12   CVSS  9.8  Critical
4. Unencrypted Telnet Server        Risk 12   CVSS  6.5  Medium
5. NFS Shares World Readable        Risk 11   CVSS  7.5  High
```

Differences between the two orderings:
- CVSS places VNC first (10.0 is the highest score). Risk places Bind Shell first because confirmed command execution outweighs a password that still needs to be guessed.
- CVSS places Telnet last (6.5). Risk places Telnet above NFS because passive sniffing scores 5 on exploitability versus NFS at 4.
- CVSS places NFS fourth (7.5 High above 6.5 Medium). Risk places NFS last because its impact is conditional while Telnet's exploitability is guaranteed.

### What the Scoring Dimensions Add

| Dimension | What It Captures That CVSS Does Not |
|-----------|-------------------------------------|
| Exploitability | Whether exploitation is passive or active; whether it leaves audit trails; real skill required in your environment |
| Impact | Whether the worst case is guaranteed or conditional on content, configuration, or follow-on steps |
| Exposure | Whether the service is actually reachable from the likely attacker position given your network topology |

### The Analyst Standard

A CVSS score describes a vulnerability's properties in a standardised, context-free way. A risk score describes what an attacker can realistically do with that vulnerability given your specific network, tools, and asset context. The same CVE can be a Priority 1 emergency on a public-facing production server and an Accepted Risk on an isolated test machine. CVSS cannot make that distinction. Risk-based prioritisation can.

Submitting a CVSS-sorted vulnerability list as a remediation plan is not analysis — it is formatting. The value an analyst provides is the judgment applied to convert a list of findings into a ranked action plan that reflects the actual threat landscape of the organisation they are protecting.

