# Lab-Week-10

# Lab 1 — Host-Based Vulnerability Assessment using Nessus Essentials

> **Subject:** Vulnerability Analysis (IKB21403)  
> **Lab Type:** Foundation  
> **Tool Used:** Tenable Nessus Essentials  
> **Target Machine:** Metasploitable2  
> **Target IP:** `192.168.56.104`  
> **Scan Date:** Saturday, 06 June 2026  
> **Student:** aienfrzna  

---

## Table of Contents

1. [Objective](#1-objective)
2. [Scope Definition](#2-scope-definition)
3. [Environment Setup](#3-environment-setup)
4. [Step-by-Step Methodology](#4-step-by-step-methodology)
5. [Scan Results Overview](#5-scan-results-overview)
6. [Top 5 Critical Vulnerabilities](#6-top-5-critical-vulnerabilities)
7. [Key Learnings](#7-key-learnings)

---

## 1. Objective

This lab demonstrates how vulnerabilities are **identified**, **classified**, and **prioritised** using an automated vulnerability scanner — not exploited.

The student learns to:
- Configure and run a host-based scan against a known vulnerable target
- Interpret CVSS scores and severity ratings
- Differentiate between genuine findings and false positives
- Export and document scan results professionally

---

## 2. Scope Definition

| Parameter | Value |
|-----------|-------|
| Scan Name | Metasploite |
| Target Host | Metasploitable2 |
| Target IP | `192.168.56.104` |
| Scanner | Kali Linux (attacker) |
| Tool | Tenable Nessus Essentials |
| Scan Template | Basic Network Scan |
| Scan Folder | My Scans |
| Purpose | Vulnerability identification and classification |

---

## 3. Environment Setup

### Network Verification — Ping Test

Before running the scan, connectivity between the Kali machine and the target was verified using `ping`.

```bash
ping 192.168.56.104
```

**Result:**
```
PING 192.168.56.104 (192.168.56.104) 56(84) bytes of data.
64 bytes from 192.168.56.104: icmp_seq=1 ttl=64 time=3.77 ms
64 bytes from 192.168.56.104: icmp_seq=2 ttl=64 time=1.73 ms
64 bytes from 192.168.56.104: icmp_seq=3 ttl=64 time=1.72 ms
...
```

✅ Target is reachable. Network connectivity confirmed.

---

## 4. Step-by-Step Methodology

| Step | Action | Details |
|------|--------|---------|
| 1 | Confirm network connectivity | Pinged `192.168.56.104` from Kali — successful |
| 2 | Choose scanning tool | Selected **Nessus Essentials** |
| 3 | Create new scan | Clicked **New Scan** in Nessus dashboard |
| 4 | Configure scan target | Name: `Metasploite` / Target: `192.168.56.104` |
| 5 | Select scan template | **Basic Network Scan** |
| 6 | Launch scan | Executed and waited for completion |
| 7 | Review results | Sorted by severity; identified Top 5 critical findings |
| 8 | Export report | Exported full results to **PDF** via Nessus |

---

## 5. Scan Results Overview

The Nessus scan against `192.168.56.104` returned a total of **110 vulnerabilities** across all severity levels.

| Severity | Count |
|----------|-------|
| 🔴 Critical | 8 |
| 🟠 High | 4 |
| 🟡 Medium | 18 |
| 🔵 Low | 7 |
| ⚪ Info | 73 |
| **Total** | **110** |

---

## 6. Top 5 Critical Vulnerabilities

The following five vulnerabilities were selected based on highest CVSS v3.0 score and real-world impact.

---

### Vulnerability 1 — Bind Shell Backdoor Detection

| Field | Details |
|-------|---------|
| **Plugin ID** | 51988 |
| **Severity** | 🔴 Critical |
| **CVSS v3.0 Score** | 9.8 |
| **CVSS v3.0 Vector** | `CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| **Port / Service** | `1524 / tcp / wild_shell` |
| **Plugin Family** | Backdoors |
| **CVE** | N/A |
| **Published** | February 15, 2011 |

**Description:**  
A shell is listening on a remote port (`1524/tcp`) without any authentication. An attacker can connect to this port and send commands directly to the system, effectively gaining full shell access as `root`.

**Nessus Output:**
```
Nessus was able to execute the command "id" using the following request:
root@metasploitable:/# uid=0(root) gid=0(root) groups=0(root)
```

**Solution:**  
Verify if the remote host has been compromised. Reinstall the operating system if a backdoor is confirmed.

**Risk Assessment:**  
This is a **confirmed active backdoor** — Nessus executed a live command and received a root shell response. This is not a false positive. Immediate remediation required.

---

### Vulnerability 2 — Canonical Ubuntu Linux SEoL (8.04.x)

| Field | Details |
|-------|---------|
| **Plugin ID** | 201352 |
| **Severity** | 🔴 Critical |
| **CVSS v3.0 Score** | 10.0 |
| **CVSS v3.0 Vector** | `CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` |
| **Port / Service** | `80 / tcp / www` |
| **Plugin Family** | General |
| **CVE** | N/A |
| **Published** | July 3, 2024 |

**Description:**  
The system is running **Ubuntu Linux 8.04**, which reached Security End of Life (SEoL) on **May 9, 2013** — over 12 years ago. No further security patches will be released by Canonical. The system is permanently exposed to all unpatched vulnerabilities discovered since that date.

**Nessus Output:**
```
OS                              : Ubuntu Linux 8.04
Security End of Life            : May 9, 2013
Time since Security End of Life : >= 12 years
```

**Solution:**  
Upgrade to a currently supported version of Ubuntu Linux (e.g., Ubuntu 22.04 LTS or 24.04 LTS).

**Risk Assessment:**  
Running an end-of-life OS means every new CVE discovered has no patch path. This significantly amplifies the risk of every other vulnerability found on this host.

---

### Vulnerability 3 — Debian OpenSSH/OpenSSL Package Random Number Generator Weakness

| Field | Details |
|-------|---------|
| **Plugin ID** | 32314 |
| **Severity** | 🔴 Critical |
| **CVSS v2.0 Score** | 10.0 |
| **CVE** | **CVE-2008-0166** |
| **CWE** | 310 |
| **Port / Service** | `22 / tcp / ssh` |
| **Plugin Family** | Gain a shell remotely |
| **VPR Score** | 5.1 |
| **EPSS Score** | 0.0165 |
| **Exploit Available** | ✅ Yes (Core Impact) |

**Description:**  
A bug in Debian/Ubuntu's OpenSSL package caused the random number generator (RNG) to be seeded with only the process ID (PID). This drastically reduces the entropy used to generate cryptographic keys, making all SSH, SSL, and OpenVPN keys generated on affected systems **predictable and guessable** by an attacker.

An attacker can:
- Obtain the private portion of the remote SSH key
- Decrypt remote sessions
- Perform man-in-the-middle attacks

**Solution:**  
Regenerate all cryptographic material on the host — all SSH, SSL, and OpenVPN keys must be considered compromised and reissued.

**Risk Assessment:**  
Active exploits exist for this vulnerability. Keys generated on this host cannot be trusted. This is a high-priority finding with real exploitation potential.

---

### Vulnerability 4 — SSL Version 2 and 3 Protocol Detection

| Field | Details |
|-------|---------|
| **Plugin ID** | 20007 |
| **Severity** | 🔴 Critical |
| **CVSS v3.0 Score** | 9.8 |
| **CVSS v3.0 Vector** | `CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| **Port / Service** | Multiple SSL/TLS ports |
| **Plugin Family** | Service Detection |
| **CVE** | N/A |
| **Published** | October 12, 2005 |

**Description:**  
The remote host accepts connections encrypted with **SSL 2.0 and/or SSL 3.0** — both of which are cryptographically broken protocols. Known flaws include:

- Insecure padding scheme with CBC ciphers
- Insecure session renegotiation and resumption
- Susceptibility to POODLE attacks (downgrade attacks forcing SSLv3)

NIST has determined that SSL 3.0 is no longer acceptable for secure communications and fails PCI DSS v3.1 definitions of "strong cryptography."

**Solution:**  
Disable SSL 2.0 and SSL 3.0 entirely. Configure the service to use **TLS 1.2** (with approved cipher suites) or **TLS 1.3** instead.

**Risk Assessment:**  
Encrypted communications over this host can potentially be intercepted or decrypted by a man-in-the-middle attacker. This affects all services using these deprecated protocol versions.

---

### Vulnerability 5 — Apache Tomcat AJP Connector Request Injection (Ghostcat)

| Field | Details |
|-------|---------|
| **Plugin ID** | 134862 |
| **Severity** | 🔴 Critical |
| **CVSS v3.0 Score** | 9.8 |
| **VPR Score** | 8.9 |
| **EPSS Score** | 0.9447 (94.47%) |
| **Port / Service** | AJP Connector |
| **Plugin Family** | Web Servers |

**Description:**  
The **Ghostcat** vulnerability (CVE-2020-1938) affects the Apache JServ Protocol (AJP) connector in Apache Tomcat. An unauthenticated attacker can read files from the web application, including configuration files, or in certain configurations, achieve Remote Code Execution (RCE) by uploading a malicious file and triggering inclusion via AJP.

With an EPSS score of **94.47%**, this vulnerability has an extremely high probability of being exploited in the wild.

**Solution:**  
- Disable the AJP connector if not in use (comment out the `<Connector port="8009" protocol="AJP/1.3">` line in `server.xml`)
- If AJP must be used, configure it with a required secret attribute
- Upgrade Apache Tomcat to a patched version

**Risk Assessment:**  
Ghostcat is one of the most actively exploited Tomcat vulnerabilities. The near-100% EPSS score confirms active real-world exploitation. High priority for patching.

---

## 7. Key Learnings

### Finding ≠ Real Risk
Not every finding from a vulnerability scanner represents an immediate or exploitable risk. Scanners report based on version detection and plugin logic — some results may be:
- **False positives** — reported as vulnerable due to version banner but patched via backport
- **Informational only** — no direct exploitability without specific conditions
- **Context-dependent** — a vulnerability on an internal-only service carries less risk than one exposed to the internet

In this lab, **Vulnerability 1 (Bind Shell Backdoor)** is a confirmed true positive — Nessus executed a command and received a live root shell. In contrast, some medium/low findings may be false positives if security patches were backported without version bumps.

### Why False Positives Exist
| Reason | Explanation |
|--------|-------------|
| **Version-based detection** | Nessus checks version strings; a patched v1.0.1 may still report as "vulnerable v1.0.1" |
| **Backported patches** | Debian/Ubuntu often backport security fixes without changing version numbers |
| **Generic plugin logic** | Some plugins flag any service matching a pattern regardless of actual config |
| **Missing credentials** | Unauthenticated scans can't verify patch status — credentialed scans are more accurate |

---

## References

| Resource | Link |
|----------|------|
| Nessus Plugin 51988 | Bind Shell Backdoor |
| Nessus Plugin 201352 | Ubuntu SEoL |
| CVE-2008-0166 | Debian OpenSSL RNG Weakness |
| Nessus Plugin 20007 | SSL v2/v3 Detection |
| CVE-2020-1938 | Apache Tomcat Ghostcat (AJP) |
| CVSS v3.0 Calculator | https://www.first.org/cvss/calculator/3.0 |
| NVD CVE Database | https://nvd.nist.gov/vuln/search |

---

*Report generated based on Nessus Essentials scan — IKB21403 Vulnerability Analysis, UniKL MIIT, March 2025 Intake*
