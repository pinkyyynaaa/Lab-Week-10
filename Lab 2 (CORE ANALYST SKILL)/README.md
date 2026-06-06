# Lab 2 — CVE, CVSS & CWE Correlation Lab (Manual Analysis)

> **Subject:** Vulnerability Analysis (IKB21403)  
> **Lab Type:** Core Analyst Skill  
> **Target Machine:** Metasploitable2  
> **Target IP:** `192.168.56.104`  

---

## Table of Contents

1. [Objective](#1-objective)
2. [Findings Selected from Lab 1](#2-findings-selected-from-lab-1)
3. [Finding 1 — Bind Shell Backdoor Detection](#3-finding-1--bind-shell-backdoor-detection)
4. [Finding 2 — Canonical Ubuntu Linux SEoL (8.04.x)](#4-finding-2--canonical-ubuntu-linux-seol-804x)
5. [Finding 3 — SSL Version 2 and 3 Protocol Detection](#5-finding-3--ssl-version-2-and-3-protocol-detection)
6. [Comparative Summary](#6-comparative-summary)
7. [Key Learning — CVSS ≠ Actual Business Risk](#7-key-learning--cvss--actual-business-risk)

---

## 1. Objective

Train students to **understand findings, not blindly trust scanners.**

This lab requires manual interpretation of 3 vulnerabilities selected from Lab 1. For each finding, the student must:

- Look up the CVE on CVE.org and cross-check on NVD
- Break down the CVSS vector string (Attack Vector, Privileges Required, User Interaction)
- Map to the corresponding CWE
- Evaluate exploitability **within this specific lab environment**
- Write a conclusion: **likely exploitable / not exploitable + reasoning**

---

## 2. Findings Selected from Lab 1

Three findings were chosen from different vulnerability categories to ensure diverse analysis:

| # | Vulnerability | Plugin | Category | CVSS v3.0 |
|---|--------------|--------|----------|-----------|
| 1 | Bind Shell Backdoor Detection | 51988 | Service / Backdoor | 9.8 |
| 2 | Canonical Ubuntu Linux SEoL (8.04.x) | 201352 | OS / General | 10.0 |
| 3 | SSL Version 2 and 3 Protocol Detection | 20007 | Crypto / Service Detection | 9.8 |

> These cover three distinct categories: **service backdoor**, **OS lifecycle risk**, and **cryptographic weakness** — giving a well-rounded cross-section for analysis.

---

## 3. Finding 1 — Bind Shell Backdoor Detection

### 3.1 Basic Information

| Field | Details |
|-------|---------|
| **Plugin ID** | 51988 |
| **Severity** | Critical |
| **CVSS v3.0 Score** | 9.8 |
| **CVE** | N/A (generic backdoor detection — no specific CVE assigned) |
| **CWE** | CWE-912: Hidden Functionality |
| **Port / Service** | `1524 / tcp / wild_shell` |
| **Plugin Family** | Backdoors |

---

### 3.2 CVSS Vector Breakdown

**Vector String:** `CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

| Metric | Value | Meaning |
|--------|-------|---------|
| **Attack Vector (AV)** | Network (N) | Exploitable remotely over the network — no physical access needed |
| **Attack Complexity (AC)** | Low (L) | No special conditions required — straightforward to exploit |
| **Privileges Required (PR)** | None (N) | Attacker needs **zero** prior credentials or access |
| **User Interaction (UI)** | None (N) | Victim does not need to do anything — fully remote, unaided |
| **Scope (S)** | Unchanged (U) | Impact stays within the vulnerable component |
| **Confidentiality (C)** | High (H) | Full read access to all system data |
| **Integrity (I)** | High (H) | Full ability to modify system data |
| **Availability (A)** | High (H) | Full ability to crash or disable the system |

---

### 3.3 CVE / NVD Lookup

No CVE is assigned to this finding. Plugin 51988 is a **generic Nessus detection plugin** that identifies any unauthenticated bind shell listening on a remote port — regardless of what malware or misconfiguration caused it. The absence of a CVE does not reduce severity; it is a confirmed active backdoor.

**CWE-912 — Hidden Functionality:**  
The software contains functionality that is not documented or intended for legitimate users, allowing an attacker to access it without authentication.

---

### 3.4 Exploitability in This Lab Environment

| Check | Result |
|-------|--------|
| Is the vulnerable service running? | Yes — port `1524/tcp` is open |
| Is the port reachable from Kali? | Yes — same network segment (`192.168.56.x`) |
| Does it require auth? | No authentication required |
| Exploit complexity | None — `nc 192.168.56.104 1524` is sufficient |

**Nessus Proof of Exploitation:**
```
Nessus was able to execute the command "id":
root@metasploitable:/# uid=0(root) gid=0(root) groups=0(root)
```

### Conclusion: LIKELY EXPLOITABLE

This is the most dangerous finding in the scan. Nessus confirmed exploitation by executing a live command and receiving a **root shell** response. No credentials, no exploit code, no complexity required — simply connecting to port 1524 grants full root access.

In this lab environment, an attacker on `192.168.56.x` can gain complete system control in one step. This is not a theoretical risk — **it has already been demonstrated by the scanner itself.**

> **CVSS vs. Reality:** The CVSS score of 9.8 accurately reflects this risk in this case. The score and real-world exploitability align.

---

## 4. Finding 2 — Canonical Ubuntu Linux SEoL (8.04.x)

### 4.1 Basic Information

| Field | Details |
|-------|---------|
| **Plugin ID** | 201352 |
| **Severity** | Critical |
| **CVSS v3.0 Score** | 10.0 |
| **CVE** | N/A (lifecycle/configuration finding) |
| **CWE** | CWE-1104: Use of Unmaintained Third-Party Components |
| **Port / Service** | `80 / tcp / www` |
| **OS End of Life** | May 9, 2013 |
| **Time Since EOL** | ≥ 12 years |

---

### 4.2 CVSS Vector Breakdown

**Vector String:** `CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`

| Metric | Value | Meaning |
|--------|-------|---------|
| **Attack Vector (AV)** | Network (N) | Accessible remotely |
| **Attack Complexity (AC)** | Low (L) | No special conditions |
| **Privileges Required (PR)** | None (N) | No credentials needed |
| **User Interaction (UI)** | None (N) | No victim action required |
| **Scope (S)** | **Changed (C)** | Impact extends beyond the vulnerable component to other systems |
| **Confidentiality (C)** | High (H) | Full data disclosure possible |
| **Integrity (I)** | High (H) | Full data manipulation possible |
| **Availability (A)** | High (H) | Full denial of service possible |

> Note: The **Scope: Changed** metric pushes this to a perfect 10.0 — it reflects that a compromised EOL OS can impact other connected systems.

---

### 4.3 CVE / NVD Lookup

No single CVE is assigned. This plugin reports an **organisational/operational risk**, not a specific software bug. The finding flags that the OS has not received any security patches since 2013, meaning:

- Every CVE discovered in Ubuntu 8.04 components after May 2013 is **permanently unpatched**
- There is no remediation path except OS upgrade

**CWE-1104 — Use of Unmaintained Third-Party Components:**  
The product relies on a component that is no longer maintained by its developer, which means no security updates will be provided.

---

### 4.4 Exploitability in This Lab Environment

| Check | Result |
|-------|--------|
| Is the vulnerable service running? | Yes — Ubuntu 8.04 is the base OS |
| Is the port reachable from Kali? | Yes — port 80 and others are open |
| Does it require auth? | Depends on which unpatched CVE is targeted |
| Direct exploit from this finding alone? | Not directly — it is a risk multiplier |

### Conclusion: NOT DIRECTLY EXPLOITABLE — BUT CRITICAL RISK AMPLIFIER

This finding does **not** represent a single exploitable bug. You cannot run an exploit titled "EOL Ubuntu" — there is no payload for it.

However, it is **critically important** because it means every other vulnerability on this host has **no patch path**. The 8+ other critical findings in this scan cannot be fixed by applying updates — the OS itself must be replaced.

In this lab environment, the EOL status amplifies the real risk of Finding 1 (Bind Shell) and Finding 3 (SSL) by confirming they will never be remediated through normal patching.

> **CVSS vs. Reality:** The score of 10.0 is **misleading as a standalone finding**. This is not a directly exploitable vulnerability — it is a lifecycle and maintenance risk. A security analyst must understand this distinction. CVSS score does not equal immediate exploitability.

---

## 5. Finding 3 — SSL Version 2 and 3 Protocol Detection

### 5.1 Basic Information

| Field | Details |
|-------|---------|
| **Plugin ID** | 20007 |
| **Severity** | Critical |
| **CVSS v3.0 Score** | 9.8 |
| **Related CVE** | CVE-2014-3566 (POODLE — SSLv3 downgrade) |
| **CWE** | CWE-327: Use of a Broken or Risky Cryptographic Algorithm |
| **Port / Service** | Multiple SSL/TLS ports |
| **Plugin Family** | Service Detection |

---

### 5.2 CVSS Vector Breakdown

**Vector String:** `CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

| Metric | Value | Meaning |
|--------|-------|---------|
| **Attack Vector (AV)** | Network (N) | Exploitable over the network |
| **Attack Complexity (AC)** | Low (L) | Exploitation does not require special conditions |
| **Privileges Required (PR)** | None (N) | No credentials required |
| **User Interaction (UI)** | None (N) | No victim action needed |
| **Scope (S)** | Unchanged (U) | Impact contained within the service |
| **Confidentiality (C)** | High (H) | Encrypted traffic can be decrypted |
| **Integrity (I)** | High (H) | Session data can be modified |
| **Availability (A)** | High (H) | Service can be disrupted |

---

### 5.3 CVE / NVD Lookup

**Related CVE: CVE-2014-3566 (POODLE)**

| Field | Details |
|-------|---------|
| Full Name | Padding Oracle On Downgraded Legacy Encryption |
| Published | October 14, 2014 |
| CVSS v3.0 | 3.4 (for POODLE specifically) |
| Affected | SSL 3.0 protocol — all implementations |
| Attack Type | Man-in-the-Middle (MitM) downgrade attack |

> Note: Plugin 20007 covers SSLv2 **and** SSLv3 broadly. The CVSS 9.8 score in Nessus reflects the **combined risk** of both deprecated protocols being enabled, not just POODLE.

**CWE-327 — Use of a Broken or Risky Cryptographic Algorithm:**  
The product uses a cryptographic algorithm that is considered broken, weak, or risky, which may allow an attacker to decrypt or modify protected data.

**Known attacks enabled by SSL 2.0 / 3.0:**
- **POODLE** — forces SSLv3 downgrade, exploits CBC padding oracle
- **DROWN** — decrypts modern TLS sessions using SSLv2
- **BEAST** — exploits CBC cipher flaws in TLS 1.0/SSL 3.0

---

### 5.4 Exploitability in This Lab Environment

| Check | Result |
|-------|--------|
| Is the vulnerable service running? | Yes — SSL 2.0 and 3.0 are active |
| Is the port reachable from Kali? | Yes — SSL ports are accessible |
| Does it require auth? | No — protocol-level attack |
| MitM positioning required? | Yes — attacker must be between client and server |
| Practical in this lab network? | Conditionally — requires ARP spoofing or similar on LAN |

### Conclusion: CONDITIONALLY EXPLOITABLE

The vulnerable protocol is **confirmed running** and **reachable from Kali**. However, exploiting SSL 2.0/3.0 weaknesses like POODLE or DROWN requires the attacker to be positioned **between a client and the server** (Man-in-the-Middle).

In this isolated lab environment (`192.168.56.x` host-only network), a MITM attack is technically possible using ARP spoofing (e.g., `arpspoof` or Ettercap from Kali), but requires an active client session to intercept — which is not present in a standalone lab scenario.

**The risk is real**, but exploitation is **not as immediate** as Finding 1. It requires:
1. An active victim session using the deprecated SSL protocol
2. Attacker positioned on the same network segment
3. Successful downgrade of the connection

> **CVSS vs. Reality:** The score of 9.8 **overstates the immediate risk** in this isolated lab environment. In a real-world network where users browse HTTPS sites over SSLv3 daily, this score would be more accurate. CVSS assumes a worst-case scenario — it does not account for the presence of active sessions or network topology.

---

## 6. Comparative Summary

| Finding | CVSS | CWE | CVE | Service Running | Port Reachable | Auth Required | Lab Exploitability |
|---------|------|-----|-----|----------------|---------------|---------------|-------------------|
| Bind Shell Backdoor | 9.8 | CWE-912 | None  **YES — Confirmed** |
| Ubuntu SEoL 8.04 | 10.0 | CWE-1104 | None | N/A | **Risk Amplifier Only** |
| SSL v2/v3 Detection | 9.8 | CWE-327 | CVE-2014-3566 | **Conditional (MitM needed)** |

### Exploitability Ranking (This Lab Environment)

```
1st  Bind Shell Backdoor    [CRITICAL] — Immediately exploitable, root access confirmed
2nd  SSL v2/v3 Detection    [HIGH]     — Exploitable with MitM setup, not immediate
3rd  Ubuntu SEoL            [MEDIUM]   — Not directly exploitable; amplifies all other risks
```

---

## 7. Key Learning — CVSS ≠ Actual Business Risk

This lab demonstrates a core principle of vulnerability analysis:

> **A high CVSS score does not automatically mean a finding is immediately exploitable or represents the highest priority for remediation.**

### Observations from This Lab

| Scenario | CVSS | Real Risk |
|----------|------|-----------|
| Bind Shell Backdoor (9.8) | High | **Equally high** — scanner confirmed root execution |
| Ubuntu SEoL (10.0) | Perfect score | **Medium immediate risk** — no direct exploit, but permanent patch gap |
| SSL v2/v3 (9.8) | High | **Lower immediate risk** — requires MitM conditions to exploit |

### Why CVSS Can Mislead

| Reason | Explanation |
|--------|-------------|
| **Environment not considered** | CVSS is calculated in a vacuum — it assumes worst-case conditions regardless of your network topology |
| **No active session = no MitM** | A network-based crypto attack scoring 9.8 means nothing if there are no active sessions to intercept |
| **EOL ≠ direct exploit** | CVSS 10.0 for an EOL OS reflects theoretical maximum exposure, not a specific exploit you can run |
| **False sense of urgency** | Teams that patch strictly by CVSS score may fix the wrong things first |
| **No business context** | A CVSS 9.8 on an internal-only test VM is less urgent than a CVSS 7.0 on a public-facing payment server |

### Analyst Takeaway

A skilled vulnerability analyst always asks:
- Is this service actually running?
- Is the port reachable from the likely attacker position?
- Does exploitation require conditions that don't exist here?
- What is the business value of the asset being protected?

Only after answering these questions can CVSS scores be translated into **actual prioritised remediation actions**.

---

## References

| Resource | Details |
|----------|---------|
| Nessus Plugin 51988 | Bind Shell Backdoor Detection |
| Nessus Plugin 201352 | Canonical Ubuntu Linux SEoL |
| Nessus Plugin 20007 | SSL Version 2 and 3 Protocol Detection |
| CVE-2014-3566 | POODLE SSLv3 Downgrade — NVD |
| CWE-912 | Hidden Functionality — MITRE |
| CWE-1104 | Use of Unmaintained Third-Party Components — MITRE |
| CWE-327 | Use of a Broken or Risky Cryptographic Algorithm — MITRE |
| CVSS v3.0 Spec | https://www.first.org/cvss/v3.0/specification-document |
| NVD CVE Search | https://nvd.nist.gov/vuln/search |
| CVE.org | https://www.cve.org |

---

*Manual analysis report — IKB21403 Vulnerability Analysis, UniKL MIIT, March 2025 Intake*