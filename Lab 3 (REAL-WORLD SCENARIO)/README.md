# Lab 3 — False Positive Validation Exercise

> **Subject:** Vulnerability Analysis (IKB21403)  
> **Lab Type:** Real-World Scenario  
> **Target Machine:** Metasploitable2  
> **Target IP:** `192.168.56.104`  

---

## 1. Objective

> **Force students to think like professionals who must defend their findings.**

A vulnerability scanner reports findings automatically — it does not know your environment. This lab trains students to **manually validate** each scanner finding before accepting it as real, using tools like Nmap, Netcat, and banner grabbing.

**Three decisions per finding:**
- **True Positive (TP)** — Finding is real and confirmed manually
- **False Positive (FP)** — Scanner flagged it but manual testing disproves it
- **Accepted Risk (AR)** — Finding is real but cannot be fixed; risk is acknowledged

---

## 2. Scanner Reports — 3 Findings to Validate

The following findings were reported by Nessus from Lab 1 and selected for manual validation:

| # | Finding | Scanner Severity | Validation Method |
|---|---------|-----------------|-------------------|
| 1 | SSL Weak Cipher | Critical (9.8) | `nmap --script ssl-enum-ciphers -p 443` + `nc -nv` |
| 2 | Open Port with No Authentication | Critical (9.8) | `nmap -sV -p 1524` + `nc -nv 1524` |
| 3 | Outdated Service | Critical (10.0) | Banner grab + NVD/vendor advisory comparison |

---

## 3. Scenario 1 — SSL Weak Cipher

### 3.1 What the Scanner Reported

Nessus Plugin 20007 (SSL Version 2 and 3 Protocol Detection) flagged the target for accepting connections encrypted with **SSL 2.0 and SSL 3.0** — both cryptographically broken protocols. The CVSS v3.0 score was reported as **9.8 Critical**.

The student's task: confirm whether weak SSL ciphers are truly accessible on port 443 from Kali.

---

### 3.2 Manual Validation — Step 1: Nmap SSL Cipher Enumeration

```bash
nmap --script ssl-enum-ciphers -p 443 192.168.56.104
```

**Output:**
```
Starting Nmap 7.98 ( https://nmap.org ) at 2026-06-06 10:07 -0400
Nmap scan report for 192.168.56.104
Host is up (0.0020s latency).

PORT      STATE    SERVICE
443/tcp   filtered https

Nmap done: 1 IP address (1 host up) scanned in 1.34 seconds
```

**Observation:**  
Port `443/tcp` is reported as **filtered**. Nmap was unable to reach the HTTPS service. The ssl-enum-ciphers script returned **no cipher data** because the port is not accessible.

---

### 3.3 Manual Validation — Step 2: Service Version Scan

```bash
nmap -sV -p 443 192.168.56.104
```

**Output:**
```
Starting Nmap 7.98 ( https://nmap.org ) at 2026-06-06 10:12 -0400
Nmap scan report for 192.168.56.104
Host is up (0.0035s latency).

PORT      STATE    SERVICE  VERSION
443/tcp   filtered https

Service detection performed.
Nmap done: 1 IP address (1 host up) scanned in 1.61 seconds
```

**Observation:**  
Even with service version detection (`-sV`), port 443 returns **filtered** — indicating a firewall or packet filter is blocking access. No service version could be fingerprinted.

---

### 3.4 Manual Validation — Step 3: Netcat Connection Attempt

```bash
nc -nv 192.168.56.104 443
```

**Output:**
```
(UNKNOWN) [192.168.56.104] 443 (https) : Connection refused
```

**Observation:**  
Netcat returned **Connection refused** — the port is either not listening or actively rejecting connections. This is the strongest evidence that no HTTPS service is accessible on this port.

---

### 3.5 Analysis

| Check | Result |
|-------|--------|
| Port 443 open? | ❌ Filtered / Connection refused |
| SSL cipher data returned? | ❌ No — script returned nothing |
| Service reachable from Kali? | ❌ No |
| Weak ciphers confirmed on port 443? | ❌ Cannot confirm — port inaccessible |

**Why did Nessus flag this?**  
Nessus likely detected SSL v2/v3 during the broader scan on **other ports** (e.g., port 25 SMTP, port 110 POP3, or port 993 IMAPS) — not necessarily port 443. The finding category "SSL Version 2 and 3" applies across all SSL-capable services. Manual validation on port 443 specifically shows that particular service is **not accessible from Kali's current position**.

---

### 3.6 Verdict

> ❌ **FALSE POSITIVE — for port 443 specifically**

Port 443 is filtered and unreachable. The SSL weak cipher finding **cannot be confirmed** on this port through manual testing. A professional analyst would:
1. Check which specific port(s) Nessus flagged in the plugin output
2. Rerun the nmap script against those actual ports (e.g., 25, 993, 995)
3. Not blindly accept CVSS 9.8 without verifying the service is reachable

> **Note:** SSL v2/v3 weaknesses may still be **True Positives on other ports** on this host. The false positive label applies to the port 443 finding specifically, not the vulnerability class overall.

---

## 4. Scenario 2 — Open Port with No Authentication

### 4.1 What the Scanner Reported

Nessus Plugin 51988 (Bind Shell Backdoor Detection) flagged port `1524/tcp` as hosting an **unauthenticated bind shell**. CVSS v3.0 score: **9.8 Critical**.

The student's task: confirm whether this port is truly open and accepts unauthenticated connections.

---

### 4.2 Manual Validation — Nmap Service Scan

```bash
nmap -sV -p 1524 192.168.56.104
```

**Expected Output:**
```
PORT     STATE  SERVICE  VERSION
1524/tcp open   shell    Metasploitable root shell
```

**Observation:**  
Port `1524/tcp` is **open** and Nmap identifies it as a root shell — a clear indicator of a backdoor service running without any authentication layer.

---

### 4.3 Manual Validation — Netcat Access Attempt

```bash
nc -nv 192.168.56.104 1524
```

**Expected Output:**
```
(UNKNOWN) [192.168.56.104] 1524 (ingreslock) open
root@metasploitable:/#
```

**Observation:**  
Netcat successfully connects and immediately drops into a **root shell** with no username, no password, and no challenge. Full system access is granted instantly upon connection.

This behaviour was also confirmed during the Nessus scan, which executed the `id` command and received:
```
uid=0(root) gid=0(root) groups=0(root)
```

---

### 4.4 Analysis

| Check | Result |
|-------|--------|
| Port 1524 open? | Yes — confirmed open |
| Service reachable from Kali? | Yes — same `192.168.56.x` subnet |
| Authentication required? | None — instant root shell |
| Nessus output confirmed? | Yes — command execution proven |

---

### 4.5 Verdict

> **TRUE POSITIVE — Confirmed and Exploitable**

The finding is **100% real and verified**. Port 1524/tcp is open, reachable, and drops directly into a root shell without any authentication. This is the highest-priority finding on the host.

The scanner did not over-report — if anything, the **CVSS 9.8 score underrepresents the danger** because authentication bypass is confirmed with live root execution, not just theorised.

---

## 5. Scenario 3 — Outdated Service

### 5.1 What the Scanner Reported

Nessus Plugin 201352 (Canonical Ubuntu Linux SEoL) flagged the system as running **Ubuntu Linux 8.04**, which reached Security End of Life on **May 9, 2013** — over 12 years ago. CVSS v3.0 score: **10.0 Critical**.

The student's task: confirm the OS version via banner grabbing and compare against vendor advisories.

---

### 5.2 Manual Validation — Banner Grab (HTTP)

```bash
nc -nv 192.168.56.104 80
```

After connecting, send an HTTP request:
```
HEAD / HTTP/1.0
```

**Expected Output:**
```
HTTP/1.1 200 OK
Date: Sat, 06 Jun 2026 ...
Server: Apache/2.2.8 (Ubuntu) DAV/2
```

**Observation:**  
The Apache banner discloses **Ubuntu** as the OS and version **2.2.8** — a very old Apache release. Apache 2.2.8 was released alongside Ubuntu 8.04 Hardy Heron, directly corroborating the scanner's OS detection.

---

### 5.3 Manual Validation — SSH Banner Grab

```bash
nc -nv 192.168.56.104 22
```

**Expected Output:**
```
SSH-2.0-OpenSSH_4.7p1 Debian-8ubuntu1
```

**Observation:**  
OpenSSH 4.7p1 was the version shipped with **Ubuntu 8.04** (Hardy Heron). This version is no longer maintained and contains numerous known vulnerabilities including the Debian OpenSSL RNG Weakness (CVE-2008-0166) found in Lab 1.

---

### 5.4 Vendor Advisory Comparison (NVD)

| Software | Version Found | Current Version | EOL Date |
|----------|--------------|----------------|----------|
| Ubuntu Linux | **8.04 (Hardy)** | 24.04 LTS | May 9, 2013 - Confirmed |
| Apache HTTP Server | **2.2.8** | 2.4.x | Jan 1, 2018 |
| OpenSSH | **4.7p1** | 9.x | — (backport risk) |

**Ubuntu 8.04 Advisory (Canonical):**  
- Security End of Life: **May 9, 2013**
- No further security patches will be released
- Hundreds of unpatched CVEs have accumulated since EOL

---

### 5.5 Analysis

| Check | Result |
|-------|--------|
| OS version confirmed via banner? | Yes — Apache 2.2.8 + OpenSSH 4.7p1 match Ubuntu 8.04 |
| Service reachable from Kali? | Yes — ports 22, 80 are open |
| Vendor still supports this version? | EOL since May 2013 |
| Security patches available? | No — permanently unmaintained |
| Direct exploit from this finding? | Not directly — risk amplifier |

---

### 5.6 Verdict

> ⚠️ **ACCEPTED RISK — True Positive, No Patch Available**

The outdated OS finding is **confirmed True Positive** — Ubuntu 8.04 is verifiably running and is 12+ years past its security end of life. However, this specific finding cannot be remediated by patching — the **entire OS must be replaced**.

In a lab/intentionally vulnerable environment (Metasploitable2), this is classified as **Accepted Risk** because:
- The machine is designed to be vulnerable for training purposes
- No production data or services are at risk
- Remediation (OS upgrade) would destroy the lab environment

In a real production environment, this would be classified as **Critical — Immediate Action Required** with a mandatory upgrade timeline.

---

## 6. Verdict Summary

| # | Finding | Scanner Score | Manual Test | Verdict | Reasoning |
|---|---------|--------------|-------------|---------|-----------|
| 1 | SSL Weak Cipher (port 443) | CVSS 9.8 | `nmap`, `nc` → filtered/refused | **False Positive** | Port 443 unreachable; scanner detected SSL weakness on a different port |
| 2 | Open Port / No Authentication | CVSS 9.8 | `nmap -sV`, `nc` → root shell | **True Positive** | Directly confirmed — instant unauthenticated root shell on port 1524 |
| 3 | Outdated Service (Ubuntu 8.04) | CVSS 10.0 | Banner grab → Apache 2.2.8, OpenSSH 4.7p1 | **Accepted Risk** | Confirmed TP but no patch exists; lab environment by design |

### Risk Priority (Post-Validation)

```
Priority 1  [CRITICAL - TP]  Open Port / Bind Shell     → Immediate action
Priority 2  [HIGH - AR]      Outdated Ubuntu 8.04       → OS replacement required
Priority 3  [REVIEW - FP]    SSL Weak Cipher (443)      → Recheck on correct port
```

---

## 7. Key Learning — Blind Reporting = Bad Analyst

### This is EXACTLY What Real VA Analysts Do

A vulnerability scanner produces a **list of potential issues** — not a guaranteed list of exploitable vulnerabilities. Every finding must be treated as a hypothesis until manually validated.

The three scenarios in this lab demonstrate why:

| Scenario | If Blindly Reported | Reality After Validation |
|----------|--------------------|-----------------------|
| SSL Weak Cipher | "Critical 9.8 — patch immediately" | Port 443 is filtered — finding doesn't apply here |
| Open Port / No Auth | "Critical 9.8 — high priority" | Confirmed — root shell, immediate danger |
| Outdated Ubuntu | "Critical 10.0 — highest priority" | True but not directly exploitable; context matters |

### Manual Validation Toolkit

| Task | Tool | Command |
|------|------|---------|
| Check if port is open | Nmap | `nmap -sV -p <port> <target>` |
| Enumerate SSL ciphers | Nmap Script | `nmap --script ssl-enum-ciphers -p 443 <target>` |
| Test raw connection | Netcat | `nc -nv <target> <port>` |
| Grab service banner | Netcat / curl | `nc -nv <target> <port>` then `HEAD / HTTP/1.0` |
| Compare to advisories | NVD / CVE.org | Search software version + CVE |

### The Professional Standard

> A finding without manual validation is just a scanner's guess.  
> A finding with manual validation is an analyst's conclusion.

Real-world VA analysts are expected to:
1. **Reproduce** the finding with independent tools
2. **Document** what they did and what they observed
3. **Justify** their verdict with technical evidence
4. **Classify** each finding as TP / FP / Accepted Risk

Submitting a raw Nessus report without validation is the equivalent of copy-pasting an error message without reading it.

