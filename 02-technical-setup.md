# Lab Technical Setup

![Wazuh](https://img.shields.io/badge/SIEM-Wazuh-005571?style=for-the-badge&logo=wazuh&logoColor=white)
![TheHive](https://img.shields.io/badge/Case%20Management-TheHive-FF6C37?style=for-the-badge&logo=thehive&logoColor=white)
![n8n](https://img.shields.io/badge/SOAR-n8n-3b0a6b?style=for-the-badge&logo=n8n&logoColor=white)
![VirusTotal](https://img.shields.io/badge/Threat%20Intel-VirusTotal-394eef?style=for-the-badge&logo=virustotal&logoColor=white)
![AbuseIPDB](https://img.shields.io/badge/Reputation-AbuseIPDB-7b1fa2?style=for-the-badge&logo=abuseipdb&logoColor=white)
![Ubuntu](https://img.shields.io/badge/Ubuntu-24.04-E95420?style=for-the-badge&logo=ubuntu&logoColor=white)
![Windows](https://img.shields.io/badge/Windows-10-0078D6?style=for-the-badge&logo=windows&logoColor=white)
![MITRE ATT&CK](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-000000?style=for-the-badge&logo=mitre&logoColor=white)
![Atomic Red Team](https://img.shields.io/badge/Testing-Atomic%20Red%20Team-FF6F61?style=for-the-badge&logo=redhat&logoColor=white)

## Virtual Machine Specifications

| VM               | OS           | RAM | CPU Cores | Storage |
|------------------|--------------|-----|-----------|---------|
| Wazuh Manager    | Ubuntu 24.04 | 8GB | 2 Cores   | 50GB    |
| Windows Endpoint | Windows 10   | 8GB | 2 Cores   | 100GB   |
| n8n/TheHive      | Ubuntu 24.04 | 8GB | 2 Cores   | 50GB    |

## Installation Process

### Step 1: Download the Installation Script

```bash
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
sudo bash ./wazuh-install.sh -a
```

### Step 2: Creating custom rules

Add custom rules

```bash
sudo nano /var/ossec/etc/rules/local_rules.xml
```

Paste all 5 rules present in creating-rules-wazuh.md

### Step 3: Restarting Wazuh-Manager Service on Ubuntu Machine in order to apply the changes.

```bash
sudo systemctl restart wazuh-manager
```

### Step 4: Installing Wazuh Agent on Windows Machine using Powershell

```bash
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.5-1.msi -OutFile ${env.tmp}\wazuh-agent; msiexec.exe /i ${env.tmp}\wazuh-agent /q WAZUH_MANAGER='192.168.0.177' WAZUH_AGENT_NAME='VULN-WIN' WAZUH_REGISTRATION_SERVER='192.168.0.177'
```

### Step 5: Installing Sysmon via Powershell

```bash
.\Sysmon64.exe -accepteula -i sysmon-config.xml
```

### Step 6: Configure Wazuh to read Sysmon logs

Add to C:\Program Files (x86)\ossec-agent\ossec.conf:

```bash
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```
### Step 7: Installing AtomicRedTeam Framework

First of all, we bypass execution policy for our current session.

```bash
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope CurrentUser -Force
```

Install AtomicRedTeam Framework with Test Definitions

```bash
Install-AtomicRedTeam -getAtomics -Force
```



 <log_format>eventchannel</log_format>
# </localfile>
