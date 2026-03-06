## Network Architecture Overview

<img width="506" height="871" alt="image" src="https://github.com/user-attachments/assets/3d4a088d-6e98-4a95-9d0d-2bd179ee48c9" />

**Note**: Kali Linux will be implemented in a future phase as part of a dedicated penetration testing project.

## VM Resource Summary

| VM               | IP Address    | RAM | CPU Cores | Storage | Status  | Purpose             |
|------------------|---------------|-----|-----------|---------|---------|---------------------|
| Wazuh Manager    | 192.168.0.177 | 8GB | 2 cores   | 50GB    | Active  | SIEM + Detection    |
| Windows Endpoint | 192.168.0.175 | 8GB | 2 cores   | 120GB   | Active  | Telemetry + Testing |
| n8n+TheHive      | 192.168.0.185 | 8GB | 2 cores   | 50GB    | Active  | SOAR + Cases        |
| Kali Linux       | N/A           | N/A | N/A       | N/A     | Planned | Pentest Project     |

## VM Resource Summary

| Source | Destination | Port | Protocol | Purpose |
|--------|-------------|------|----------|---------|
| Windows (192.168.0.175) | Wazuh (192.168.0.177) | 1514 | TCP/UDP | Agent connection |
| Windows (192.168.0.175) | Wazuh (192.168.0.177) | 55000 | TCP | Agent enrollment |
| Wazuh (192.168.0.177) | n8n (192.168.0.185) | 5678 | HTTP | Webhook alerts |
| n8n (192.168.0.185) | VirusTotal | 443 | HTTPS | Hash/URL reputation |
| n8n (192.168.0.185) | AbuseIPDB | 443 | HTTPS | IP reputation |
| n8n (192.168.0.185) | TheHive (localhost) | 9000 | HTTP | Case creation |

## Active Detection Rules (MITRE ATT&CK Mapped)

| Rule ID | MITRE Tactic | MITRE Technique | Description | Level |
|---------|--------------|-----------------|-------------|-------|
| **100001** | Execution (TA0002) | T1059.001 | PowerShell Download Detection | 8 |
| **100002** | Credential Access (TA0006) | T1003.001 | Mimikatz Credential Dumping | 14 |
| **100003** | Defense Evasion (TA0005) | T1562.001 | Windows Defender Disable Attempt | 12 |
| **100004** | Persistence (TA0003) | T1053.005 | Scheduled Task Creation | 8 |
| **100005** | Command & Control (TA0011) | T1095 | Netcat C2 Connection | 12 |

