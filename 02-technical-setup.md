# Wazuh 4.7 Installation on Ubuntu

[![Wazuh](https://img.shields.io/badge/Wazuh-4.7-blue.svg)](https://wazuh.com)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Unix-lightgrey.svg)](https://wazuh.com)

## Prerequisites

Before starting the installation, ensure your system meets the following requirements:

- **Operating System**: Ubuntu
- **RAM**: 8GB
- **CPU**: 2 cores
- **Storage**: 50GB

## 🚀 Quick Installation

```bash
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
sudo bash ./wazuh-install.sh -a

## Add custom rules
sudo nano /var/ossec/etc/rules/local_rules.xml
# Paste all 5 rules above

# Restart Wazuh
sudo systemctl restart wazuh-manager
Windows Agent Configuration
powershell
# Install agent via Powershell
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.5-1.msi -OutFile ${env.tmp}\wazuh-agent; msiexec.exe /i ${env.tmp}\wazuh-agent /q WAZUH_MANAGER='192.168.0.177' WAZUH_AGENT_NAME='VULN-WIN' WAZUH_REGISTRATION_SERVER='192.168.0.177' 

# Add Sysmon
.\Sysmon64.exe -accepteula -i sysmon-config.xml

# Configure Wazuh to read Sysmon logs

Add to C:\Program Files (x86)\ossec-agent\ossec.conf:

# <localfile>
#   <location>Microsoft-Windows-Sysmon/Operational</location>
#   <log_format>eventchannel</log_format>
# </localfile>
