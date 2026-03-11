## n8n Workflow Configuration

[<img width="506" height="871" alt="image" src="https://github.com/user-attachments/assets/3d4a088d-6e98-4a95-9d0d-2bd179ee48c9" />](https://i.imgur.com/hYn8ds6.png)

### Webhook Node
| Setting | Value |
|---------|-------|
| **Method** | `POST` |
| **Path** | `/webhook/wazuh-alerts` |
| **Response Mode** | `Immediately` |
| **Authentication** | `None` |

### IF Filter Node
| Setting | Value |
|---------|-------|
| **Condition** | `{{ $json.body.rule.level }} >= 8` |
| **True Branch** | `Continue to AI analysis` |
| **False Branch** | `NoOps` |

### AI Investigation Node
| Setting | Value |
|---------|-------|
| **Type** | `Investigation Summarization` |
| **Individual Summary Prompt** | See below ↓ |
| **Final Prompt to Combine** | See below ↓ |

```bash
# Individual Summary Prompt
You are a SOC analyst. Analyze this security alert and extract key information.

Alert Data:
- Rule: {{ $json.body.rule.description }}
- Level: {{ $json.body.rule.level }}
- Agent: {{ $json.body.agent.name }}
- Source IP: {{ $json.body.data.win.eventdata.sourceIp }}
- Destination IP: {{ $json.body.data.win.eventdata.destinationIp }}
- File Hash: {{ $json.body.data.win.eventdata.hashes }}
- Process: {{ $json.body.data.win.eventdata.image }}
- Command: {{ $json.body.data.win.eventdata.commandLine }}

Provide:
1. MITRE Tactic & Technique
2. Key findings (2-3 sentences)
3. Risk level (Critical/High/Medium/Low)
4. 2-3 immediate actions
```

```bash
# Final Prompt to Combine

Create a comprehensive investigation report using this exact format:

INCIDENT OVERVIEW
- **Rule**: {{ $json.body.rule.description }}
- **Severity Level**: {{ $json.body.rule.level }}
- **Agent**: {{ $json.body.agent.name }}
- **Timestamp**: {{ $json.body.timestamp }}

KEY INDICATORS
- **Source IP**: {{ $json.body.data.win.eventdata.sourceIp }}
- **Destination IP**: {{ $json.body.data.win.eventdata.destinationIp }}
- **File Hash**: {{ $json.body.data.win.eventdata.hashes }}
- **Process**: {{ $json.body.data.win.eventdata.image }}
- **Command Line**: `{{ $json.body.data.win.eventdata.commandLine }}`

MITRE ATT&CK MAPPING
- **Tactic**: [Extracted from analysis]
- **Technique**: [Extracted from analysis]
- **Technique ID**: [Extracted from analysis]

RISK ASSESSMENT
- **Threat Level**: [Extracted from analysis]
- **Summary**: [Extracted from analysis]

RECOMMENDED ACTIONS
- [Extracted from analysis]

RAW ALERT DATA
```json
{{ JSON.stringify($json.body, null, 2) | safe }}
```

### Telegram Node
| Setting | Value |
|---------|-------|
| **Credential** | `SOC Alert Bot (Telegram API)` |
| **Resource** | `Message` |
| **Operation** | `Send Message` |
| **Chat ID** | `[My Telegram Chat ID]` |
| **Text** | See below ↓ |

```bash
*SOC ALERT*

*Investigation Report:*
{{ $json.output.text }} 

*Sent automatically via n8n*
```

