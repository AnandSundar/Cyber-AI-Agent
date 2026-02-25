# 🔥 Agentic AI SOC Analyst / Threat Hunter

<a href="https://www.youtube.com/watch?v=vFuM--0H3qE"><img width="50" height="15" alt="image" src="https://github.com/user-attachments/assets/910838d4-5917-4bbd-8abe-9820376a5781" /></a>  Youtube Video: [https://www.youtube.com/watch?v=oWa5Wxb8w-o](https://www.youtube.com/watch?v=oWa5Wxb8w-o)

> **AI will replace bad SOC Analysts, not good ones.**

An **Agentic AI SOC Analyst / Threat Hunter** that does hours of manual work in minutes.

It can:

* 🔍 Hunt threats across Azure Log Analytics
* ⚡ Prioritize intelligently with confidence scoring
* 📝 Investigate + document findings with MITRE ATT&CK mapping
* 🛡️ Automatically isolate compromised VMs (with approval)

All **faster than any junior analyst I've ever seen**.

---

## ❓ Does this mean SOC Analysts are obsolete?

❌ **No.**
But it does mean the days of "click-next analysts" are numbered.

👉 The future SOC team will be **human + AI**:

* 🤖 **AI handles**: noise, repetition, speed
* 🧠 **Humans handle**: intuition, creativity, strategy

---

## 💥 The Controversial Part

* Companies won't need as many entry-level analysts — **AI will fill that gap**.
* The analysts who thrive will be those who **leverage AI as a partner, not compete with it**.

---

## 🎥 Demo

Check out the demo video of the Agentic AI in action — doing the work *with me*, not *for me*.

---

## 🏗️ Architecture

```mermaid
flowchart TD
    A[User Request] --> B[OpenAI GPT Model]
    B --> C[Tool Selection]
    C --> D[Build KQL Query]
    D --> E[Azure Log Analytics]
    E --> F[Return Logs]
    F --> G[Threat Hunt Analysis]
    G --> H{Threats Found?}
    H -->|Yes| I[Display Findings]
    H -->|No| J[Exit]
    I --> K{High Confidence?}
    K -->|Yes| L[Offer VM Isolation]
    K -->|No| M[Log Results]
    L --> N[Microsoft Defender API]
```

---

## 🚀 Features

- **Intelligent Query Building**: Automatically constructs KQL queries based on natural language requests
- **Multi-Table Support**: Queries multiple MDE tables including DeviceProcessEvents, DeviceNetworkEvents, DeviceLogonEvents, and more
- **MITRE ATT&CK Mapping**: Every finding is mapped to MITRE tactics, techniques, and sub-techniques
- **Confidence Scoring**: Findings are rated Low/Medium/High confidence to help prioritize response
- **IOC Extraction**: Automatically extracts Indicators of Compromise (IPs, domains, hashes, filenames)
- **Guardrails**: Built-in validation for tables, fields, and models to prevent unauthorized operations
- **Cost Awareness**: Tracks token usage and estimates costs before running expensive queries
- **Automated Response**: Can isolate compromised VMs via Microsoft Defender for Endpoint API

---

## 📋 Prerequisites

- Python 3.10+
- Azure subscription with Log Analytics Workspace
- Microsoft Defender for Endpoint (optional, for VM isolation)
- OpenAI API key

---

## ⚙️ Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/AnandSundar/Cyber-AI-Agent.git
   cd Cyber-AI-Agent
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure environment variables**
   
   Create a `.env` file in the project root:
   ```env
   OPENAI_API_KEY=your_openai_api_key
   LOG_ANALYTICS_WORKSPACE_ID=your_workspace_id
   ```

4. **Authenticate with Azure**
   ```bash
   az login
   ```

---

## 🎮 Usage

Run the main script:
```bash
python _main.py
```

You'll be prompted to describe what you want to hunt for. Example:
```
I'm worried that windows-target-1 might have been maliciously logged into in the last few days
```

The AI will:
1. Analyze your request and select appropriate log tables
2. Build and execute a KQL query against Azure Log Analytics
3. Analyze the returned logs for threats
4. Present findings with MITRE ATT&CK mapping and recommendations
5. Offer to isolate VMs if high-confidence threats are detected

---

## 📁 Project Structure

```
Cyber-AI-Agent/
├── _main.py              # Main entry point - orchestrates the threat hunt
├── executor.py           # Core execution logic for queries and API calls
├── guardrails.py         # Validation for tables, fields, and models
├── model_management.py   # OpenAI model selection and token management
├── prompt_management.py  # System prompts and threat hunt templates
├── utilities.py          # Helper functions for display and sanitization
├── requirements.txt      # Python dependencies
└── .env                  # Environment configuration (not in repo)
```

---

## 🗂️ Supported Log Tables

| Table | Description |
|-------|-------------|
| `DeviceProcessEvents` | Process execution events |
| `DeviceNetworkEvents` | Network connection events |
| `DeviceLogonEvents` | Logon/logoff events |
| `DeviceFileEvents` | File creation/modification events |
| `DeviceRegistryEvents` | Registry modification events |
| `AzureNetworkAnalytics_CL` | Azure network flow logs |
| `AzureActivity` | Azure activity logs |
| `SigninLogs` | Azure AD sign-in logs |

---

## 🤖 Supported Models

| Model | Max Input | Cost (Input/Output per 1M tokens) |
|-------|-----------|-----------------------------------|
| gpt-4.1-nano | 1,047,576 | $0.10 / $0.40 |
| gpt-4.1 | 1,047,576 | $1.00 / $8.00 |
| gpt-5-mini | 272,000 | $0.25 / $2.00 |
| gpt-5 | 272,000 | $1.25 / $10.00 |

---

## 🛡️ MITRE ATT&CK Coverage

This tool can detect and map findings to all 14 MITRE ATT&CK tactics:

| Tactic | Description |
|--------|-------------|
| 🔎 Reconnaissance | Gathering information before attack |
| 🛠️ Resource Development | Setting up attack infrastructure |
| 🚪 Initial Access | First foothold in environment |
| ⚡ Execution | Running malicious code |
| 🔄 Persistence | Maintaining long-term access |
| 📈 Privilege Escalation | Gaining higher permissions |
| 🕵️ Defense Evasion | Avoiding detection |
| 🔑 Credential Access | Stealing credentials |
| 🗺️ Discovery | Mapping the environment |
| 🔄 Lateral Movement | Moving between systems |
| 📥 Collection | Gathering valuable data |
| 🌐 Command and Control | Controlling compromised systems |
| 📤 Exfiltration | Stealing data out |
| 💣 Impact | Final damage stage |

---

## 📊 Example Output

```
Cognitive hunt complete. Took 12.34 seconds and found 3 potential threat(s)!

┌─────────────────────────────────────────────────────────────┐
│ THREAT 1: Suspicious PowerShell Execution                   │
├─────────────────────────────────────────────────────────────┤
│ Confidence: HIGH                                             │
│ MITRE: T1059.001 - Command and Scripting Interpreter        │
│ Description: Encoded PowerShell command detected...         │
│ IOCs: 192.168.1.100, malicious.exe                          │
│ Recommendations: [pivot, create incident]                   │
└─────────────────────────────────────────────────────────────┘
```

---

## 🔒 Security Considerations

- **Guardrails**: All queries are validated against allowed tables and fields
- **Model Validation**: Only approved OpenAI models can be used
- **User Approval**: VM isolation requires explicit user confirmation
- **No Data Exfiltration**: Logs are analyzed locally via API, not stored

---

## 💭 What do you think?

* Is AI going to be the **end of SOC analyst jobs**?
* Or is it the **biggest upgrade our industry has ever seen**?

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

---

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

---

## 🙏 Acknowledgments

- OpenAI for GPT models
- Microsoft for Azure Log Analytics and Defender for Endpoint
- MITRE Corporation for the ATT&CK framework

---

### 🔗 Tags

`#SOC` `#ThreatHunting` `#AI` `#Cybersecurity` `#OpenAI` `#Azure` `#MicrosoftDefender` `#MITRE` `#Automation`

---

Youtube Video: [https://www.youtube.com/watch?v=vFuM--0H3qE](https://www.youtube.com/watch?v=oWa5Wxb8w-o)
