# 🔐 Automated Penetration Testing Toolkit — Project Continuity Prompt
> Paste this entire document at the start of any new chat with Claude to continue exactly where you left off.

---

## 📌 Project Identity
- **Project Name:** Automated Penetration Testing Toolkit
- **University:** University of Petroleum and Energy Studies (UPES), Dehradun
- **School:** School of Computer Science
- **Mentor:** Debanjan Ghosh
- **Team:**
  | Name | Role / Specialization | Batch |
  |---|---|---|
  | Deepanshu Kushwaha | Cybersecurity & Lead Developer | Batch 13 CSF |
  | Yash Yadav | Security Testing & Core Modules | Batch 13 CSF |
  | Lakshay Gupta | UI & Integration | Batch 14 CSF |
  | Utkarsh | Research & Documentation | Batch 13 CSF |

---

## ✅ Decisions Made So Far

### Platform & Tools
- **Language:** Python 3.10+
- **GUI Framework:** PyQt5 (cybersecurity-themed dark UI)
- **Editor:** VS Code with Claude Code extension
- **Target OS:** Cross-platform — Windows + Kali Linux both
- **AI Integration:** Anthropic API (Claude) for intelligent result analysis

### Features to Build (Confirmed)
| # | Feature | Description |
|---|---|---|
| 1 | 🤖 AI-Powered Analysis | Anthropic API analyses every scan result, explains vulnerabilities in plain English, suggests fixes |
| 2 | ⚡ Single-Command Workflow | One command/button triggers full recon + scan + web assessment pipeline |
| 3 | 🎓 Beginner-Friendly Guided Mode | Step-by-step interactive mode, explains what each scan does, color-coded severity |
| 4 | 🧠 Smart Scan Prioritization (DSA) | Full Priority Queue (Heap) + HashMap + Queue implementation for intelligent task scheduling and risk scoring |
| 6 | 📄 Auto HTML Report Generation | Generates professional pentest report as HTML after every scan |

### Features NOT in scope (for now)
- CTF Mode (Feature 5) — deferred to future version

---

## 🏗️ Agreed Project Structure

```
pentesting-toolkit/
│
├── main.py                  # Entry point, launches PyQt GUI
├── config.py                # Tool paths, API keys, OS detection
├── requirements.txt         # Python dependencies
│
├── gui/
│   ├── main_window.py       # Main PyQt5 window
│   ├── guided_mode.py       # Beginner step-by-step guided mode UI
│   ├── results_panel.py     # Scan results display widget
│   └── styles.qss           # Dark cybersecurity theme stylesheet
│
├── modules/
│   ├── recon.py             # Subdomain enum, WHOIS, DNS
│   ├── scanner.py           # Port scanning via python-nmap
│   ├── web_assess.py        # Directory brute-force, header checks
│   └── scheduler.py         # Queue + Heap DSA-based task scheduler
│
├── ai/
│   └── analyzer.py          # Anthropic API integration, result analysis
│
├── reports/
│   ├── report_gen.py        # HTML report generator (Jinja2)
│   └── templates/
│       └── report.html      # Jinja2 HTML report template
│
└── wordlists/
    └── common.txt           # Directory brute-force wordlist
```

---

## 🛠️ Tech Stack

| Component | Technology |
|---|---|
| Language | Python 3.10+ |
| GUI | PyQt5 |
| Port Scanning | python-nmap |
| HTTP/Web | requests, httpx |
| Subdomain Enum | sublist3r (Python) |
| AI Analysis | Anthropic API (claude-sonnet-4-20250514) |
| Report Generation | Jinja2 HTML templates |
| CLI fallback | argparse + rich |
| Styling | PyQt QSS dark theme |

---

## 🖥️ Cross-Platform Strategy

```python
import platform
OS = platform.system()  # 'Linux' or 'Windows'
```

| Tool | Kali Linux | Windows |
|---|---|---|
| nmap | Pre-installed | Install from nmap.org |
| subfinder | apt install | GitHub binary |
| nikto | Pre-installed | Perl + manual |
| dirsearch | Python-based | Works natively |
| Python 3 | Pre-installed | python.org |

The `config.py` will auto-detect OS and set correct binary paths.

---

## 🧠 Feature 4: Smart Scan Prioritization — Full DSA Design

This is the academic backbone of the project. Three data structures work together:

### Data Structures Used

| DSA | Role in Toolkit |
|---|---|
| **Min-Heap (Priority Queue)** | Prioritizes scan tasks by risk level — critical ports/checks run first |
| **HashMap (Python dict)** | Stores and retrieves scan results by target key instantly |
| **Queue (FIFO)** | Maintains ordered execution of recon → scan → web assess pipeline |

### How It Works

```
User enters target
        ↓
Queue: [recon_task, port_scan_task, web_assess_task]   ← FIFO order
        ↓
For port scanning:
Heap pushes tasks by priority:
  (1, scan_port_22_ssh)      ← highest risk, runs first
  (1, scan_port_21_ftp)
  (2, scan_port_80_http)
  (3, scan_port_8080_alt)    ← lowest risk, runs last
        ↓
HashMap stores results:
  { "192.168.1.1:22": { service: "ssh", status: "open", risk: "high" },
    "192.168.1.1:80": { service: "http", status: "open", risk: "medium" } }
        ↓
AI Analyzer reads HashMap → generates risk score (0-100) → HTML report
```

### Risk Score System

Every target gets an overall **Risk Score (0–100)** calculated from findings:

| Finding | Points Added |
|---|---|
| Open port 21 (FTP) | +15 |
| Open port 23 (Telnet) | +20 |
| Open port 3389 (RDP) | +15 |
| Missing security headers | +10 each |
| Exposed admin directory | +25 |
| Outdated service version | +10 |

**Score Bands:**
- 🔴 75–100 → Critical
- 🟠 50–74 → High
- 🟡 25–49 → Medium
- 🟢 0–24 → Low

This score is shown prominently in the GUI and at the top of the HTML report.

### Port Priority Table (Built-in)

```python
# scheduler.py — priority values (lower = higher priority)
PORT_PRIORITIES = {
    21:   1,   # FTP — plaintext, critical
    22:   2,   # SSH — important but secure
    23:   1,   # Telnet — plaintext, critical
    25:   2,   # SMTP
    80:   2,   # HTTP
    443:  3,   # HTTPS — lower risk
    445:  1,   # SMB — critical (ransomware target)
    3306: 1,   # MySQL exposed — critical
    3389: 1,   # RDP — critical
    8080: 3,   # Alt HTTP
}
```

---

## 🤖 AI Analysis Layer Plan

Every scan result gets passed to the Anthropic API like this:

```python
# ai/analyzer.py concept
from anthropic import Anthropic

client = Anthropic()

def analyze_results(scan_data: dict) -> str:
    prompt = f"""
    You are a cybersecurity expert. Analyze these penetration testing results 
    and provide: 
    1. Plain English explanation of each finding
    2. Risk severity (Critical/High/Medium/Low)
    3. Specific remediation steps
    
    Scan Results:
    {scan_data}
    """
    response = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=1000,
        messages=[{"role": "user", "content": prompt}]
    )
    return response.content[0].text
```

---

## 🎨 GUI Design Plan (PyQt5)

- **Theme:** Dark cybersecurity aesthetic (similar to Kali Linux terminal style)
- **Color Palette:**
  - Background: `#0d1117` (near black)
  - Accent: `#00ff41` (matrix green)
  - Warning: `#ff6b35` (orange-red)
  - Panel: `#161b22` (dark gray)
  - Text: `#c9d1d9` (light gray)

### Main Window Sections:
1. **Target Input Panel** — Enter domain/IP, select scan type
2. **Guided Mode Toggle** — Switch between Expert and Beginner mode
3. **Live Scan Output** — Real-time scrolling terminal-like output
4. **AI Analysis Panel** — Shows Claude's analysis of results
5. **Report Button** — One-click HTML report generation

---

## 📦 requirements.txt (Planned)

```
PyQt5>=5.15.0
python-nmap>=0.7.1
requests>=2.31.0
httpx>=0.24.0
sublist3r>=1.0
anthropic>=0.25.0
jinja2>=3.1.0
rich>=13.0.0
dnspython>=2.3.0
```

---

## 🚦 Development Order (Recommended)

1. `config.py` — OS detection, paths, API key setup
2. `modules/scheduler.py` — Full DSA layer: Queue + Heap + HashMap + Risk Scoring
3. `modules/scanner.py` — nmap integration, feeds results into HashMap
4. `modules/recon.py` — subdomain + WHOIS
5. `modules/web_assess.py` — directory + headers, updates risk score
6. `ai/analyzer.py` — Anthropic API integration, reads HashMap for analysis
7. `reports/report_gen.py` + template — HTML report with risk score badge
8. `gui/` — PyQt5 GUI (main window, guided mode, results panel, risk score display)
9. `main.py` — Wire everything together

---

## 📝 What to Tell Claude in Next Chat

Paste this file and say:

> "Continue building the Automated Pentesting Toolkit from where we left off. 
> Start with [module name] as per the project plan in this document."

---

## 🔑 Important Notes for Next Session

- Always confirm with Claude which module to build first
- Ask Claude to write **cross-platform compatible code** for Windows + Kali
- The GUI should always use **PyQt5**, not tkinter or any other framework
- AI analysis uses **Anthropic API** with model `claude-sonnet-4-20250514`
- Keep **ethical use** disclaimer in the GUI and reports at all times
- All scanning must warn user to **only scan authorized targets**

---

*Last updated: Session 1 — Project planning and architecture complete. All 5 features confirmed (1, 2, 3, 4, 6). Feature 4 fully designed with Heap + HashMap + Queue + Risk Scoring system. No code written yet. Ready to begin coding from Session 2.*
