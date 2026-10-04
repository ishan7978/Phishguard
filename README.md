# PHISHGUARD 🛡️

PHISHGUARD is a web-based phishing detection dashboard for analyzing **URLs, SMS messages, and email text**.

It analyzes suspicious patterns, URLs, phishing language, brand impersonation signals, and other indicators to generate a **risk score, confidence score, verdict, and detection evidence**.

> ⚠️ **Disclaimer:** PHISHGUARD is a defensive security analysis tool. A `LIKELY_LEGITIMATE` result does not guarantee that an input is completely safe.

---

## ✨ Features

* 🔗 URL phishing analysis
* 📱 SMS phishing analysis
* 📧 Email phishing analysis
* 🎯 Risk score from 0–100
* 📊 Confidence score
* 🚨 Phishing verdict
* 🔍 Detection evidence
* 🎭 Brand impersonation detection
* 🌐 URL/domain analysis
* 🧠 Regex and heuristic-based detection
* 🗂️ Local scan history
* 💻 Web dashboard
* ⚡ Fast local analysis

---

## 🧰 Requirements

Install the following before running PHISHGUARD:

* Python 3
* Node.js
* npm
* Git

Check your versions:

```bash
python3 --version
node --version
npm --version
git --version
```

---

# 🚀 Installation

## 1. Clone the repository

```bash
git clone https://github.com/ishan7978/Phishguard.git
cd Phishguard
```

---

# 🔧 Backend Setup

Go to the backend:

```bash
cd backend
```

Create a Python virtual environment:

```bash
python3 -m venv .venv
```

Activate the environment:

```bash
source .venv/bin/activate
```

Install the required Python packages:

```bash
pip install -r requirements.txt
```

---

# ▶️ Start the Backend

From the `backend` directory:

```bash
uvicorn app.main:app --reload --port 8000
```

The backend runs at:

```text
http://127.0.0.1:8000
```

Keep this terminal running.

---

# 🎨 Start the Frontend

Open a **second terminal**.

Go to the frontend directory:

```bash
cd ~/Downloads/phishguard/frontend
```

If you cloned the repository somewhere else, replace the path with your own PHISHGUARD folder.

Install the frontend dependencies:

```bash
npm install
```

Start the frontend:

```bash
npm run dev
```

Vite will show a local address, normally:

```text
http://localhost:5173
```

Open that address in your browser.

---

# 🛡️ How to Use PHISHGUARD

After opening the dashboard:

1. Select the type of input you want to analyze.
2. Enter the URL, SMS message, or email text.
3. Click the corresponding scan button.
4. Wait for the analysis to complete.
5. Review:

   * Verdict
   * Risk score
   * Confidence
   * Detection evidence
   * Recommended action
6. Previous scans can be viewed in the scan history section.

---

# 🚨 Verdicts

PHISHGUARD may return different verdicts depending on the detected risk:

| Verdict                 | Meaning                                                     |
| ----------------------- | ----------------------------------------------------------- |
| `LIKELY_LEGITIMATE`     | No significant phishing indicators were detected            |
| `INSUFFICIENT_EVIDENCE` | There is not enough evidence for a stronger classification  |
| `SUSPICIOUS`            | Suspicious indicators were detected                         |
| `HIGH_RISK`             | Multiple or strong phishing indicators were detected        |
| `LIKELY_PHISHING`       | The combined signals indicate a high likelihood of phishing |

A legitimate result should **not** be interpreted as proof that something is completely safe.

---

# 📂 Scan History

PHISHGUARD stores scan history locally on the machine running the backend.

The history file is:

```text
backend/data/scan_history.json
```

This file is intentionally excluded from GitHub through `.gitignore`.

Therefore:

* Your personal scan history is **not uploaded to GitHub**.
* Someone cloning PHISHGUARD gets a fresh local history.
* Each installation maintains its own scan history.
* The history is stored locally by the backend.

---

# 🗑️ How to Clear Scan History

Stop the backend first with:

```text
CTRL + C
```

Then from the PHISHGUARD project directory run:

```bash
rm -f backend/data/scan_history.json
```

Start the backend again:

```bash
cd backend
source .venv/bin/activate
uvicorn app.main:app --reload --port 8000
```

Refresh the PHISHGUARD dashboard.

The scan history will be empty.

### Alternative

You can clear the history without deleting the file:

```bash
echo "[]" > backend/data/scan_history.json
```

---

# 📁 Project Structure

```text
Phishguard/
│
├── backend/
│   ├── app/
│   │   ├── analyzers/
│   │   │   ├── domain_age.py
│   │   │   ├── patterns.py
│   │   │   ├── phishing_reputation.py
│   │   │   ├── regex_engine.py
│   │   │   ├── url_analyzer.py
│   │   │   └── vt_reputation.py
│   │   │
│   │   ├── scoring/
│   │   │   └── risk.py
│   │   │
│   │   └── main.py
│   │
│   └── requirements.txt
│
├── frontend/
│   ├── src/
│   │   ├── main.tsx
│   │   └── styles.css
│   ├── index.html
│   ├── package.json
│   ├── package-lock.json
│   ├── tsconfig.json
│   └── vite.config.ts
│
├── .gitignore
└── README.md
```

---

# 🔍 Detection

PHISHGUARD uses multiple analysis signals, including:

* Regex-based detection
* Suspicious language patterns
* URL structure analysis
* Domain analysis
* IP-based URL detection
* IDN indicators
* Brand impersonation signals
* Fuzzy/typosquatting signals
* Reputation signals when configured
* Risk scoring

The system combines multiple indicators rather than relying on a single check.

---

# 🔐 API Keys and Secrets

If you configure external reputation services, **never put API keys directly into source code**.

Use environment variables or a local `.env` file.

`.env` files are excluded from Git through `.gitignore`.

**Never upload API keys, passwords, tokens, or other secrets to GitHub.**

---

# 🧪 Development

Start the backend:

```bash
cd backend
source .venv/bin/activate
uvicorn app.main:app --reload --port 8000
```

Start the frontend in another terminal:

```bash
cd frontend
npm install
npm run dev
```

Build the frontend:

```bash
npm run build
```

---

# ⚠️ Important Limitations

No phishing detection system can guarantee 100% accuracy.

For example, a malicious website may still have:

* Valid HTTPS/TLS
* Working DNS
* A valid-looking domain
* No existing reputation report
* No obvious phishing keywords

Therefore, PHISHGUARD should be used as a **security analysis and decision-support tool**, not as an absolute source of truth.

Always independently verify suspicious requests through a trusted channel.

---

# 🔒 Responsible Use

PHISHGUARD is intended for:

* Cybersecurity education
* Defensive security research
* Authorized testing
* Phishing detection
* Security demonstrations
* Hackathon and research projects

Do not use PHISHGUARD to conduct unauthorized attacks, steal credentials, or harm other users or systems.

---

# 👨‍💻 Author

**Ishan**

GitHub:

https://github.com/ishan7978

---

# 📜 License

This project is provided for educational, research, and authorized defensive-security purposes.

---

## PHISHGUARD

**Analyze. Detect. Protect.**
