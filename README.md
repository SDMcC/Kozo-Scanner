# 🔍 Kozo Scanner

> **Ephemeral, privacy-first code scanner for technical debt scoring and security alerts**

Kozo Scanner is the open-source engine powering **[Kozo](https://kozo.one)** — guardrails for vibe coders using Cursor, Emergent.sh, Bolt.new, Lovable, Windsurf, and similar AI coding agents.

It processes uploaded project zips (or GitHub repo contents) entirely **in memory**, never persisting or transmitting your code to third parties. The logic is fully visible so you can verify exactly what is — and isn't — being checked.

We open-sourced our scanner so you can verify that we never see your raw code. We analyze your project's health locally in your browser and only receive the metadata needed to build your Constitution.
---

## ✨ Features

### 📐 File Size & Structure Analysis
- Lines of code per file (flags files >300–500 lines)
- Maximum nesting depth (flags depth >6)
- Cyclomatic complexity per function/method (flags >10–15)
- Function/method length analysis
- Basic duplication detection (repeated blocks)

### 🔐 Security & Secret Scanning (Wide-Net)
Regex-based detection for 22+ common patterns, including:
- API keys, tokens, and secrets
- Hardcoded emails & PII
- Crypto wallet addresses (ETH, BTC)
- AWS keys, JWT tokens, private keys
- Localhost/dev URLs in production code
- Missing `.env.example` signal

### 🌐 Language-Agnostic Basics
- Focused file type filtering (`.js` / `.ts` / `.jsx` / `.tsx` / `.py`, etc.)
- Automatically ignores `node_modules`, `__pycache__`, `.git`, and build artifacts

---

## 📦 Output Format

Generates a JSON report containing:

| Field | Description |
|---|---|
| `debtScore` | Overall debt score (0–100) |
| `files` | Per-file violations with severity |
| `securityFindings` | Security hits with file, line, pattern & redacted preview |
| `summary` | Aggregates — language breakdown, top offenders |

### Example `report.json`

```json
{
  "debtScore": 68,
  "summary": "High debt: 7 files exceed 500 lines. 3 potential secrets found.",
  "files": [
    {
      "path": "frontend/src/pages/AdminDashboard.js",
      "language": "TypeScript",
      "lines": 1213,
      "maxNesting": 9,
      "cyclomaticMax": 18,
      "violations": [
        { "type": "size", "severity": "critical", "message": "143% over 500-line limit" },
        { "type": "nesting", "severity": "high", "message": "Max nesting 9 > recommended 6" }
      ]
    }
  ],
  "securityFindings": [
    {
      "file": "config.js",
      "line": 42,
      "pattern": "aws-secret",
      "preview": "aws_access_key_id = 'AKIA...'"
    }
  ]
}
```

---

## 🚀 Installation

### Prerequisites
- Node.js (recommended for most web projects), **or**
- Python 3.x

### Clone & Install

```bash
# Clone the repo
git clone https://github.com/SDMcC/vitals-scanner.git
cd vitals-scanner

# Node.js / TypeScript
npm install

# Python
pip install -r requirements.txt
```

---

## ⚡ Quick Start

### Node.js

```bash
# Scan a local zip file
node src/scanner.js --zip path/to/my-project.zip --output report.json
```

---

## 🔒 Security & Privacy Guarantees

| Guarantee | Detail |
|---|---|
| **No code retention** | Processed in memory, discarded immediately after scan |
| **No external API calls** | All logic runs locally / offline |
| **No telemetry** | Zero tracking or logging of file contents |
| **Auditable patterns** | Regex list is plain-text and fully inspectable |
| **Ephemeral by design** | Matches Kozo's privacy-first model |

---

## ❓ Why Open Source?

We believe **trust is essential** when scanning code.

By making the core scanner logic public, you can verify exactly what we check — and what we **don't** (no exfiltration, no persistent storage, no third-party calls with your code).

---

## 🤝 Contributing

We welcome PRs, bug reports, and new pattern suggestions!

1. **Fork & branch:** `git checkout -b feature/new-pattern`
2. Add tests if changing logic
3. Update this README if adding features
4. Open a PR with a clear description

---

## 📄 License

**MIT License** — see [LICENSE](./LICENSE) for full text.

You are free to use, modify, and distribute — even commercially — as long as you retain the copyright notice.

---

## 💬 Questions / Issues

[Open an issue](https://github.com/SDMcC/vitals-scanner/issues) on GitHub.

---

*Built for vibe coders who want speed without the mess. 🚀*
