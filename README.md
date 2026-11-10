# ⚡ CYBER-GUARD v2.5 PRO // Quantum Threat Intelligence & AI Prompt Engine

An ultra-modern, cyberpunk SOC-grade threat evaluation platform featuring holographic cyber defense artwork, dual-engine intelligence, real-time diagnostic pipelines, and an automated AI prompt generator.

---

## 🎨 Visual Aesthetics & Architecture ("Unique & Image-Rich")

- **Holographic Cyber Shield Visual**: High-resolution 3D holographic digital shield and cryptographic lock telemetry artwork (`assets/cyber-hero.png`).
- **Live Threat Stream Ticker**: Real-time simulated global attack stream across the header showing intercepted typosquats, malicious npm packages, and crypto drainers.
- **Cyber Sound FX Synthesizer**: Native Web Audio API sound generator producing sci-fi diagnostic sweeps, blips, and alerts with an on/off audio toggle.
- **Quantum HUD Telemetry**: Real-time UTC clock, defense status indicators, dynamic SVG gauge animations, and scanline CRT overlays.
- **Lucide Icons & Glassmorphism**: Tailored with custom glowing cyan (`#00f2fe`), emerald (`#10b981`), amber (`#f59e0b`), and crimson (`#f43f5e`) accents.

---

## 🛡️ Core Capabilities & Modules

### 1. Omni-Scanner & AI Prompt Generator
- **Auto-Type Detection**: Identifies whether the input is a **Full URL**, **Domain**, **GitHub Repo**, or **Package**.
- **Interactive Scenarios**:
  - 🚨 *Typosquat Phish (`paypaI-security-update-verify-login.xyz`)*
  - 🚨 *Malicious Repo (`free-aimbot-2026/fortnite-cheat-engine` with compiled `.exe` dropper)*
  - ⚠️ *Fake Airdrop Drainer (`crypto-airdrop-rewards-2026.net`)*
  - ✅ *React Repository (`facebook/react` - Verified OSS)*
  - 🌐 *Cloudflare (`cloudflare.com` - Verified)*
- **Simulated Diagnostic Pipeline**: Multi-stage progress radar with real-time terminal logs.
- **Automated AI Prompt Generator**: Tailors expert prompts for ChatGPT, Gemini, or Claude across 4 personas:
  - 🛡️ *Senior Anti-Phishing Specialist (Prompt 1)*
  - 💻 *DevSecOps Analyst & Source Code Auditor (Prompt 2)*
  - 🛒 *E-Commerce Fraud & Fake Store Check*
  - 🔍 *Incident Response & Forensic Deep Dive*
- **One-Click Clipboard Copying**: Instant copy with visual and audio feedback.

### 2. Senior Anti-Phishing Specialist Intelligence Report
- **Task 1: Threat Level Rating** (0–100 score with LOW, MEDIUM, HIGH, CRITICAL RISK classification).
- **Task 2: Typosquatting Check** (Compares against 120+ top global brands, detecting font tricks like `paypaI` capital `I` vs lowercase `l`).
- **Task 3: Key Red Flags** (TLD risk rating, subdomain stacking, IP literals, registration age anomalies).
- **Task 4: Scam Purpose Classification** (Credential harvesting, infostealer dropper, crypto drainer).
- **Task 5: Safe Action Plan** (Step-by-step instructions on whether it is safe to open/login, remediation, and abuse contacts).

### 3. DevSecOps Analyst & GitHub Code Auditor Report
- **Task 1: Trust Score (1 to 10)** (Weighted scoring assessing maintainer longevity, repo age, and engagement).
- **Task 2: Suspicious Indicators** (Burner maintainer accounts, star farming botnets).
- **Task 3: Code Inspection Checklist** (Language-tailored targets for Python `setup.py`/`__init__.py`, Node.js `package.json` hooks, Go, Rust `build.rs`, binaries, and CI/CD workflows).
- **Task 4: Red Flags Diagnostic** (Password-protected README archives, base64 strings, Discord/Telegram webhooks).
- **Safe Execution & Quarantine Protocol**: Copyable terminal commands (`--ignore-scripts`, `--no-build-isolation`, Docker sandbox).

### 4. Interactive Security Labs
- **Unicode Homoglyph & Punycode Matrix**: Character-by-character inspection mapping Cyrillic/Greek lookalikes and Punycode (`xn--...`).
- **Malicious Script Sandbox**: Paste code to detect dangerous hooks, Discord webhooks, Telegram bots, and PowerShell IEX cradles.
- **Slide-In Scan History Drawer**: LocalStorage-backed scan log with quick re-scan triggers.

---

## 💻 How to Run

### Option 1: Python Local Server (Recommended)
```powershell
python server.py
```
*Opens `http://localhost:8080` automatically in your browser.*

### Option 2: Direct File Open
Double-click `index.html` in Windows Explorer or open it in any modern web browser. The entire application is self-contained and operates 100% client-side.

---

## 📁 Project Directory

```
cyper security checker/
├── index.html                 # Main Cyber-Guard Web Application
├── server.py                  # Local HTTP server with CORS headers & auto-launch
├── README.md                  # Documentation & Architecture
├── assets/
│   ├── cyber-hero.png         # High-resolution 3D holographic cyber shield artwork
│   └── cyber-hero.jpg         # Fallback JPEG artwork
└── js/
    ├── homoglyph-engine.js    # Unicode lookalike & brand typosquatting engine
    ├── url-analyzer.js        # Senior Cybersecurity & Anti-Phishing Specialist Engine
    ├── repo-auditor.js        # DevSecOps Analyst & Source Code Auditor Engine
    ├── payload-inspector.js   # Static regex signature scanner for scripts
    └── app.js                 # App controller, audio synthesizer, HUD, and export
```
