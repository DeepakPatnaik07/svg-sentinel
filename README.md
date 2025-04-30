# 🛡️ SVG Sentinel

**Static SVG Malware Scanner for Security Analysts and Engineers**

SVG Sentinel is a command-line tool that analyzes `.svg` files to detect embedded threats like JavaScript payloads, phishing redirects, base64 malware blobs, CSS-based exploits, and XML entity bombs. Built for fast offline triage by cybersecurity professionals.

---

## 🚨 Why SVGs?

SVG files look harmless — they're just images, right?  
**Wrong.**

Attackers embed malicious scripts in SVGs to:
- Evade traditional email gateways and AV
- Execute JavaScript without user interaction
- Redirect victims to phishing sites or drop malware

**SVG Sentinel scans and classifies these threats before they execute.**

---

## ✅ Features

- Detects malicious patterns such as:
  - `<script>` tags and embedded JS payloads
  - `onload`, `onclick`, and event-based triggers
  - Base64-encoded malware
  - `<foreignObject>` HTML injection
  - CSS `@import` rules with external tracking URLs
  - JavaScript obfuscation (`String.fromCharCode`, `\uXXXX`, `eval()`)
  - XML entity expansions (XXE, Billion Laughs)

- Threat Scoring System:
  - Classifies files as: `HIGH RISK`, `SUSPICIOUS`, or `PROBABLY SAFE`

- Clear CLI Output:
  - Easily parse results and integrate into your workflow
  - Offline-first and lightweight

---

## 🚀 Usage

Install dependencies:

```bash
pip install -r requirements.txt

Run a scan:

python sentinel.py --file test_files/test_master.svg

Example output:

[OK] Parsed: test_master.svg
[ALERT] EVENTS → 2 detection(s)
[ALERT] BASE64 → 1 detection(s)
[ALERT] FOREIGN → 1 detection(s)

=== SUMMARY REPORT ===
[+] Threat Score: 105
[+] Classification: HIGH RISK



⸻

🧠 Tech Stack
	•	Python 3.9+
	•	lxml for XML parsing
	•	argparse for CLI support
	•	Regex and static string scanning

⸻

📁 Project Structure

SVG_Sentinel/
├── scanner.py          # Detection logic
├── sentinel.py         # CLI interface
├── test_files/
├── requirements.txt
├── README.md



⸻

💡 Future Additions
	•	YARA rule integration for custom signatures
	•	Streamlit-based drag-and-drop GUI
	•	GitHub Action to auto-scan SVGs in repos
	•	Live threat classification dashboard (JSON export)

⸻

👨‍💻 Author

Deepak Patnaik
MSc Cyber Security @ Lancaster University
🔐 Passionate about Cyber Resilience, Threat Intelligence, and SOC Automation

⸻

📜 License

MIT License – use, modify, and break things freely.
