# 🛡️ VirusTotal IP & Domain Reputation Checker (Command Line Tool)

This is a simple and fast command-line Python tool that checks the **reputation of multiple IP addresses or domains** using the [VirusTotal API v3](https://developers.virustotal.com/reference/overview).

---

## 🔧 Features

- 🔎 Check reputation of **multiple IPs or domains** in one command
- ⚡️ Uses VirusTotal's public API
- ✅ Outputs verdicts (harmless, malicious, suspicious) from VirusTotal
- 🐍 Lightweight and easy to use

---

## 🚀 Getting Started

### 1. Clone the Repository
```bash
git clone https://github.com/ahoquea/vt-ip-domain-check-cmd.git
cd vt-ip-domain-check-cmd
```

### 2. Install Dependencies
Make sure you have Python 3.6+ and install the required library:
```bash
pip install requests
```

### 3. Add Your VirusTotal API Key
Open vt__check_cmd.py and replace the placeholder with your VirusTotal API key:
```python
# Replace this with your ONLY VirusTotal API key
API_KEY = "VIRUSTOTAL_API_KEY"
```

---

## ✅ Usage
```bash
python vt_check_cmd.py <ip_or_domain1> <ip_or_domain2>
```

## 📄Example:
```bash
python vt_check_cmd.py 8.8.8.8 example.com
```

## ▶️ Sample Output:
```yaml
8.8.8.8 -> Harmless: 85, Suspicious: 0, Malicious: 0
example.com -> Harmless: 75, Suspicious: 1, Malicious: 2
```

## 📄 License
This project is licensed under the MIT License.
