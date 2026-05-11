# SprayMaster v2.0

A highly concurrent, multi-protocol network login auditor and password spraying tool. Designed for authorized penetration testing and security auditing.

![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)

## ⚠️ Legal Disclaimer
**SprayMaster is created for authorized penetration testing and security auditing purposes only.** 
Any usage of this tool on targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state, and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program.

## 🚀 Features
* **Multi-Protocol Support:** 15 network protocols supported out of the box.
* **High Performance:** Concurrent multithreaded attacks.
* **Attack Modes:** Standard brute-force, password spraying (to avoid account lockouts), and combo-list (`user:pass`) attacks.
* **Smart Stop Strategies:** Stop on first global success, per-host, or per-user.
* **Rich Terminal UI:** Beautiful live progress bars and reporting using the `rich` library.
* **Reporting:** Export successful credentials to Plain Text, JSONL, or CSV.

## 🔌 Supported Protocols
`ftp`, `http`, `imap`, `ldap`, `mssql`, `mysql`, `pop3`, `postgres`, `redis`, `smb`, `smtp`, `snmp`, `ssh`, `telnet`, `vnc`

## 🛠️ Installation

```bash
git clone https://github.com/yokesh-kumar-M/SprayMaster.git
cd SprayMaster

# Create a virtual environment (optional but recommended)
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows

# Install dependencies
pip install -r requirements.txt
```

## 📖 Usage

### Basic Syntax
```bash
python -m spraymaster --protocol <PROTO> [TARGETS] [CREDENTIALS] [OPTIONS]
```

### Examples

**1. Password Spraying (Avoid Lockouts)**
Test one password across a list of users before moving to the next password.
```bash
python -m spraymaster -U users.txt -P passwords.txt -T targets.txt --protocol ssh --spray --threads 20
```

**2. Standard Brute Force**
Brute force combinations on a single target.
```bash
python -m spraymaster -U users.txt -P passwords.txt -t 192.168.1.100 --protocol ftp --threads 10
```

**3. Combo List Attack**
Use a file with `username:password` format.
```bash
python -m spraymaster -C combos.txt -t 10.10.10.50 --protocol mysql
```

**4. HTTP Form Auth Attack**
Attack a web login form using placeholder tags `^USER^` and `^PASS^`.
```bash
python -m spraymaster -U users.txt -p Summer2024! -t http://example.com --protocol http \
  --http-path /login \
  --http-method POST \
  --http-form-data "username=^USER^&password=^PASS^&submit=Login" \
  --http-fail-string "Invalid credentials"
```

**5. Output to JSON**
Save successful logins to a JSON Lines file.
```bash
python -m spraymaster -U users.txt -P pass.txt -t 192.168.1.5 --protocol smb -o results.json --output-format json
```

## ⚙️ Core Options

| Flag | Description |
|------|-------------|
| `-t`, `--target` | Single target host or IP |
| `-T`, `--targetlist`| File containing targets (one per line) |
| `-u`, `--user` | Single username |
| `-U`, `--userlist` | File containing usernames |
| `-p`, `--password` | Single password |
| `-P`, `--passlist` | File containing passwords |
| `-C`, `--combo` | File containing `user:pass` combos |
| `--protocol` | Protocol to attack (default: `ftp`) |
| `--spray` | Enable password spray mode |
| `--stop-on-success`| Strategy to stop on success (`none`, `user`, `host`, `global`) |
| `--threads` | Number of concurrent threads (default: `16`) |
| `-o`, `--output` | Write valid credentials to file |
| `--output-format` | Format for output file (`text`, `json`, `csv`) |
