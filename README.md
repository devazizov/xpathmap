# 🕷️ XPathMap

> Automated XPath Injection Testing Tool — SQLMap-compatible syntax

<p align="center">
  <img src="https://img.shields.io/badge/python-3.8%2B-blue?style=flat-square&logo=python" />
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" />
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey?style=flat-square" />
  <img src="https://img.shields.io/badge/techniques-Boolean%20%7C%20Error%20%7C%20Time-red?style=flat-square" />
</p>

---

## 📽️ Demo

<video src="assets/demo.MP4" controls="controls" style="max-width: 100%;">
  Your browser does not support video.
</video>

---

## 📌 About

**XPathMap** is an automated XPath injection testing and exploitation tool built for penetration testers and security researchers. It detects and exploits XPath injection vulnerabilities in web applications that use XML as a data backend.

The CLI syntax is intentionally compatible with **SQLMap** — if you know SQLMap, you already know XPathMap.

### Key Features

| Feature               | Description                                                |
| --------------------- | ---------------------------------------------------------- |
| 🔍 **Detection**      | Error-based, Boolean-blind, Time-based                     |
| 📂 **Enumeration**    | Enumerate root nodes, child nodes, attributes, elements    |
| 💣 **Extraction**     | Full blind data extraction character by character          |
| 💾 **Session cache**  | Resumes from where it left off across runs                 |
| 📊 **CSV export**     | Dumps saved to `~/.xpathmap/output/<host>/` as CSV         |
| 📋 **Table output**   | SQLMap-style ASCII table at end of dump                    |
| 📁 **Raw request**    | Load requests directly from Burp Suite (`-r request.txt`)  |
| 🔀 **Proxy support**  | Route traffic through Burp / OWASP ZAP                     |
| 🧠 **Auto-structure** | Detects flat-list and container XML patterns automatically |

---

## ⚙️ Installation

```bash
git clone https://github.com/devazizov/xpathmap.git
cd xpathmap
pip3 install -r requirements.txt
chmod +x xpathmap.py
```

Optional — add to PATH:

```bash
sudo ln -sf $(pwd)/xpathmap.py /usr/local/bin/xpathmap
```

---

## 🚀 Usage

### Basic syntax

```
xpathmap.py -u <URL> [options]
xpathmap.py -r <request_file> [options]
```

### Examples

```bash
# Detect injection and enumerate root nodes
xpathmap.py -u "http://target.com/search?q=test" --dbs

# Enumerate tables (child nodes) under a root node
xpathmap.py -u "http://target.com/search?q=test" --tables -D users

# Enumerate columns (attributes / child elements)
xpathmap.py -u "http://target.com/search?q=test" --columns -D users -T user

# Dump all records from a node
xpathmap.py -u "http://target.com/search?q=test" --dump -D users -T user

# Dump specific columns only
xpathmap.py -u "http://target.com/search?q=test" --dump -D users -T user -C "username,password"

# Dump everything
xpathmap.py -u "http://target.com/search?q=test" --dump-all

# Load raw HTTP request from Burp Suite
xpathmap.py -r request.txt --dump-all

# POST request with specific parameter
xpathmap.py -u "http://target.com/login" --data "user=test&pass=x" -p user --dbs

# Use only Boolean-based technique, through Burp proxy
xpathmap.py -u "http://target.com/api?id=1" --technique B --proxy http://127.0.0.1:8080 --dbs

# Flush session cache (start fresh)
xpathmap.py -u "http://target.com/search?q=test" --flush-session --dump-all

# Identify XPath engine / version
xpathmap.py -u "http://target.com/search?q=test" --fingerprint

# Verbose output
xpathmap.py -u "http://target.com/search?q=test" --dbs -vvv
```

---

## 🎛️ Options

### Target

| Flag             | Description                               |
| ---------------- | ----------------------------------------- |
| `-u URL`         | Target URL                                |
| `-d DATA`        | POST data (url-encoded or JSON)           |
| `-r FILE`        | Raw HTTP request file (Burp Suite format) |
| `--cookie`       | HTTP Cookie header                        |
| `-H HEADERS`     | Extra headers (separated by `\n`)         |
| `--proxy`        | HTTP proxy (e.g. `http://127.0.0.1:8080`) |
| `--random-agent` | Use random User-Agent                     |

### Injection

| Flag               | Description                                       |
| ------------------ | ------------------------------------------------- |
| `-p PARAM`         | Testable parameter(s), comma-separated            |
| `--technique TECH` | `B`=Boolean, `E`=Error, `T`=Time (default: `BET`) |
| `--prefix`         | Payload prefix string                             |
| `--suffix`         | Payload suffix string                             |
| `--level 1-5`      | Test depth level (default: 1)                     |
| `--risk 1-3`       | Risk level (default: 1)                           |

### Detection

| Flag           | Description                                 |
| -------------- | ------------------------------------------- |
| `--string`     | String that appears when condition is True  |
| `--not-string` | String that appears when condition is False |
| `--code`       | HTTP status code indicating True            |

### Enumeration

| Flag            | Description                                      |
| --------------- | ------------------------------------------------ |
| `--dbs`         | Enumerate root XML nodes (like databases)        |
| `--tables`      | Enumerate child nodes (like tables)              |
| `--columns`     | Enumerate attributes and elements (like columns) |
| `--dump`        | Dump records from a node                         |
| `--dump-all`    | Dump all data                                    |
| `--fingerprint` | Identify XPath engine                            |
| `-D`            | Target root node                                 |
| `-T`            | Target child node                                |
| `-C`            | Columns to extract (comma-separated)             |
| `--start N`     | First record index                               |
| `--stop N`      | Last record index                                |

### Output

| Flag                | Description                     |
| ------------------- | ------------------------------- |
| `-v / -vv / -vvv`   | Verbosity level                 |
| `--output-dir PATH` | Custom output directory         |
| `--flush-session`   | Clear session cache and restart |

---

## 🗂️ Output

Results are saved to `~/.xpathmap/output/<host>/`:

```
~/.xpathmap/output/
└── target.com_8080/
    ├── session.json       ← extraction cache (auto-resume)
    ├── users_user.csv     ← dumped table
    └── store_product.csv  ← dumped table
```

At the end of every dump, XPathMap prints a summary table:

```
════════════════════════════════════════════════════════════
  DUMP SUMMARY
════════════════════════════════════════════════════════════

[+] Table: accounts/acc  (2 records)
  +-------+-----------+----------------------------------------+
  | @id   | username  | password                               |
  +-------+-----------+----------------------------------------+
  | 1     | admin     | bcc3b42debd91b5612aa80b1742f3aef       |
  | 2     | htb-stdnt | 295362c2618a05ba3899904a6a3f5bc0       |
  +-------+-----------+----------------------------------------+

  [*] Saved to: ~/.xpathmap/output/target.com/accounts_acc.csv
════════════════════════════════════════════════════════════
```

---

## 🔄 Session & Caching

XPathMap automatically caches every extracted value. If you interrupt a run or re-run the same command, it continues from where it left off — no repeated HTTP requests for already-known values.

```bash
# First run — extracts everything live
xpathmap.py -r req.txt --dump-all

# Second run — uses cache, instant output
xpathmap.py -r req.txt --dump-all

# Force fresh extraction
xpathmap.py -r req.txt --dump-all --flush-session
```

---

## 🧪 Testing Locally

A vulnerable test server is included:

```bash
python3 test_server.py
# Listening on http://127.0.0.1:7171

xpathmap.py -u "http://127.0.0.1:7171/search?name=x" --dump-all --batch
```

---

## ⚠️ Disclaimer

This tool is intended for **authorized penetration testing and security research only**.
Do not use against systems you do not have explicit permission to test.
The author is not responsible for any misuse.

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

<p align="center">Made by 👾 <a href=https://t.me/avdev>avdev</a></p>
