# Port-Scanner
# 🔍 Port Scanner Tool

Bash-based interactive port scanner with colorful output, progress bar, JSON support, vulnerability hints, and service detection.

> ⚠️ For educational and authorized use only.

---

## 📌 Features

- ✅ Scan single port or a range of ports.
- 🎨 Color-coded, readable output.
- ⚠️ Warns about commonly vulnerable ports.
- 📁 Saves results to text file and optional JSON.
- 📊 Shows real-time scanning progress bar.
- 🔎 Identifies known services by port number.

---

## 🚀 Usage

```bash
./portscanner.sh <target_ip_or_domain> <start_port-end_port> [options]


| Option                 | Description                                |
| ---------------------- | ------------------------------------------ |
| `--timeout=<seconds>`  | Set timeout per port scan (default: 1 sec) |
| `--json`               | Output results to `results.json` in JSON   |
| `--single-port=<port>` | Scan a single port only                    |
| `--help`               | Show usage help                            |


# Scan ports 20 to 80 on 8.8.8.8
./portscanner.sh 8.8.8.8 20-80

# Scan only port 22 and save as JSON
./portscanner.sh 192.168.1.1 --single-port=22 --json

# Scan with 2 seconds timeout
./portscanner.sh example.com 1000-1010 --timeout=2


📄 Output
Text File: Results saved as scan_results_YYYYMMDD_HHMMSS.txt

Optional JSON: If --json is passed, results saved in results.json

Each scanned port includes:

Port number

Status (open/closed)

Associated service (if recognized)

Security warning if port is known to be vulnerable

🔐 Security Notes
Only scan IPs/domains you have permission to test.

This script is for educational and authorized use only.

Some ports may show as open but may not be vulnerable unless misconfigured.

🧑‍💻 Author
Made with ❤️ for learning and practical cybersecurity usage.

📜 License
This project is licensed under the MIT License - feel free to modify and use it responsibly.

📷 Screenshots
You can add screenshots/gifs here to show the tool in action.

🌍 Multilingual Support
This script has Arabic comments and usage hints for native Arabic speakers.

.

