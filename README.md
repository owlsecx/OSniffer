# 🦉 OSniffer

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Linux-0a0c10?style=flat-square"/>
  <img src="https://img.shields.io/badge/Category-ONetwork-blue?style=flat-square"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square"/>
  <img src="https://img.shields.io/badge/Part%20of-OwlSec%20Toolkit-7b5ea7?style=flat-square"/>
  <img src="https://img.shields.io/badge/Version-1.0-cyan?style=flat-square"/>
</p>

> **OSniffer** — Defensive packet capture and network telemetry monitor (DNS/HTTP/TLS/SSH/ARP)

---

> ⚠️ **AUTHORISED USE ONLY** — Use only on systems you own or have explicit written permission to test. Unauthorised use is illegal.

---

## 📌 Overview


OSniffer is a defensive network monitor that captures and analyses traffic metadata without ever extracting credentials or payload content. It decodes DNS, HTTP, HTTPS/TLS, SSH, FTP, SMTP, DHCP, ARP, ICMP, MDNS, NBNS and SSDP, detects port/host scans, and stores sessions in SQLite with HTML reports and encrypted exports. It is intended for authorized security analysis and defensive telemetry only.

---

## ✨ Features


- Protocol-aware metadata decoding for DNS, HTTP, TLS, SSH, FTP, SMTP, DHCP, ARP, ICMP, MDNS, NBNS and SSDP
- Scan-detection engine with configurable window and threshold, plus top-talker statistics
- BPF filtering and host/net/port selectors, with duration/count limits for bounded captures
- SQLite session storage, HTML/JSON/CSV reports and optional password-encrypted exports
- Lab-mode, output masking, daemon mode and an embedded web view (--web HOST:PORT)
- Defensive by design: never extracts credentials, passwords or payload content

---

## ⚙️ Requirements

- **Linux**
- **No Python installation needed** — runs as a standalone executable

---

## 🚀 Usage


```bash
./OSniffer -i eth0 --duration 60 --html report.html
./OSniffer -i wlan0 --dns-only --json dns.json
./OSniffer -i eth0 --bpf "tcp port 443" --mask-output --encrypt
./OSniffer --self-test
./OSniffer --help
```

---

## 📦 Part of OwlSec Toolkit

This tool is part of the **OwlSec** suite — a collection of 300+ security and privacy tools.

🔗 [owlsec.org](https://owlsec.org)

---

## ©️ License

MIT License — © Khaled S. Haddad

*Tools are distributed as pre-built executables. Source code is proprietary.*
