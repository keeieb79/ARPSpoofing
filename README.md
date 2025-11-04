# MITMscapy

`MITMscapy.py` is a Man-In-The-Middle (MITM) utility implemented in Python using **Scapy**.  
It performs ARP spoofing to intercept and inspect HTTP (port 80) traffic between a victim and a router on the same local network.

> **Warning:** This script is intended only for educational and authorized security testing.  
> Unauthorized use on networks you do not own or do not have explicit permission to test is illegal.

---

## Table of Contents

- [Description](#description)  
- [Features](#features)  
- [How it Works](#how-it-works)  
- [Installation](#installation)  
- [Usage](#usage)  
  - [Arguments](#arguments)  
  - [Example](#example)  
- [Requirements](#requirements)  
- [Safety & Ethics](#safety--ethics)  
- [Notes & Limitations](#notes--limitations)  
- [Contributing](#contributing)  
- [License](#license)

---

## Description

`MITMscapy.py` automates ARP spoofing between a victim and a router (gateway), enabling packet capture and payload inspection of intercepted HTTP traffic.

The script:

- Discovers MAC addresses for provided IPs.  
- Forges ARP replies to poison ARP caches of both victim and router.  
- Runs a packet sniffer on the specified interface and prints raw payloads when present.  
- Attempts to restore original ARP mappings when the script exits.

---

## Features

- Automatic ARP spoofing of victim and router.  
- Live packet sniffing (default: HTTP / port 80).  
- Automatic ARP table restoration on exit (uses `atexit` and sends corrective ARP replies).  
- Multithreaded operation: spoofing and sniffing run concurrently.  
- Prints decoded raw payloads (where decoding succeeds).

---

## Demo video
- linux (fedora): the attacker
- windows 10: the victim

[ARPSpoofingScapy.webm](https://github.com/user-attachments/assets/547342d0-695d-4443-b0e7-1c62b7255d1c)

---
## How it Works

1. The script uses ARP requests to obtain MAC addresses for the victim and router IPs.  
2. It continuously sends forged ARP replies to both the victim and router so that each believes the attacker's MAC corresponds to the other's IP.  
3. With traffic redirected, the script sniffs packets on the chosen interface and prints decoded payloads for packets that contain raw application data.  
4. On normal exit (Ctrl+C) or process termination via Python mechanisms, the script tries to restore correct ARP mappings by sending multiple corrective ARP replies to both targets.

---

## Installation

### installation
```bash
pip install scapy
```

> Note: On some systems Scapy may require additional OS packages (for example `libpcap` development headers). Use your distribution package manager if necessary.

---

## Usage

Run the script with root/administrator privileges (required to send raw packets and sniff network interfaces):


```bash
sudo python3 MITMscapy.py -i <interface> -r <router_ip> -v <victim_ip>
```

### Arguments

- `-i`, `--interface` — Network interface name (example: `eth0`, `wlan0`)  
- `-r`, `--routerIP` — Router (gateway) IP address  
- `-v`, `--victimIP` — Victim (target) IP address

### Example
```bash
sudo python3 MITMscapy.py -i wlan0 -r 192.168.1.1 -v 192.168.1.20
```

---

## Requirements

- Python 3.8 or newer.  
- Scapy (`pip install scapy`).  
- Root/administrator privileges to operate network interfaces and send raw packets.

---

## Safety & Ethics

- Use only in controlled lab environments or on networks where you have explicit permission to perform testing.  
- ARP spoofing can disrupt network connectivity; inform and obtain consent from network owners and affected users.  
- Misuse of this tool may be illegal and may cause harm to networks or devices. The author and repository maintainers are not responsible for misuse.

---

## Notes & Limitations

- Sniffing is limited to port 80 (HTTP) by default; encrypted traffic (HTTPS) will not be readable.  
- The script attempts to restore ARP entries on exit; unexpected termination (for example, `kill -9`) may leave incorrect ARP entries on targets. In such cases, rebooting targets or manually clearing ARP caches may be necessary.  
- The `getMac` function retries via recursion on failure; repeated unresolved addresses can result in extended runtime. Consider improving retry/backoff logic for production testing.  
- Decoding of raw payloads assumes text encodings; binary data or other encodings may be skipped silently.

---

## Contributing

If you want to contribute improvements, consider:

- adding configurable filters (ports, protocols),  
- adding logging to file instead of printing to STDOUT,  
- adding improved ARP recovery strategies,  
- adding a safer/test mode that simulates spoofing without sending packets.

Please submit pull requests or open issues describing what you intend to change.

---

## License
**GPL-3.0 license**
