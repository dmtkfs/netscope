# **NetScope: Home Network Visibility & Safe MITM Analysis Toolkit**

>***NetScope** is a Windows-focused Python toolkit that provides **local network visibility**, **device inventory**, **hostname/vendor mapping**, **live connection monitoring** and a **safely constrained ARP man-in-the-middle inspection mode** for educational, diagnostic and authorized home security testing.
>It is built for **clarity**, **safety** and **zero destructive actions**. All active behavior is strictly limited to ARP spoofing within the user’s own LAN and automatically self-repairs on exit.*

### ⚠️ Legal & Ethical Disclaimer

**NetScope is intended ONLY for use on networks you own or are explicitly authorized to test.**

Unauthorized interception or manipulation of network traffic is **illegal** in most jurisdictions.

By using this tool, you agree that:

* You will **not use it against networks/devices without explicit permission**
* You understand that traffic inspection, even passively, may expose sensitive information
* You assume all responsibility for your usage

The authors and contributors are **not liable for misuse, damage, or legal consequences** arising from this software.

# Features

### **1. Device Inventory**

* Discovers devices on your local Wi-Fi/Ethernet network
* Collects:
  * IP address
  * MAC address
  * Vendor name (via OUI lookup)
  * Reverse DNS hostnames (if available)
* Performs safe ARP + ping-based discovery (no port scanning)
* Saves results in `.netscope/cache/<interface>.json`

### **2. Host Connection Insight**

* Displays your host’s outbound connections (TCP/UDP)
* Includes:
  * Process name
  * Local/remote IPs & ports
  * DNS-resolved hostnames
  * WHOIS enrichment (organization name)

### **3. Live Host Activity (“host-live”)**

* Runs a DNS + SNI sniffer (requires Npcap)
* Shows live process-to-domain mappings
* Helpful for understanding what apps talk to which clouds (Google, AWS, Akamai, etc.)

### **4. MITM Planning (Dry Run)**

* Uses your inventory snapshot to let you select a target device
* Detects the gateway
* Computes ARP relationships from the current ARP table
* Prints a detailed description of what would happen—*but performs no changes*

### **5. Active MITM Mode**

A controlled ARP poisoning engine + traffic sniffer:

* Enables Windows IPv4 forwarding only for the session
* ARP poisoning at safe, low frequency
* Sniffing operates on all available Npcap interfaces  
* Extracts:
  * Target’s remote connections
  * Ports
  * DNS/SNI-based hostnames
  * WHOIS ownership (AWS, Google Cloud, etc.)    
* On exit:
  * Sends ARP repair packets
  * Restores IP forwarding
  * Cleans up gracefully

### **6. Safety Rails**

Built specifically to avoid user-accidental damage:

* No packet flooding
* No routing table modification
* No firewall modification
* No services disabled
* No OS-level ARP table writes (repair uses broadcast ARP only)
* Limited to LAN layer-2 only
* Fails gracefully when target/gateway MACs cannot be validated

# Installation

### Requirements

* **Python 3.10+**
* **Windows 10/11**
* **Npcap** installed in *WinPcap compatibility mode*
  ([https://nmap.org/npcap/](https://nmap.org/npcap/))
* Admin privileges when sniffing/ARP spoofing

### Install dependencies

```
pip install -r requirements.txt
```

Typical requirements include:

```
psutil
scapy
ipwhois
manuf
```
# Usage

*All commands are run as:*

```
python run_netscope.py <command>
```

## 1. Device Inventory

```
python run_netscope.py inventory
```
*Scans the local subnet using safe ARP + ping probes and produces a full device list (IP, MAC, vendor, hostname), saving a snapshot for later MITM sessions.*

## 2. Host Insight (snapshot)

```powershell
python run_netscope.py host
```
*Shows your computer’s current outbound connections, enriched with DNS lookups, process names and WHOIS information.*

## 3. Live Host View

```powershell
python run_netscope.py host-live
```
*Runs a real-time DNS/SNI sniffer (Npcap required) to reveal which apps and processes are actively communicating with which domains/clouds.*

## 4. MITM Dry Run

```powershell
python run_netscope.py mitm-plan
```
*Shows:*
* *target IP*
* *gateway IP*
* *ARP table snapshot*
* *safety plan*
* *what would happen if MITM were run*

*Builds a safe simulation of a MITM attack: computes the target, gateway, ARP map and shows exactly what would happen without sending any packets.*

## 5. Active MITM

```powershell
python run_netscope.py mitm
```
*Performs a controlled ARP MITM against a chosen device, captures its outbound IPv4 connections, and displays cloud/vendor mapping before restoring the network state.*

*You will:*

  1. *Choose the interface*
  2. *Select a target from inventory*
  3. *Confirm gateway*
  4. *Begin active ARP MITM*
  5. *Press **Ctrl+C** to stop**

*After stopping, you will see a summary of:*

* *Remote IPs contacted*
* *Cloud / WHOIS mappings (e.g., GOOGLE-CLOUD, AMAZON-IAD, etc.)*

# How It Works (Technical Overview)

### Device Discovery

* ARP cache parsing
* Subnet ping sweep
* OUI database for vendor lookup
* Reverse DNS (PTR) lookups
* Snapshot saved locally in JSON

### MITM Engine

* ARP spoofing with Scapy
* Windows IP forwarding temporarily enabled
* Traffic sniffed using Scapy sniff() across all adapters

### Traffic Mapping

* DNS capture → hostname mapping
* WHOIS queries → cloud/vendor enrichment
* TLS SNI capture (if available)

### Safety Design

* No forced gateway routing changes
* ARP poisoning rate limited
* All ARP effects auto-restored
* Forwarding always reverted

# Limitations

* **Only works on LANs** (Wi-Fi/Ethernet)
* Does **not** bypass encrypted traffic (HTTPS)
  * Only metadata (remote IP, SNI, DNS, ports) is visible
* Some devices may ignore or bypass ARP poisoning entirely. This usually happens because they use one or more of the following protections:
  * ARP spoofing mitigation: OS network stacks validate ARP replies or throttle unsolicited updates.
  * MAC randomization: Especially on Wi-Fi, devices periodically rotate MACs, breaking persistent spoofing.
  * Client isolation / AP protections: Many access points isolate wireless clients or suppress forged ARP announcements.
  * Preferential IPv6 routing: Traffic may flow over IPv6 (NDP, RA) instead of IPv4, where ARP-based MITM is ineffective.
* Encrypted DNS (DoH/DoT) prevents domain visibility
* Windows interface naming may differ from Npcap adapter naming
* No deep packet inspection (no decryption)
