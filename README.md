# Nmap-and-scapy-scan
# Objectives
This project captures my hands-on replication of key Nmap and Scapy practical exercises. The objective was to explore an internal lab network by performing host discovery, service enumeration, OS fingerprinting, SMB scans, custom packet crafting, packet sniffing, and ICMP traffic analysis. Through these tasks, I developed essential skills in network reconnaissance, enumeration, and packet-level investigation.
The target network is 10.6.6.0/24, focusing primarily on the host 10.6.6.23 gravemimd.vm
# Environment 
OS: Kali Linux
Tools: Nmap, Scapy, tcpdump
Network Range: 10.6.6.0/24
Target Host: 10.6.6.23
Interface Used: br-internal / eth0
Lab Type: Internal ParoCyber training network

# Nmap Documentation

---
## **Active Host Identification within the Network**

Network Scan (10.6.6.0/24) 

```
nmap -sn 10.6.6.0/24
```

This performs a basic scan of the entire 10.6.6.0/24 network range to discover active hosts and their basic port information. 

---
## **Host Scan**
This performs a focused, single-target scan to reveal open ports and running services on the host.
```
sudo nmap -O 10.6.6.23
```
gravemind.vm shows several open TCP ports, including 21 (ftp), 22 (ssh), 80 (http), 139 (netbios-ssn), and 445 (microsoft-ds). It also provides OS details, indicating the target is running Linux

---
## **Port 21 Aggressive Service Scan**
Identifies the service running on port 21, detects version information, and performs aggressive scanning
```
nmap -p21 -sV -A -T4 10.6.6.23
```

This is a focused aggressive scan. -p 21: Targets only port 21 (FTP). 
-sV: Enables version detection to determine the exact service and version
-A: Enables the aggressive scan features, including OS detection, script scanning, and traceroute3.
-T4: Sets the scanning speed to Aggressive (level 4).

---

## **SMB Ports Scan (139 and 445)**
This scan focuses on ports 139 and 445, which are used by SMB (Server Message Block) for Windows file sharing, to identify potential vulnerabilities.

```
nmap -A -p139,445 10.6.6.23
```

---

## **SMB Share Enumeration with NSE Script**

```
nmap --script smb-enum-shares.nse -p445 10.6.6.23
```

Detects SMB shares available on the target system.

---

## **Supporting Network Context Commands**

```
ifconfig
ip route
cat /etc/resolv.conf
```

Displays interface information, route paths, and DNS resolver configuration.

---

## Scapy Documentation

## **Starting Scapy as Root**

```
sudo su
scapy
```

---

## **Basic Packet Sniffing**

Start sniffing:

```
sniff()
```
Generate traffic in a new terminal:

```
ping google.com
```

Stop sniffing:

* `ctrl + c` on ping
* `ctrl + c` on Scapy

Store captured packets:

```
paro = _
paro.summary()
```

---

## **Interface-Specific Sniffing**

```
sniff(iface="br-internal")
```

Generate traffic:

```
ping 10.6.6.1/24
```

Visit internal page:

```
10.6.6.23
```

Stop sniffing:

```
ctrl + c
```

Store results:

```
paro2 = _
paro2.summary()
```

---

## **ICMP-Filtered Sniffing**

Capture only ICMP packets (five packets total):

```
sniff(iface="br-internal", filter="icmp", count=5)
```

Trigger ICMP:

```
ping 10.6.6.23
```

Stop terminals:

* `ctrl + c` ping
* `ctrl + c` Scapy

Store captured ICMP packets:

```
paro3 = _
paro3.summary()
```

Inspect a specific packet:

```
paro3[3]
```

---

# **Summary of Work**

The Nmap phase focused on identifying active hosts, fingerprinting operating systems, enumerating running services, scanning SMB ports, and confirming SMB accessibility. The Scapy phase showcased packet sniffing, interface-specific traffic capture, ICMP filtering, and deep packet inspection. Combined, these exercises highlight core penetration-testing reconnaissance skills and essential packet-level analysis techniques commonly applied in real-world cybersecurity operations.

