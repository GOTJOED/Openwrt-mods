# OpenWrt Live Firewall Intelligence Dashboard

![Version](https://img.shields.io/badge/version-1.0.0-purple.svg) ![License](https://img.shields.io/badge/license-MIT-green.svg) ![OpenWrt](https://img.shields.io/badge/OpenWrt-21.02+-orange.svg)

A real-time firewall intelligence dashboard for OpenWrt LuCI. Visualize dropped and allowed packets, identify top offending IPs, and monitor triggered firewall rules directly from your router.

## Features

🛡️ **Live Packet Tracking**
* Real-time monitoring of OpenWrt `dmesg` logs
* Visual badges for firewall actions (ALLOW, DROP, REJECT)
* Protocol identification (TCP, UDP, ICMP)

📊 **Smart Analytics**
* Top Source IPs leaderboard
* Top Target IPs leaderboard
* Top Triggered Firewall Rules tracking

⚡ **Interactive Interface**
* Clickable IP addresses for instant search filtering
* Global search bar

---

## Installation

### Prerequisites
* OpenWrt 25.x or later
* LuCI web interface installed
* SSH access to your router
