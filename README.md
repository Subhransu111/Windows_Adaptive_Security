# Windows Adaptive Security Agent (WASA)

> **A self-healing host-based security system for Windows that detects brute-force attacks in real-time and automatically hardens the operating system.**

![Status](https://img.shields.io/badge/Status-Prototype-orange) ![Platform](https://img.shields.io/badge/Platform-Windows_10%2F11-blue) ![Language](https://img.shields.io/badge/Language-PowerShell_5.1-blue)

##  Project Overview
WASA is a lightweight, event-driven security agent designed to close the gap between **detection** and **response**. Unlike traditional tools that simply log attacks, WASA acts as an automated Blue Team operator: detecting threats in real-time and applying configuration hardening to stop them.

**Core Capabilities:**
* **Zero-Latency Detection:** Listens directly to the Windows Kernel Event Stream (ETW).
* **Adaptive Response:** Dynamically hardens the `Account Lockout Policy` when under attack.
* **Active Defense:** Instantly blocks attacker IPs using the Windows Firewall API.
* **Self-Healing:** Restores a secure posture automatically without human intervention.

##  Architecture
The system follows a sensor-detector-responder pipeline:

```mermaid
graph TD
    A[Attacker] -->|Brute Force RDP/SMB| B(Windows OS)
    B -->|Event ID 4625| C[Sensor Component]
    C -->|Normalized JSON| D{Detector Logic}
    D -->|Count > 5 in 60s| E[Trigger Alert]
    
    E -->|Action 1| F[Responder: Firewall Block]
    E -->|Action 2| G[Responder: Policy Hardening]
    
    F -->|Block IP| B
    G -->|Set Lockout Threshold| B
