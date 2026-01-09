# Lab Demo Guide: Windows Adaptive Security Agent

This guide outlines the steps to replicate the "Self-Healing" capabilities of the WASA agent in a virtual lab environment.

## Prerequisites
* **Victim Machine:** Windows 10/11 or Server (IP: `Target_IP`)
* **Attacker Machine:** Kali Linux or another Windows VM
* **Network:** Both machines must be on the same isolated network (e.g., Host-Only Adapter).

---

## Step 1: Prepare the Victim (Windows)
1.  **Reset Security Policy:**
    Ensure the system is currently "vulnerable" (no account lockout policy).
    ```powershell
    net accounts /lockoutthreshold:0
    ```
2.  **Allow Script Execution:**
    ```powershell
    Set-ExecutionPolicy Bypass -Scope Process -Force
    ```
3.  **Start the Agent:**
    Open PowerShell as Administrator and run:
    ```powershell
    .\src\agent.ps1
    ```
    *Status: You should see `[INFO] LISTENING FOR ATTACKS...`*

---

## Step 2: Launch the Attack (Kali Linux)
We will simulate a brute-force attack against the SMB protocol. This generates the same Event ID (`4625`) as RDP but is faster and more reliable for testing.

1.  **Generate a Payload:**
    Create a file with 10 wrong passwords.
    ```bash
    for i in {1..10}; do echo "wrongpass" >> badpass.txt; done
    ```
2.  **Fire the Attack:**
    Replace `[Target_IP]` with your Windows VM IP.
    ```bash
    hydra -l testadmin -P badpass.txt [Target_IP] smb
    ```

---

## Step 3: Verify the Defense
Watch the Windows PowerShell window. As the attack hits the 5th failure threshold:

### 1. The Alert 
The agent will detect the anomaly and output:
> `[ALERT] BRUTE FORCE DETECTED: User testadmin (5 failures)`

### 2. The Healing 
The agent automatically hardens the operating system configuration:
> `[HEALING] POLICY: System hardened (Lockout set to 3)`

**Proof:** Open a new terminal and run: `net accounts`.
* *Result:* "Lockout threshold" will now be **3**.

### 3. The Block 
The agent permanently blocks the attacker's IP:
> `[DEFENSE] FIREWALL: Blocked IP [Attacker_IP]`

**Proof:** Run `Get-NetFirewallRule -DisplayName "AutoBlock_*"`.
* *Result:* You will see a new rule created for the specific attacker IP.

---

## Step 4: Reset the Lab
To run the demo again, run these cleanup commands on the Windows Victim:

```powershell
# 1. Unblock the IP
Get-NetFirewallRule -DisplayName "AutoBlock_*" | Remove-NetFirewallRule

# 2. Reset Policy to Vulnerable
net accounts /lockoutthreshold:0
