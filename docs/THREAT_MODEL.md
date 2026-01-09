# Threat Model & Trust Boundaries

## 1. Scope
The goal of the Windows Adaptive Security Agent (WASA) is to detect and mitigate local brute-force attacks without introducing new vulnerabilities or instability to the host OS.

## 2. Trust Boundaries
* **Sensor (System) ↔ Detector (Logic):** The detector trusts the Windows Event Log integrity. It validates all input to prevent injection attacks via log spoofing.
* **Responder ↔ OS Configuration:** The agent runs with Administrator privileges but is scoped to modify *only* specific Firewall Rules (`AutoBlock_*`) and the `Account Lockout` policy. It cannot modify other system binaries or registry keys.

## 3. Risk Acceptance
* **False Positives:** Legitimate users failing passwords 5 times rapidly will be temporarily blocked. This is an accepted trade-off for the "Self-Healing" capability in this lab environment.
* **Local Admin Abuse:** If an attacker already has Admin rights, they can terminate the agent. This tool is designed to stop *unprivileged* attackers from gaining that access.