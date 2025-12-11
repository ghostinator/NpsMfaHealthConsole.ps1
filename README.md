# NPS + Azure MFA Health Console

A comprehensive, GUI-based PowerShell tool designed to troubleshoot, audit, and fix common issues with the **NPS Extension for Azure MFA**.

This tool provides a unified dashboard to visualize authentication flows, manage certificates, and toggle critical registry settings without needing to dig through Event Viewer or the Registry Editor manually.

<img width="805" height="655" alt="image" src="https://github.com/user-attachments/assets/886a1550-3576-4a6f-bdcf-3ee6ac0ee7ce" />



## 🚀 Features

* **Health Dashboard:** Instantly checks NPS Service status, Azure MFA Extension version, Azure connectivity (TCP 443), and RADIUS Client configurations.
* **Log Forensics & Correlation:**
    * Parses **NPS Text Logs** (IAS) and correlates them with **Azure MFA Event Logs** and **Windows Security Audits**.
    * Visualizes the entire auth flow: *Radius Request -> NPS Policy -> MFA Challenge -> Result*.
* **Certificate Management:**
    * Identifies the active Azure MFA certificate and warns about expiration.
    * One-click cleanup of expired/superseded certificates.
    * Launcher for the official Microsoft Certificate Renewal script.
* **Registry Tuning:**
    * Toggle critical settings like `OVERRIDE_NUMBER_MATCHING_WITH_OTP` and `REQUIRE_USER_MATCH` via a user-friendly UI.
    * Built-in descriptions for every registry key explaining what it fixes.
* **Safety First:** Includes backup features before performing resets.

## 📋 Prerequisites

* **OS:** Windows Server 2012 R2 or later (Server 2016/2019/2022 recommended).
* **Roles:** Network Policy Server (NPS) role installed.
* **Software:** Azure MFA NPS Extension installed.
* **PowerShell:** Version 5.1 (default on Server) or PowerShell 7+.
* **Permissions:** Must be run as **Administrator** (Local Admin) to read logs and modify the registry.

## 📥 Installation

1.  **Download:** Download the `NpsMfaHealthConsole.ps1` file to your NPS Server.
2.  **Unblock:** Right-click the file -> **Properties** -> Check **Unblock** (if applicable).
3.  **Run:**
    Open PowerShell as Administrator and run:
    ```powershell
    .\NpsMfaHealthConsole.ps1
    ```

## 🛠️ Usage Guide

### 1. Overview Tab
This is your landing page. It runs automatic health checks upon launch:
* **NPS Service:** Checks if running and if the startup type is Automatic.
* **Extension Status:** Verifies the DLLs exist and reports the installed version.
* **Connectivity:** Tests TCP connectivity to `adnotifications.windowsazure.com`.
* **Certificate:** Checks the Local Machine store for a valid Azure MFA certificate.

### 2. Logs & Correlation Tab
The core troubleshooting engine.
1.  Enter a **User Name** (UPN or sAMAccountName) to filter the noise.
2.  Set the **Lookback (Minutes)** (default is 30).
3.  Click **Analyze Auth Flow**.
4.  **The Result:** A merged timeline showing exactly where authentication failed (e.g., "MFA Challenge Sent" followed by "Access Denied" or "NPS Discard").

### 3. Certificates Tab
Manage the self-signed certificates used by the extension to talk to Azure.
* **Scan:** Lists all potential MFA certificates in the local store.
* **Remove Expired:** Safely deletes old certificates that clutter the store.
* **Run MS Renewal Script:** Launches the official Microsoft PowerShell script to generate a new cert and update the Service Principal in Azure Entra ID.

### 4. Registry Config Tab
Easily configure advanced settings for the extension.
* **Checkboxes:** Enable or Disable specific registry keys.
* **Dropdowns:** Select valid values (TRUE/FALSE, Timeouts, etc.).
* **Apply Configuration:** Writes the changes to `HKLM\SOFTWARE\Microsoft\AzureMfa` and restarts the service if needed.

**Common Fixes:**
* **VPNs not showing Number Match:** Set `OVERRIDE_NUMBER_MATCHING_WITH_OTP` = `TRUE`.
* **UPN Mismatch:** Set `REQUIRE_USER_MATCH` = `FALSE` if your on-prem usernames don't match Cloud UPNs.

### 5. Start Fresh / Advanced
Use this tab if you need to perform a "hard reset" of the configuration.
* **Backup:** Exports current NPS configuration (XML) and Azure MFA Registry keys (REG) to a timestamped folder.
* **Reset Registry:** Reverts critical keys to their default state.

## ⚠️ Disclaimer
This script is provided "as is" without warranty of any kind. While it includes safety checks (like backups and confirmations), always test in a non-production environment first or ensure you have server backups before performing destructive actions like removing certificates.

## 🤝 Contributing
Issues and Pull Requests are welcome! Please ensure any modifications maintain compatibility with Windows PowerShell 5.1.
