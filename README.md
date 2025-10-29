# WindowsSecurer

WindowsSecurer is a Windows hardening and system-collection PowerShell script (or collection of scripts) that performs reconnaissance and applies many security-focused configuration changes to a Windows computer for the CyberPatriot competition. 

Disclaimer: I am no longer a participant in the competition. This script serves as inspiration. You may not use this script in a CyPat competition unless you have permission from Troy Cyber.

> WARNING: Make sure forensic questions are answered/thought-out before running this script. This script might delete malicious folders containing information needed to solve these questions.


## Instructions
1. Download as zip. It'll be named ```win-main```.
  2. Edit the `users.txt` and `admins.txt` files. If there's some Windows system critical services, possibly edit the `enabled_services.txt` or `disabled_services.txt` files. The script will ask you if you want to enable and configure RDP, FTP, and SMB.
  3. Run the following in a Powershell terminal with administrative privileges:
  ```powershell
  Set-ExecutionPolicy Unrestricted -Confirm -Force
  .\scripts\main.ps1
  ```
  The script will try to import a GPO last. You can start doing your own thing by then, even before the GPO finishes importing. The output will be logged to `script_log.txt` in the `logs` folder. 

If you want to look for media files, run `media.bat`, which will log to a folder on your user's desktop.

## GPOs
- `{9AA00A8B-E75B-452C-B263-D4FA774C511E}` is Kile and Nick's Win10UltGPO
- `{EE1CF134-A163-4488-8832-D7CEAC60FB43}` is Olric's old one
- `{79677B19-3111-423D-AB81-B72CBD52008D}` is the new one made by Olric and Shirley

## Details

This script creates a directory on the Desktop (by default) called `windowssecurer-output` which houses all the files it creates. The script can perform one or more of the following actions:

- Collect system artifacts (users, groups, shares, processes, hosts file, firewall config, netstat, open ports).
- Make a more readable and useful NETSTAT-style listing (including owning process and PID).
- Enumerate users and groups; optionally disable and rename built-in Guest and Administrator accounts.
- Optionally set or enforce a secure password for every local user (configurable).
- Export Account and Local Security Policies.
- Enumerate and export share configurations.
- Flush DNS cache and save DNS resolver state.
- Collect hosts file and other network-related config files.
- Disable unnecessary Windows features.
- List and optionally terminate processes exceeding a configured memory threshold (defaults to 2000 MB).
- Ensure Windows Firewall is enabled, import secure rules, and add custom rules.
- Set network profile to Public to reduce file/device discovery.
- Apply a large set of registry hardening keys (Remote Desktop disabling, Automatic Updates configuration, UAC settings, LSASS auditing, SMB hardening, clear sensitive paths, disable storage of domain passwords, restrict anonymous enumeration, and many more — see "Registry" below).
- Enable Windows Defender and related protections where applicable.
- Disable unsafe Autoruns / Startup entries (safe-mode toggle available).
- Disable macros and block risky Office/execution behaviors (where possible via policy).
- Enable smart screen / phishing protections for Internet Explorer/Edge as supported on the host.
- Manage Windows services: disable unneeded services and ensure required ones (e.g., Windows Update) are running.
- Create an audit log of everything the script changed and collected so changes are reproducible and reviewable.

What it does (explanation)
The script is split into collection and remediation phases. Collection gathers key artifacts to help with incident response or review. Remediation applies a set of conservative security baseline changes intended to reduce attack surface and lock down common risky behaviors. The collected artifacts allow you to review changes and provide a baseline snapshot for future comparison.

Modules & Features (detailed)
- Files & Output
  - Creates a top-level output folder on the Desktop (default `Desktop\windowssecurer-output`) and writes all artifacts and logs there.
  - Exports text and CSV files for most enumerations to make them easy to parse or feed into other tools.

- Network & Recon
  - Enhanced NETSTAT: lists active connections, listening ports, owning process names and PIDs, and remote endpoints.
  - Saves `ipconfig /all`, `route print`, ARP table, DNS cache (if requested), and hosts file.
  - Lists installed network adapters and their properties.

- Users & Accounts
  - Enumerates local users and groups and writes detailed reports.
  - Optionally disables, renames, or sets passwords for built-in accounts (Guest, Administrator) — configurable and disabled by default.
  - Optionally enforces a password policy or sets passwords (default example password in scripts is `Asecurepassword123!` — change this before running).

- Policies
  - Exports Local Security Policy and Account Policy (where available) to files for review.
  - Applies recommended account policy changes (password length, complexity, max age) if remediation mode is enabled.

- File Shares
  - Enumerates all registered shares and their permissions and writes to an output file.

- Processes & Memory
  - Lists all processes and can create a separate file for processes exceeding a configurable memory threshold (default 2000 MB).

- Firewall
  - Ensures Windows Firewall is enabled.
  - Optionally imports a bundled firewall configuration (if supplied) with hardened settings.
  - Adds custom inbound and outbound rules recommended for a locked-down host (examples provided in the scripts).
  - Sets network profile to Public to reduce discovery & file sharing (configurable).

- Registry Hardening (examples of keys changed)
  - Disable Remote Desktop
  - Configure Automatic Updates (set to recommended mode for organization)
  - Restrict CD-ROM / removable media policies
  - Disable remote access to floppy drives (if present)
  - Clear/disable page file or configure it per policy (note: modifying page file has side effects)
  - Restrict installation of printer drivers
  - Enable auditing for LSASS.exe access
  - Enable LSA protection (RunAsPPL where supported)
  - Limit use of blank passwords
  - Audit access to global system objects
  - Audit Backup and Restore
  - Restrict anonymous enumeration (shares, SAM)
  - Disable storage of domain passwords in memory (if available)
  - Remove Anonymous User/Everyone permissions from sensitive objects
  - Enforce NTLM/SMB signing and sealing where possible
  - Set idle lock timeout (example 45 minutes)
  - Clear null session pipes
  - Restrict anonymous access to named pipes and shares
  - Enable SMB encryption where applicable
  - Clear remote registry paths and restrict remote registry service
  - Enable SmartScreen and phishing protections for supported browsers
  - Disable IE password caching (legacy IE policies)
  - Warn users for bad certificates and redirects
  - Enable Do Not Track
  - Show hidden and protected OS files (if desired; configurable)
  - Disable crash dump file creation (optional)
  - Disable Autoruns (or export autorun list and optionally disable)
  - Enable Windows Defender (where available) and configure exclusions minimally
  - Block macros and untrusted content execution via Office macro policies (where Group Policy support exists)

  Note: Registry modifications are extensive and dependent on Windows version. Scripts check Windows build and only apply keys appropriate for that version. Review the changes before applying in production.

- Services
  - Enumerates all services and their startup types.
  - Disables commonly unnecessary services (configurable list).
  - Ensures necessary services are running (e.g., Windows Update, Windows Defender services, Event Log).

Output & directory layout (example)
- Desktop\windowssecurer-output\
  - README-run.json 
  - logs\script.log
  - collection\users.csv
  - collection\groups.csv
  - collection\netstat.csv
  - collection\processes.csv
  - collection\large-processes.csv
  - collection\shares.csv
  - collection\hosts.txt
  - collection\firewall-policy.wfw (exported)
  - remediation\registry-changes.txt 
  - remediation\services-changes.txt
  - remediation\firewall-changes.txt

Configuration options
- OUTPUT_DIR: path to write output (defaults to Desktop\windowssecurer-output)
- DRY_RUN: if true, the script will only collect artifacts and print planned changes without applying them
- VERBOSE / LOG_LEVEL: more detailed logging
- APPLY_REMEDIATION: enable or disable remediation actions (default: false)
- ENFORCE_PASSWORDS: boolean (if true, will set local user passwords)
- NEW_PASSWORD: string used when ENFORCE_PASSWORDS is enabled (do NOT hardcode insecure passwords)
- MEMORY_THRESHOLD_MB: threshold for listing/stopping large processes (default 2000)
- FIREWALL_PROFILE: "Public" | "Private" | "Domain" for network profile changes
- MODULES: allow running a subset of modules, e.g. `Modules = @("Users","Firewall","Registry")`

Requirements
- Windows 8 / Server 2012 or newer recommended. Some features work on older versions; scripts include checks.
- PowerShell 5.1+, or PowerShell 7.x (some cmdlets differ between versions).
- Administrator privileges (required for most remediation actions).
- When run on domain-joined machines, some changes may be overridden by Group Policy.
- Optional: execution policy might need to be set to allow running scripts (or sign scripts).

Safety, rollback & testing
- Test on a non-production virtual machine before running on production systems.
- Backup important configuration: Export the registry hives and system state, create a snapshot, or set a System Restore point if possible.
- The script records all modifications in the remediation folder. If available, use the generated registry export files to roll back specific keys (the script may optionally create .reg backups before applying changes).
- Some changes (e.g., setting password for all accounts) can lock you out if misconfigured; always verify credentials and have an alternative admin account or emergency access.
- For domain-joined machines: many changes might be reverted by domain Group Policy. Coordinate with domain admins before running.

