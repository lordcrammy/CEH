# CEH
CEH Exam Notes

Useful Links:
https://gtfobins.github.io/ - List of binaries that can be used to exploit misconfigured permissions.
https://www.rapid7.com/db/ - Vulnerability and Exploit Database
https://crackstation.net/ - List of Password Hashes to crack online
https://github.com/danielmiessler/SecLists - Wordlists, payloads, web shells
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md - Reverse shell cheatsheet
https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php - PHP reverse shell for web servers

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
