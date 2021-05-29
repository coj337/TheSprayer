![GitHub Actions CI](https://github.com/coj337/TheSprayer/workflows/CI/badge.svg)
![GitHub all releases](https://img.shields.io/github/downloads/coj337/TheSprayer/total)

# TheSprayer
TheSprayer is a cross-platform tool designed to help penetration testers spray passwords against an Active Directory domain WITHOUT locking out accounts.  

## Quick Start
To run it, you will need to update the parameters.
The tool requires a domain name, DC IP/Hostname and a Username+Password combo for the domain in order to enumerate users and password policies.

You can grab a release and run it directly:
```
TheSprayer.exe -d windomain.local -s 192.168.38.102 -u Administrator -p Password1 -i Passwords.txt
```

## Options
```
-d, --Domain          Required. The Active Directory domain (e.g. windomain.local)
-s, --Server          Required. The IP or hostname of a domain controller
-u, --Username        Required. Username for domain user to enumerate policies
-p, --Password        Required. Password for domain user to enumerate policies
-i, --PasswordFile    Required. A file containing a line delimited list of passwords to try
-o, --OutFile         File to output found credentials
--help                Display help screen
--version             Display version information
```

## Releases
| [Windows](https://github.com/coj337/TheSprayer/releases/latest/download/TheSprayer.exe) |
[Linux](https://github.com/coj337/TheSprayer/releases/latest/download/TheSprayer) |
