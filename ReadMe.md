![GitHub Actions CI](https://github.com/coj337/TheSprayer/workflows/CI/badge.svg)
![GitHub all releases](https://img.shields.io/github/downloads/coj337/TheSprayer/total)

# TheSprayer
TheSprayer is a cross-platform tool designed to help penetration testers spray passwords against an Active Directory domain WITHOUT locking out accounts.  

## Quick Start
To run it, you will need to update the parameters.
The tool requires a domain name, DC IP/Hostname and a Username+Password combo for the domain in order to enumerate users and password policies.

Spray all users with a password list:
```
TheSprayer.exe -d windomain.local -s 192.168.38.102 -U Administrator -P Password1 -p Passwords.txt
```

Spray against a list of users:
```
TheSprayer.exe -d windomain.local -s 192.168.38.102 -U Administrator -P Password1 -u Users.txt
```

Spray a single user+password without any files:
```
TheSprayer.exe -d windomain.local -s 192.168.38.102 -U Administrator -P Password1 -u DomainAdmin -p DefinitelyValidPassword
``` 

## Options
```
-d, --Domain               Required. The Active Directory domain (e.g. windomain.local)
-s, --Server               Required. The IP or hostname of a domain controller
-U, --Username             Required. Username for domain user to enumerate policies
-P, --Password             Required. Password for domain user to enumerate policies
-p, --PasswordList         Required. A file containing a line delimited list of passwords or a single password to try
-u, --UserList             A file containing a line delimited list of usernames or a single user to try
-o, --OutFile              File to output found credentials
-a, --AttemptsRemaining    Amount of attempts to leave per-account before lockout (Default: 2)
-f, --Force                Force authentication attempts, even users close to lockout
--help                     Display this help screen.
```

## Releases
| [Windows](https://github.com/coj337/TheSprayer/releases/latest/download/TheSprayer.exe) |
[Linux](https://github.com/coj337/TheSprayer/releases/latest/download/TheSprayer) |
