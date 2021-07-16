![GitHub Actions CI](https://github.com/coj337/TheSprayer/workflows/CI/badge.svg)
![GitHub all releases](https://img.shields.io/github/downloads/coj337/TheSprayer/total)

# TheSprayer
TheSprayer is a cross-platform tool designed to help penetration testers spray passwords against an Active Directory domain WITHOUT locking out accounts.  

## Quick Start
To run it, you will need to update the parameters.
I've covered off a bunch of common use cases below, you can mix and match too! 🔥

##### Spray all users with a password list:
```
TheSprayer.exe -p Passwords.txt
```

##### Spray against a list of users:
```
TheSprayer.exe -u Users.txt
```

##### Spray a single user and password:
```
TheSprayer.exe -u DomainAdmin -p DefinitelyValidPassword
``` 

##### Spray as another user
```
TheSprayer.exe -U Administrator -P Password1 -p Passwords.txt
```

##### Spray from a non-domain machine
```
TheSprayer.exe -d windomain.local -s 192.168.38.102 -p Passwords.txt
```

##### Spray from a non-domain machine with another user
```
TheSprayer.exe -d windomain.local -s 192.168.38.102 -U Administrator -P Password1 -p Passwords.txt
```

##### Force spray a password list against all users
```
TheSprayer.exe -p Passwords.txt -f
```
*Note: This will spray even if it's detected as unsafe, use at your own risk!*

## Options
```
-d, --Domain               Required. The Active Directory domain (e.g. windomain.local)
-s, --Server               Required. The IP or hostname of a domain controller
-U, --Username             Required. Username for domain user to enumerate policies
-P, --Password             Required. Password for domain user to enumerate policies
-u, --UserList             A file containing a line delimited list of usernames or a single user to try
-p, --PasswordList         Required. A file containing a line delimited list of passwords or a single password to try
-o, --OutFile              File to output found credentials
-a, --AttemptsRemaining    Amount of attempts to leave per-account before lockout (Default: 2)
-c, --Continuous           Continuously spray credentials, waiting between attempts to prevent lockout.
-n, --NoDb                 Disable using a DB to store previously sprayed creds.
-f, --Force                Force authentication attempts, even users close to lockout
--help                     Display this help screen.
```

## Releases
| [Windows](https://github.com/coj337/TheSprayer/releases/latest/download/TheSprayer.exe) |
[Linux](https://github.com/coj337/TheSprayer/releases/latest/download/TheSprayer) |
