using CommandLine;

namespace TheSprayer
{
    public class CommandLineOptions
    {
        [Option('d', "Domain", Required = true, HelpText = "The Active Directory domain (e.g. windomain.local)")]
        public string Domain { get; set; }

        [Option('s', "Server", Required = true, HelpText = "The IP or hostname of a domain controller")]
        public string DomainController { get; set; }

        [Option('u', "Username", Required = true, HelpText = "Username for domain user to enumerate policies")]
        public string Username { get; set; }

        [Option('p', "Password", Required = true, HelpText = "Password for domain user to enumerate policies")]
        public string Password { get; set; }

        [Option('i', "PasswordFile", Required = true, HelpText = "A file containing a line delimited list of passwords to try")]
        public string PasswordListFile { get; set; }

        [Option('o', "OutFile", Required = false, HelpText = "File to output found credentials")]
        public string OutFile { get; set; }
    }
}
