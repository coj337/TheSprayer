using CommandLine;

namespace TheSprayer
{
    public class CommandLineOptions
    {
        [Option('d', "Domain", Required = true, HelpText = "The Active Directory domain (e.g. windomain.local)")]
        public string Domain { get; set; }

        [Option('s', "Server", Required = true, HelpText = "The IP or hostname of a domain controller")]
        public string DomainController { get; set; }

        [Option('U', "Username", Required = true, HelpText = "Username for domain user to enumerate policies")]
        public string Username { get; set; }

        [Option('P', "Password", Required = true, HelpText = "Password for domain user to enumerate policies")]
        public string Password { get; set; }

        [Option('u', "UserList", Required = false, HelpText = "A file containing a line delimited list of usernames or a single user to try")]
        public string UserList { get; set; }

        [Option('p', "PasswordList", Required = true, HelpText = "A file containing a line delimited list of passwords or a single password to try")]
        public string PasswordList { get; set; }

        [Option('o', "OutFile", Required = false, HelpText = "File to output found credentials")]
        public string OutFile { get; set; }

        [Option('a', "AttemptsRemaining", Required = false, HelpText = "Amount of attempts to leave per-account before lockout (Default: 2)")]
        public int AttemptsRemaining { get; set; }
    }
}
