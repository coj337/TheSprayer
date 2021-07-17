using CommandLine;

namespace TheSprayer
{
    public class CommandLineOptions
    {
        [Option('d', "Domain", Required = false, HelpText = "The Active Directory domain (e.g. windomain.local)")]
        public string Domain { get; set; }

        [Option('s', "Server", Required = false, HelpText = "The IP or hostname of a domain controller")]
        public string DomainController { get; set; }

        [Option('U', "Username", Required = false, HelpText = "Username for domain user to enumerate policies")]
        public string Username { get; set; }

        [Option('P', "Password", Required = false, HelpText = "Password for domain user to enumerate policies")]
        public string Password { get; set; }

        [Option('u', "UserList", Required = false, HelpText = "A file containing a line delimited list of usernames or a single user to try")]
        public string UserList { get; set; }

        [Option('p', "PasswordList", Required = false, HelpText = "A file containing a line delimited list of passwords or a single password to try")]
        public string PasswordList { get; set; }

        [Option('o', "OutFile", Required = false, HelpText = "File to output found credentials")]
        public string OutFile { get; set; }

        [Option('a', "AttemptsRemaining", Required = false, HelpText = "Amount of attempts to leave per-account before lockout (Default: 2)")]
        public int AttemptsRemaining { get; set; }

        [Option('c', "Continuous", Required = false, HelpText = "Continuously spray credentials, waiting between attempts to prevent lockout.")]
        public bool Continuous { get; set; }

        [Option('n', "NoDb", Required = false, HelpText = "Disable using a DB to store previously sprayed creds.")]
        public bool NoDb { get; set; }

        [Option("Users", Required = false, HelpText = "Outputs a list of all users to the specified file")]
        public string OutputUsers { get; set; }

        [Option("UsersCsv", Required = false, HelpText = "Outputs a list of all users along with their domain info to the specified CSV file")]
        public string OutputUsersCsv { get; set; }

        [Option("Policy", Required = false, HelpText = "Outputs the password policy(ies) to the terminal")]
        public bool OutputPasswordPolicy { get; set; }

        [Option('f', "Force", Required = false, HelpText = "Force authentication attempts, even users close to lockout")]
        public bool Force { get; set; }
    }
}
