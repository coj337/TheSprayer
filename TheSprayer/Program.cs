using CommandLine;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace TheSprayer
{
    public class Program
    {
        public static void Main(string[] args)
        {
            Parser.Default.ParseArguments<CommandLineOptions>(args).WithParsed(o =>
            {
                var adService = new ActiveDirectoryService(o.Domain, o.Username, o.Password, o.DomainController);
                
                IEnumerable<string> passwords, users;
                int remainingAttempts;

                //Get password list from file or assume it's a single password if it doesn't exist
                if (File.Exists(o.PasswordList))
                {
                    passwords = File.ReadAllLines(o.PasswordList);
                }
                else
                {
                    passwords = new List<string> { o.PasswordList };
                }

                //Get user list if it exists
                if (!string.IsNullOrWhiteSpace(o.UserList))
                {
                    //Get from a file if it exists, otherwise assume it's a single user
                    if (File.Exists(o.UserList))
                    {
                        users = File.ReadAllLines(o.UserList);
                    }
                    else
                    {
                        users = new List<string> { o.UserList };
                    }
                }
                else
                {
                    users = null;
                }

                //Parse the remaining attempts
                if(o.AttemptsRemaining > 0)
                {
                    remainingAttempts = o.AttemptsRemaining;
                }
                else
                {
                    remainingAttempts = 2;
                }

                adService.SprayPasswords(passwords, users, remainingAttempts, o.OutFile);
            });
        }
    }
}
