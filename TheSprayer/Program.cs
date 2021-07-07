using CommandLine;
using System;
using System.Collections.Generic;
using System.IO;
using TheSprayer.Helpers;

namespace TheSprayer
{
    public class Program
    {
        public static void Main(string[] args)
        {
            Parser.Default.ParseArguments<CommandLineOptions>(args).WithParsed(o =>
            {
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

                //Try figure out the domain if it isn't provided
                if (string.IsNullOrWhiteSpace(o.Domain))
                {
                    o.Domain = DomainHelpers.GetCurrentDomain();
                    if (string.IsNullOrWhiteSpace(o.Domain))
                    {
                        ColorConsole.WriteLine("Unable to determine domain automatically. Please run on a domain joined device or specify the domain with -d.", ConsoleColor.Red);
                        return;
                    }
                }

                //Try figure out the dc if it's not provided
                if (string.IsNullOrWhiteSpace(o.DomainController))
                {
                    o.DomainController = DomainHelpers.GetDomainController(o.Domain);
                    if (string.IsNullOrWhiteSpace(o.DomainController))
                    {
                        ColorConsole.WriteLine("Unable to determine domain controller automatically. Please run on a domain joined device or specify the dc IP or host name with -s.", ConsoleColor.Red);
                        return;
                    }
                }

                //If no username or password passed in, test authentication with SSPI
                if (string.IsNullOrWhiteSpace(o.Username) || string.IsNullOrWhiteSpace(o.Password))
                {
                    if (!DomainHelpers.IsImplicitUserValid(o.DomainController))
                    {
                        ColorConsole.WriteLine("Unable to validate current user automatically. Please specify a domain users creds with -U and -P.", ConsoleColor.Red);
                        return;
                    }
                }

                var adService = new ActiveDirectoryService(o.Domain, o.Username, o.Password, o.DomainController);
                adService.SprayPasswords(passwords, users, remainingAttempts, o.OutFile, o.Force);
            });
        }
    }
}
