using CommandLine;
using ServiceStack;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using TheSprayer.Helpers;
using TheSprayer.Services;

namespace TheSprayer
{
    public class Program
    {
        private static string[] PreserveEmptyPasswordArgument(string[] args)
        {
            var normalizedArgs = new List<string>(args.Length + 1);

            for (var i = 0; i < args.Length; i++)
            {
                normalizedArgs.Add(args[i]);

                var isPasswordOption = args[i] == "-p"
                    || args[i].Equals("--passwordlist", StringComparison.OrdinalIgnoreCase);
                var hasNoValue = i == args.Length - 1
                    || LooksLikeOption(args[i + 1]);

                if (isPasswordOption && hasNoValue)
                {
                    normalizedArgs.Add(string.Empty);
                }
            }

            return normalizedArgs.ToArray();
        }

        private static bool LooksLikeOption(string value)
        {
            return !string.IsNullOrEmpty(value)
                && value.Length > 1
                && value[0] == '-';
        }

        public static void Main(string[] args)
        {
            // Windows PowerShell 5.1 can remove an explicitly empty native argument. Restore
            // it when -p has no value before the next option (or is the final argument).
            args = PreserveEmptyPasswordArgument(args);

            // Transform long form args to lowercase
            for(var i = 0; i < args.Length; i++)
            {
                // Only transform long form args
                if (args[i].Length > 2 && args[i][0] == '-' && args[i][1] == '-')
                {
                    args[i] = args[i].ToLower();
                }
            }

            Parser.Default.ParseArguments<CommandLineOptions>(args).WithParsed(o =>
            {
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

                // Bind once up front so authentication failures are reported clearly instead of
                // being repeated by each policy and user search.
                if (!adService.TryBind(out var bindError))
                {
                    ColorConsole.WriteLine($"Unable to authenticate to LDAP on {o.DomainController}.", ConsoleColor.Red);
                    ColorConsole.WriteLine(bindError, ConsoleColor.Red);
                    return;
                }

                //Output a list of users to the specified file and exit
                if (o.OutputUsers)
                {
                    var users = adService.GetAllDomainUsers().Select(u => u.SamAccountName);
                    File.WriteAllLines("AdUserList.txt", users);
                    Console.WriteLine("AdUserList.txt created.");
                    return;
                }
                if (o.OutputUsersCsv)
                {
                    var users = adService.GetAllDomainUsers();
                    File.WriteAllText("AdUserDetails.csv", users.ToCsv());
                    Console.WriteLine("AdUserDetails.csv created.");
                    return;
                }
                else if (o.OutputPasswordPolicy) //Output the password policy to the terminal and exit
                {
                    var defaultPolicy = adService.GetPasswordPolicy();
                    var fineGrainedPolicies = adService.GetFineGrainedPasswordPolicy();

                    //Get a list of password policies attached to users that we didn't find, this means it's fine grained policies we can't see because of privs
                    var unknownPolicies = adService.GetAllDomainUsers().Select(u => u.PasswordPolicyName)
                        .Where(p => !string.IsNullOrWhiteSpace(p)
                            && p != "Default Password Policy"
                            && !fineGrainedPolicies.Any(fp => fp.Name == p))
                        .Distinct(StringComparer.OrdinalIgnoreCase);

                    ConsoleHelpers.PrintPasswordPolicy(defaultPolicy);
                    Console.WriteLine();
                    foreach (var fineGrainedPolicy in fineGrainedPolicies)
                    {
                        ConsoleHelpers.PrintPasswordPolicy(fineGrainedPolicy);
                        Console.WriteLine();
                    }

                    foreach(var policy in unknownPolicies)
                    {
                        ColorConsole.WriteLine($"Found fine-grained password policy but this user can't read it: {policy}", ConsoleColor.Red);
                    }
                    return;
                }
                else //Otherwise we want to validate remaining parameters and spray
                {
                    if (o.EmptyPassword && o.PasswordList != null)
                    {
                        ColorConsole.WriteLine("Specify either -p or --empty-password, not both.", ConsoleColor.Red);
                        return;
                    }

                    // Null means -p was omitted. An explicitly supplied empty string is a valid
                    // password and must not be treated as a missing option.
                    if (!o.EmptyPassword && o.PasswordList == null)
                    {
                        ColorConsole.WriteLine("A password list must be provided with -p, or use --empty-password.", ConsoleColor.Red);
                        return;
                    }

                    IEnumerable<string> passwords, users;
                    int attemptsToLeave;

                    // Get the password list from a file, use an explicit empty password, or assume
                    // the -p value is a single password when it is not an existing file.
                    if (o.EmptyPassword)
                    {
                        passwords = [string.Empty];
                    }
                    else if (File.Exists(o.PasswordList))
                    {
                        passwords = File.ReadAllLines(o.PasswordList);
                    }
                    else
                    {
                        passwords = [o.PasswordList];
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

                    // Parse the desired lockout buffer
                    if (o.AttemptsRemaining > 0)
                    {
                        attemptsToLeave = o.AttemptsRemaining;
                    }
                    else
                    {
                        attemptsToLeave = 2;
                    }

                    adService.SprayPasswords(passwords, users, attemptsToLeave, o.OutFile, o.Continuous, o.NoDb, o.Force, o.RetryOnSuccess);
                }
            });
        }
    }
}
