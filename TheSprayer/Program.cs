using CommandLine;
using System.Collections.Generic;
using System.IO;

namespace TheSprayer
{
    public class Program
    {
        public static void Main(string[] args)
        {
            Parser.Default.ParseArguments<CommandLineOptions>(args).WithParsed(o =>
            {
                var adService = new ActiveDirectoryService(o.Domain, o.Username, o.Password, o.DomainController);
                var passwords = File.ReadAllLines(o.PasswordListFile);

                adService.SprayPasswords(passwords);
            });
        }
    }
}
