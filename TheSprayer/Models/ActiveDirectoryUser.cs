using System;

namespace TheSprayer.Models
{
    public class ActiveDirectoryUser
    {
        public string ADsPath { get; set; }
        public string UserPrincipalName { get; set; }
        public string SamAccountName { get; set; }
        public string DistinguishedName { get; set; }
        public string ObjectSid { get; set; }
        public string SidHistory { get; set; }
        public string GivenName { get; set; }
        public string Surname { get; set; }
        public string Description { get; set; }
        public string AdminDescription { get; set; }
        public string Company { get; set; }
        public string PasswordPolicyName { get; set; }
        public DateTime? PasswordLastSet { get; set; }
        public DateTime? LastBadPasswordTime { get; set; }
        public DateTime? LastLogin { get; set; }
        public DateTime? AccountExpiry { get; set; }
        public DateTime? DateCreated { get; set; }
        public int? BadPasswordAttempts { get; set; }
        public int LogonCount { get; set; }
        public bool Disabled { get; set; }
        public DateTime LastSync { get; private set; }

        public ActiveDirectoryUser()
        {
            LastSync = DateTime.Now;
        }
    }
}
