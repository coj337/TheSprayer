using Microsoft.EntityFrameworkCore;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;
using TheSprayer.Db;
using TheSprayer.Models;

namespace TheSprayer.Services
{
    public class SqliteService
    {
        private readonly SprayDbContext _db;

        public SqliteService()
        {
            _db = new SprayDbContext();

            //Apply all migrations
            _db.Database.Migrate();
        }

        public void SaveCredentialPair(string username, string password, bool isSuccess)
        {
            var normalizedUsername = NormalizeUsername(username);
            _db.Attempts.Add(new CredentialAttempt()
            {
                Username = normalizedUsername,
                Password = password,
                Success = isSuccess,
                LastSprayTime = DateTime.Now
            });
            _db.SaveChanges();
        }

        public async Task<bool> IsCredentialPairSprayed(string username, string password) 
        {
            var normalizedUsername = NormalizeUsername(username);
            return await _db.Attempts.AnyAsync(a => a.Username == normalizedUsername && a.Password == password);
        }

        public IEnumerable<CredentialAttempt> GetSprayAttempts()
        {
            return _db.Attempts;
        }

        public IEnumerable<CredentialAttempt> GetSprayAttemptsForUser(string username)
        {
            var normalizedUsername = NormalizeUsername(username);
            return _db.Attempts.Where(a => a.Username == normalizedUsername);
        }

        public Dictionary<string, List<CredentialAttempt>> GetSprayAttemptsForUsers(IEnumerable<string> usernames)
        {
            var normalizedUsernames = usernames?
                .Select(NormalizeUsername)
                .Where(u => !string.IsNullOrEmpty(u))
                .ToList() ?? new List<string>();

            return _db.Attempts
                .Where(a => normalizedUsernames.Contains(a.Username))
                .AsEnumerable()
                .GroupBy(a => a.Username)
                .ToDictionary(u => u.Key, u => u.ToList());
        }

        public IEnumerable<CredentialAttempt> GetSprayAttemptsForPassword(string password)
        {
            return _db.Attempts.Where(a => a.Password == password);
        }

        public void BulkSaveCredentialPairs(IEnumerable<CredentialAttempt> attempts)
        {
            foreach (var attempt in attempts)
            {
                attempt.Username = NormalizeUsername(attempt.Username);
            }
            _db.Attempts.AddRange(attempts);
            _db.SaveChanges();
        }

        private static string NormalizeUsername(string username)
        {
            return string.IsNullOrWhiteSpace(username) ? username : username.ToLowerInvariant();
        }
    }
}
