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
            _db.Attempts.Add(new CredentialAttempt()
            {
                Username = username,
                Password = password,
                Success = isSuccess,
                LastSprayTime = DateTime.Now
            });
            _db.SaveChanges();
        }

        public async Task<bool> IsCredentialPairSprayed(string username, string password) 
        {
            return await _db.Attempts.AnyAsync(a => a.Username == username && a.Password == password);
        }

        public IEnumerable<CredentialAttempt> GetSprayAttempts()
        {
            return _db.Attempts;
        }

        public IEnumerable<CredentialAttempt> GetSprayAttemptsForUser(string username)
        {
            return _db.Attempts.Where(a => a.Username == username);
        }

        public Dictionary<string, List<CredentialAttempt>> GetSprayAttemptsForUsers(IEnumerable<string> usernames)
        {
            return _db.Attempts
                .Where(a => usernames.Contains(a.Username))
                .AsEnumerable()
                .GroupBy(a => a.Username)
                .ToDictionary(u => u.Key, u => u.ToList());
        }

        public IEnumerable<CredentialAttempt> GetSprayAttemptsForPassword(string password)
        {
            return _db.Attempts.Where(a => a.Password == password);
        }
    }
}
