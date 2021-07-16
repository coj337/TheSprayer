using Microsoft.EntityFrameworkCore;
using System.Reflection;
using TheSprayer.Models;

namespace TheSprayer.Db
{
    public class SprayDbContext : DbContext
    {
        public DbSet<CredentialAttempt> Attempts { get; set; }

        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            optionsBuilder.UseSqlite("Filename=TheSprayer.db", options =>
            {
                options.MigrationsAssembly(Assembly.GetExecutingAssembly().FullName);
            });
            base.OnConfiguring(optionsBuilder);
        }
    }
}
