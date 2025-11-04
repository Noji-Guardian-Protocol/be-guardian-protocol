using Microsoft.EntityFrameworkCore;
using be_guardianprotocol.Core.Models;

namespace be_guardianprotocol.Core.Data
{
    public class GuardianProtocolDbContext : DbContext
    {
        public GuardianProtocolDbContext(DbContextOptions<GuardianProtocolDbContext> options) : base(options) { }

        public DbSet<TenantConfiguration> TenantConfigurations { get; set; }
        public DbSet<TenantTopic> TenantTopics { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<TenantConfiguration>()
                .HasKey(t => new { t.TenantId, t.ConfigurationType });

            modelBuilder.Entity<TenantTopic>()
                .HasKey(t => t.TenantId);
        }
    }
}