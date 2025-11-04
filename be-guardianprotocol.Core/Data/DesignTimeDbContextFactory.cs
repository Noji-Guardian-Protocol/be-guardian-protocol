using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using Microsoft.Extensions.Configuration;
using System.IO;

namespace be_guardianprotocol.Core.Data
{
    public class DesignTimeDbContextFactory : IDesignTimeDbContextFactory<GuardianProtocolDbContext>
    {
        public GuardianProtocolDbContext CreateDbContext(string[] args)
        {
            var configuration = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
                .Build();

            var connectionString = configuration.GetConnectionString("Database") ?? 
                                 configuration["Database:ConnectionString"];

            var optionsBuilder = new DbContextOptionsBuilder<GuardianProtocolDbContext>();
            optionsBuilder.UseSqlServer(connectionString);

            return new GuardianProtocolDbContext(optionsBuilder.Options);
        }
    }
}